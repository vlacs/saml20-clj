(ns saml20-clj.sp
  (:require [clojure.data.xml :as xml]
            [clojure.xml :refer [parse]]
            [ring.util.response :refer [redirect]]
            [clj-time.core :as ctime]
            [hiccup.core :as hiccup]
            [clojure.data.zip.xml :as zf])
  (:import [javax.xml.crypto]
           [javax.xml.crypto.dsig XMLSignature XMLSignatureFactory]
           [javax.xml.crypto.dom]
           [javax.xml.crypto.dsig.dom DOMValidateContext]
           [java.security]
           [javax.xml.parsers DocumentBuilderFactory]
           [org.w3c.dom Document]
           [org.w3c.dom NodeList])
  (:use [saml20-clj.shared :as shared]
        [saml20-clj.xml :as saml-xml]
        )
  (:gen-class))

(defn bump-saml-id-timeout!
  "Sets the current time to the provided saml-id in the saml-id-timeouts ref map.
  This function has side-effects."
  [saml-id-timeouts saml-id issue-instant]
  (dosync (alter saml-id-timeouts assoc saml-id issue-instant)))

(defn next-saml-id!
  "Returns the next available saml id."
  [saml-last-id]
  (swap! saml-last-id inc))

(defn prune-timed-out-ids!
  "Given a timeout duration, remove all SAML IDs that are older than now minus the timeout."
  [saml-id-timeouts timeout-duration]
  (let [now (ctime/now)
        oldest (ctime/minus now timeout-duration)
        filter-fn (partial filter (shared/make-filter-after-fn oldest))]
    (dosync
      (let [updated-timeouts (into {} (filter-fn @saml-id-timeouts))]
        (ref-set saml-id-timeouts updated-timeouts)))))

(defn create-request
  "Return XML elements that represent a SAML 2.0 auth request."
  [time-issued saml-format saml-service-name saml-id acs-url]
  (str
    (hiccup.page/xml-declaration "UTF-8")
    (hiccup/html
      [:samlp:Authnrequest
       {:xmlns:samlp "urn:oasis:names:tc:SAML:2.0:protocol"
        :ID saml-id
        :Version "2.0"
        :IssueInstant time-issued
        :ProtocolBinding "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        :ProviderName saml-service-name
        :IsPassive false
        :AssertionConsumerServiceURL acs-url}
       [:saml:Issuer
        {:xmlns:saml "urn:oasis:names:tcSAML:2.0:assertion"}
        saml-service-name]
       [:samlp:NameIDPolicy
        {:AllowCreate false
         :Format saml-format}]])))

(defn generate-mutables
  []
  {:saml-id-timeouts (ref {})
   :saml-last-id (atom 0)
   })

(defn create-request-factory
  "Creates new requests for a particular service, format, and acs-url."
  ([mutables saml-format saml-service-name acs-url]
     (create-request-factory
      #(next-saml-id! (:saml-last-id mutables))
      (partial bump-saml-id-timeout! (:saml-id-timeouts mutables))
      saml-format saml-service-name acs-url))
  ([next-saml-id-fn! bump-saml-id-timeout-fn! saml-format saml-service-name acs-url]
     (fn request-factory []
       (let [current-time (ctime/now)
             new-saml-id (next-saml-id-fn!)
             issue-instant (shared/make-issue-instant current-time)]
         (bump-saml-id-timeout-fn! new-saml-id current-time)
         (create-request issue-instant 
                         saml-format
                         saml-service-name
                         new-saml-id
                         acs-url)))))

(defn get-idp-redirect
  "Return Ring response for HTTP 302 redirect."
  [idp-url saml-request relay-state]
  (redirect
    (str idp-url
         "?"
         (let [saml-request (shared/str->deflate->base64 saml-request)]
           (shared/uri-query-str
             {:SAMLRequest saml-request :RelayState relay-state})))))

(defn pull-attrs
  [loc attrs]
  (zipmap attrs (map (partial zf/attr loc) attrs)))

(defn response->map
  "Parses and performs final validation of the request. An exception will be thrown if validation fails."
  [saml-resp]
  (let [response-attr-names [:ID :IssueInstant :InResponseTo]
        subject-conf-names [:Recipient :NotOnOrAfter :InResponseTo]
        saml-cond-attr-names [:NotBefore :NotOnOrAfter]

        saml-status (zf/xml1-> saml-resp :samlp:Status :samlp:StatusCode)
        saml-assertion (zf/xml1-> saml-resp :Assertion)
        saml-subject (zf/xml1-> saml-assertion :Subject)
        saml-issuer (zf/xml1-> saml-assertion :Issuer)
        saml-name-id (zf/xml1-> saml-subject :NameID)
        saml-subject-conf-data(zf/xml1-> saml-subject :SubjectConfirmation :SubjectConfirmationData)
        saml-conditions (zf/xml1-> saml-assertion :Conditions)
        saml-audience-restriction (zf/xml1-> saml-conditions :AudienceRestriction :Audience)]

    (let [response-attrs (pull-attrs saml-resp response-attr-names)
          status-str (zf/attr saml-status :Value)
          issuer (zf/text saml-issuer)
          user-identifier (zf/text saml-name-id)
          user-type (zf/attr saml-name-id :Format)
          conditions (pull-attrs saml-conditions saml-cond-attr-names)
          subject-conf-attrs (pull-attrs saml-subject-conf-data subject-conf-names)
          acs-audience (zf/text saml-audience-restriction)]

      {:responding-to (:InResponseTo response-attrs)
       :response-id (:ID response-attrs)
       :issued-at (:IssueInstant response-attrs)
       ;;; TODO: Validate that "now" is within saml conditions.
       :success? (and (shared/saml-successful? status-str)
                      (= (:InResponseTo response-attrs)
                         (:InResponseTo subject-conf-attrs)))
       :user-format user-type
       :user-identifier user-identifier})))

(defn parse-saml-response
  "Does everything from parsing the verifying saml data to returning it in an easy to use map."
  [raw-response]
  (let [parsed-zipper (clojure.zip/xml-zip (parse (shared/str->inputstream raw-response)))]
    (response->map parsed-zipper)))

