(ns saml20-clj.sp
  (:require [clojure.data.xml :as xml]
            [clojure.xml :refer [parse]]
            [ring.util.response :refer [redirect]]
            [clj-time.core :as ctime]
            [hiccup.core :as hiccup])
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
  [mutables saml-format saml-service-name acs-url]
  (fn []
    (let [current-time (ctime/now)
          new-saml-id (next-saml-id! (:saml-last-id mutables))
          issue-instant (shared/make-issue-instant current-time)]
      (bump-saml-id-timeout! (:saml-id-timeouts mutables) new-saml-id current-time)
      (create-request issue-instant 
                      saml-format
                      saml-service-name
                      new-saml-id
                      acs-url))))

(defn get-idp-redirect
  "Return Ring response for HTTP 302 redirect."
  [idp-url saml-request relay-state]
  (redirect
    (str idp-url
         "?"
         (let [saml-request (shared/str->deflate->base64 saml-request)]
           (shared/uri-query-str
             {:SAMLRequest saml-request :RelayState relay-state})))))

;;; We might want to make this more specific, such as extracting the user type
;;; and the associated identifier.
(defn parse-saml-response
  [raw-response]
  (parse raw-response))





