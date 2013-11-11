(ns saml20-clj.sp
  (:require [clojure.data.xml :as xml]
            [ring.util.response :refer [redirect]]
            [clj-time.core :as ctime])
  (:use [saml20-clj.shared :as shared])
  (:gen-class))

(def saml-id-timeouts (ref {}))
(def saml-last-id (atom 0)) ;; SAML IDs will be numerically ordered.

(defn bump-saml-id-timeout
  "Sets the current time to the provided saml-id in the saml-id-timeouts ref map.
  This function has side-effects."
  [saml-id issue-instant]
  (dosync (alter saml-id-timeouts assoc saml-id issue-instant)))

(defn next-saml-id!
  "Returns the next available saml id."
  []
  (swap! saml-last-id inc))

(defn prune-timed-out-ids!
  "Given a timeout duration, remove all SAML IDs that are older than now minus the timeout."
  [timeout-duration]
  (let [now (ctime/now)
        oldest (ctime/minus now timeout-duration)
        filter-fn (partial filter (shared/make-filter-after-fn oldest))]
    (dosync (alter saml-id-timeouts filter-fn))))

(defn create-request
  "Return XML elements that represent a SAML 2.0 auth request."
  [time-issued saml-format saml-service-name saml-id acs-url]
  (xml/element "samlp:AuthnRequest"
               {"xmlns:samlp" "urn:oasis:names:tc:SAML:2.0:protocol"
                "ID" saml-id
                "Version" "2.0"
                "IssueInstant" time-issued
                "ProtocolBinding" "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                "ProviderName" saml-service-name
                "IsPassive" false
                "AssertionConsumerServiceURL" acs-url}
               (xml/element "saml:Issuer"
                            {"xmlns:saml" "urn:oasis:names:tc:SAML:2.0:assertion"}
                            saml-service-name)
               (xml/element "saml:NameIDPolicy"
                            {"AllowCreate" "false"
                             "Format" saml-format})))

(defn create-request-factory!
  "Creates new requests for a particular service, format, and acs-url."
  [saml-format saml-service-name acs-url]
  (fn []
    (let [current-time (ctime/now)
          new-saml-id (next-saml-id!)
          issue-instant (shared/make-issue-instant current-time)]
      (bump-saml-id-timeout new-saml-id current-time)
      (xml/emit-str
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
        (let [saml-request (shared/str->deflate->base64 saml-request)
              relay-state (shared/str->base64 relay-state)]
          (shared/uri-query-str
            {:SAMLRequest saml-request :RelayState relay-state})))))



