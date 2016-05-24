(ns ^{:doc "The compojure based routes for the SAML Service Provider (SP)"
      :author "Stelios Sfakianakis"}
  saml20-clj.routes
  (:require [compojure.core :as cc]
            [saml20-clj.sp :as saml-sp]
            [saml20-clj.xml :as saml-xml]
            [saml20-clj.shared :as saml-shared]
            [helmsman uri navigation])
  (:gen-class))

(def saml-format "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")

(defn redirect-to-saml [continue-to-url]
  {:status  302 ;; Found
   :headers {"Location" (str "/saml?continue=" continue-to-url)}
   :body    ""})

(defn create-hmac-relay-state [secret-key-spec relay-state]
  (str relay-state ":" (saml-shared/hmac-str secret-key-spec relay-state)))

(defn valid-hmac-relay-state? [secret-key-spec hmac-relay-state]
  (let [idx (.lastIndexOf hmac-relay-state ":")
        [relay-state hmac] (if (pos? idx)
                             [(subs hmac-relay-state 0 idx) (subs hmac-relay-state (inc idx))]
                             [hmac-relay-state ""])
        valid? (= hmac (saml-shared/hmac-str secret-key-spec relay-state))]
    [valid? relay-state]))

(defn meta-response
  [req]
  (let [{:keys [app-name acs-uri cert]} (:saml20 req)]
    {:status 200
     :headers {"Content-type" "text/xml"}
     :body (saml-sp/metadata app-name acs-uri cert)}))

(defn new-request-handler
  [req]
  (let [continue-url (get-in req [:params :continue] "/")
        relay-state (create-hmac-relay-state
                      (get-in req [:saml20 :mutables :secret-key-spec])
                      continue-url)]
    (saml-sp/get-idp-redirect
      (get-in req [:saml20 :idp-uri])
      ((get-in req [:saml20 :saml20-req-factory!]))
      relay-state)))

(defn process-response-handler
  [{:keys [saml20 params session] :as req}]
  (let [xml-response (saml-shared/base64->inflate->str (:SAMLResponse params))
        [valid-relay-state? continue-url]
        (valid-hmac-relay-state?
          (get-in saml20 [:mutables :secret-key-spec])
          (:RelayState params))
        saml-resp (saml-sp/xml-string->saml-resp xml-response)
        valid-signature?
        (if (:idp-cert saml20)
          (saml-sp/validate-saml-response-signature
            saml-resp (:idp-cert saml20)) true)
        valid? (and valid-relay-state? valid-signature?)
        saml-info (when valid? (saml-sp/saml-resp->assertions
                                 saml-resp (:decrypter saml20)))]
    (if valid?
      {:status 303
       :headers {"Location" continue-url}
       :session (assoc session :saml20 saml-info)
       :body ""}
      {:status 500
       :body "The SAML response from the IdP did not validate!"})))

(defn saml-routes
  "The SP routes. They can be combined with application specific routes. Also it is assumed that
  they are wrapped with compojure.handler/site or wrap-params and wrap-session.
  
  The single argument is a map containing the following fields:
  
  :app-name - The application's name
  :base-uri - The Base URI for the application i.e. its remotely accessible hostname and
              (if needed) port, e.g. https://example.org:8443 This is used for building the
              'AssertionConsumerService' URI for the HTTP-POST Binding, by prepending the 
              base-uri to the '/saml' string.
  :idp-uri  - The URI for the IdP to use. This should be the URI for the HTTP-Redirect SAML Binding
  :idp-cert - The IdP certificate that contains the public key used by IdP for signing responses.
              This is optional: if not used no signature validation will be performed in the responses
  :keystore-file - The filename that is the Java keystore for the private key used by this SP for the
                   decryption of responses coming from IdP
  :keystore-password - The password for opening the keystore file
  :key-alias - The alias for the private key in the keystore
  
  The created routes are the following:

  - GET /saml/meta : This returns a SAML metadata XML file that has the needed information
                     for registering this SP. For example, it has the public key for this SP.

  - GET /saml : it redirects to the IdP with the SAML request envcoded in the URI per the
                HTTP-Redirect binding. This route accepts a 'continue' parameter that can 
                have the relative URI, where the browser should be redirected to after the
                successful login in the IdP. 

  - POST /saml : this is the endpoint for accepting the responses from the IdP. It then redirects
                 the browser to the 'continue-url' that is found in the RelayState paramete, or the '/' root
                 of the app.
  "
 [{:keys [app-name base-uri idp-uri idp-cert keystore-file keystore-password key-alias]}]
  (let [decrypter (saml-sp/make-saml-decrypter keystore-file keystore-password key-alias)
        cert (saml-shared/get-certificate-b64  keystore-file keystore-password key-alias)
        mutables (assoc (saml-sp/generate-mutables)
                        :xml-signer (saml-sp/make-saml-signer keystore-file keystore-password key-alias))
        
        acs-uri (str base-uri "/saml")
        saml-req-factory! (saml-sp/create-request-factory mutables
                                                          idp-uri
                                                          saml-format
                                                          app-name
                                                          acs-uri)
        prune-fn! (partial saml-sp/prune-timed-out-ids!
                           (:saml-id-timeouts mutables))
        state {:mutables mutables
               :saml-req-factory! saml-req-factory!
               :timeout-pruner-fn! prune-fn!
               :certificate-x509 cert}]
    (cc/routes
      (cc/GET "/saml/meta" [] {:status 200
                               :headers {"Content-type" "text/xml"}
                               :body (saml-sp/metadata app-name acs-uri cert) } )
      (cc/GET "/saml" [:as req]
              (new-request-handler req))
      (cc/POST "/saml" {params :params session :session}
               (let [xml-response (saml-shared/base64->inflate->str (:SAMLResponse params))
                     relay-state (:RelayState params)
                     [valid-relay-state? continue-url] (valid-hmac-relay-state? (:secret-key-spec mutables) relay-state)
                     saml-resp (saml-sp/xml-string->saml-resp xml-response)
                     valid-signature? (if idp-cert
                                        (saml-sp/validate-saml-response-signature saml-resp idp-cert)
                                        true)
                     valid? (and valid-relay-state? valid-signature?)
                     saml-info (when valid? (saml-sp/saml-resp->assertions saml-resp decrypter) )]
              ;;(prn saml-info)
              (if valid?
                {:status  303 ;; See other
                 :headers {"Location" continue-url}
                 :session (assoc session :saml saml-info)
                 :body ""}
                {:status 500
                 :body "The SAML response from IdP does not validate!"}))))))

(defn saml-wrapper
  [handler
   {:keys [base-uri app-name idp-uri idp-cert keystore-file
           keystore-password key-alias] :as saml20-config}
   mutables]
  (let [new-mutables (assoc
                       mutables
                       :xml-signer
                       (saml-sp/make-saml-signer
                         keystore-file keystore-password key-alias))]
  (fn saml-wrapper-fn
    [request]
    (let [acs-uri (str base-uri
                       (helmsman.uri/assemble
                         (:path
                           (helmsman.navigation/get-route-by-id
                             request :saml20-clj/endpoint))))]
      (handler
        (assoc
          request :saml20
          (assoc
            saml20-config
            :decrypter 
            (saml-sp/make-saml-decrypter
              keystore-file keystore-password key-alias)
            :cert 
            (saml-shared/get-certificate-b64
              keystore-file keystore-password key-alias)
            :mutables new-mutables
            :acs-uri acs-uri
            :saml20-req-factory! (saml-sp/create-request-factory
                                   new-mutables idp-uri saml-format
                                   app-name acs-uri)
            :prune-fn! (partial saml-sp/prune-timed-out-ids!
                                (:saml-id-timeouts mutables)))))))))

(defn helmsman-routes
  [saml20-config]
  [[saml-wrapper saml20-config (saml-sp/generate-mutables)]
   [:get "saml/meta" meta-response]
   ^{:id :saml20-clj/endpoint}
   [:get "saml" new-request-handler]
   [:post "saml" process-response-handler]])


