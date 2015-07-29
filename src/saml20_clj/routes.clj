(ns ^{:doc "The compojure based routes for the SAML Service Provider (SP)"
      :author "Stelios Sfakianakis"}
  saml20-clj.routes
  (:require [compojure.core :as cc]
            [saml20-clj.sp :as saml-sp]
            [saml20-clj.xml :as saml-xml]
            [saml20-clj.shared :as saml-shared])
  (:gen-class))

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
        
        saml-format "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
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
      (cc/GET "/saml" [& params]
              (let [continue-url (get params :continue "/")
                    relay-state (create-hmac-relay-state (:secret-key-spec mutables) continue-url) ]
                (saml-sp/get-idp-redirect idp-uri
                                          (saml-req-factory!)
                                          relay-state)))
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

