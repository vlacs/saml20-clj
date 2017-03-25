# saml20-clj

This is a SAML 2.0 clojure library for SSO. 
This library allows a clojure application to act as a service provider (SP).
Tested with Microsoft Active Directory Federation Server (ADFS) as the identity provider (IdP).

## Installation

Add ```[k2n/saml20-clj "0.1.7"]``` to your project dependencies.

## Usage

See [quephird/saml-test](https://github.com/quephird/saml-test) for the usage. 
This is forked from [vlacs/saml20-clj](https://github.com/vlacs/saml20-clj) and added the support for XML signing with SHA-256 instead of SHA-1, which is required by ADFS by default. 

``` clojure
(ns myapp.routes.saml
  (:require [clojure.tools.logging :as log]
            [compojure.core :refer [defroutes routes GET POST]]
            [myapp.config :refer [base-url saml-keystore-password]]
            [ring.util.response :refer :all]
            [saml20-clj.sp :as saml-sp]
            [saml20-clj.routes :as saml-routes]
            [saml20-clj.shared :as saml-shared]
            [slingshot.slingshot :refer [try+ throw+]]))

(def config
  {:app-name (format "%s/saml/metadata" base-url)
   :base-uri base-url
   :idp-uri "https://adfs.example.com/adfs/ls/"
   ;; Copy /EntityDescriptor/RoleDescriptor/KeyDescriptor[@use="signing"]/KeyInfo/X509Data/X509Certificate of 
   ;; https://adfs.example.com/federationMetadata/2007-06/federationMetadata.xml
   :idp-cert "ABCDEF..." 
   :keystore-file "saml.jks"
   :keystore-password saml-keystore-password
   :key-alias "saml"})

(defn saml-routes
  [{:keys [app-name base-uri idp-uri idp-cert keystore-file keystore-password key-alias]}]
  (let [decrypter         (saml-sp/make-saml-decrypter keystore-file keystore-password key-alias)
        sp-cert           (saml-shared/get-certificate-b64 keystore-file keystore-password key-alias)
        ;; Specify :sha256 as XML signing algorithm if you use ADFS as IdP. OpenSAML expects :sha1.
        mutables          (assoc (saml-sp/generate-mutables)
                                 :xml-signer (saml-sp/make-saml-signer keystore-file keystore-password key-alias
                                                                       :algorithm :sha256))
        acs-uri           (str base-uri "/saml")
        saml-req-factory! (saml-sp/create-request-factory mutables
                                                          idp-uri
                                                          saml-routes/saml-format
                                                          app-name
                                                          acs-uri)
        prune-fn!         (partial saml-sp/prune-timed-out-ids!  (:saml-id-timeouts mutables))
        state             {:mutables mutables
                           :saml-req-factory! saml-req-factory!
                           :timeout-pruner-fn! prune-fn!
                           :certificate-x509 sp-cert}]
    (routes
     (GET "/saml/metadata" []
       {:status 200
        :headers {"Content-type" "text/xml"}
        :body (saml-sp/metadata app-name acs-uri sp-cert)})

     (GET "/saml" [:as req]
       (let [saml-request (saml-req-factory!)
             hmac-relay-state (saml-routes/create-hmac-relay-state (:secret-key-spec mutables)
                                                                   "no-op")]
         (log/info "GET /saml hmac-relay-state:" hmac-relay-state)
         (saml-sp/get-idp-redirect idp-uri saml-request hmac-relay-state)))

     (POST "/saml" {params :params session :session}
       (let [xml-response (saml-shared/base64->inflate->str (:SAMLResponse params))
             relay-state (:RelayState params)
             [valid-relay-state? continue-url] (saml-routes/valid-hmac-relay-state? (:secret-key-spec mutables) relay-state)
             saml-resp (saml-sp/xml-string->saml-resp xml-response)
             valid-signature? (if idp-cert
                                (saml-sp/validate-saml-response-signature saml-resp idp-cert)
                                false)
             valid? (and valid-relay-state? valid-signature?)
             saml-info (when valid? (saml-sp/saml-resp->assertions saml-resp decrypter))]
         (if valid?
           {:status  303 ;; See other
            :headers {"Location" continue-url}
            :session (assoc session :saml saml-info)
            :body ""}
           {:status 500
            :body "The SAML response from IdP does not validate!"}))))))
```

## License

Copyright © 2013 VLACS <jdoane@vlacs.org>
Copyright © 2017 Kenji Nakamura <kenji@signifier.jp>

Distributed under the Eclipse Public License, the same as Clojure.
