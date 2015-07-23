(ns demo-sp
  (:require [saml20-clj.sp :as sp]
            [saml20-clj.shared :as shared]
            [saml20-clj.xml :as xml]
            [saml20-clj.routes :as sr]
            [compojure.core :refer [defroutes routes GET POST]]
            [compojure.handler :as handler]
            [hiccup.page :refer [html5]]
            [ring.adapter.jetty :refer [run-jetty]]
            [clojure.edn :as edn]))

(defn template-page [title & contents]
  (html5
    [:html
     [:head
      [:link {:rel "stylesheet" :href "//maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css"}]
      [:title title]]
     [:body.container
      [:h1 "Demo Service Provider"]
      [:p.lead "You can get the SAML metadata " [:a {:href "/saml/meta"} "here"]]
      contents]]))

(defn login-page []
  (template-page "Login"
                 [:a.btn.btn-primary {:href "login"} "Login to IdP"]))

(defn debug-page [saml-info]
  (let [attrs (-> saml-info :assertions first :attrs)
        status (dissoc saml-info :assertions) ]
    (template-page "SAML Debug page"
                   [:h2 "SAML response"]
                   [:table.table.table-striped
                    (map (fn [[k v]]
                           [:tr [:td k] [:td v]]) status)]
                   [:h2 "You 've been authenticated as"]
                   [:table.table.table-striped
                    (map (fn [[k v]]
                           [:tr [:td k] [:td v]]) attrs) ])))

(defroutes main-routes
  (GET "/" {session :session}
       (if-let [saml-info (:saml session)]
         (debug-page (:saml session))
         (login-page)))
  (GET "/login" [] (sr/redirect-to-saml "/")))


(defn whats-my-ip
  "A hack, to get the externally visible IP address of the current host
   using http://checkip.amazonaws.com"
  []
  (clojure.string/trim (slurp "http://checkip.amazonaws.com")))

(defn main []
 ;; (let [state (reset-state! "config.edn")]
 ;;  (println "running server at port " (:app-port state))
 ;;  (start-ring!))
 (let [port 8080
       base-uri (str "http://" (whats-my-ip) ":" port)
       saml-routes (sr/saml-routes {:app-name "saml20-clj"
                                    :base-uri base-uri
                                    :idp-uri "https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php"
                                    :idp-cert "MIICizCCAfQCCQCY8tKaMc0BMjANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMCTk8xEjAQBgNVBAgTCVRyb25kaGVpbTEQMA4GA1UEChMHVU5JTkVUVDEOMAwGA1UECxMFRmVpZGUxGTAXBgNVBAMTEG9wZW5pZHAuZmVpZGUubm8xKTAnBgkqhkiG9w0BCQEWGmFuZHJlYXMuc29sYmVyZ0B1bmluZXR0Lm5vMB4XDTA4MDUwODA5MjI0OFoXDTM1MDkyMzA5MjI0OFowgYkxCzAJBgNVBAYTAk5PMRIwEAYDVQQIEwlUcm9uZGhlaW0xEDAOBgNVBAoTB1VOSU5FVFQxDjAMBgNVBAsTBUZlaWRlMRkwFwYDVQQDExBvcGVuaWRwLmZlaWRlLm5vMSkwJwYJKoZIhvcNAQkBFhphbmRyZWFzLnNvbGJlcmdAdW5pbmV0dC5ubzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt8jLoqI1VTlxAZ2axiDIThWcAOXdu8KkVUWaN/SooO9O0QQ7KRUjSGKN9JK65AFRDXQkWPAu4HlnO4noYlFSLnYyDxI66LCr71x4lgFJjqLeAvB/GqBqFfIZ3YK/NrhnUqFwZu63nLrZjcUZxNaPjOOSRSDaXpv1kb5k3jOiSGECAwEAATANBgkqhkiG9w0BAQUFAAOBgQBQYj4cAafWaYfjBU2zi1ElwStIaJ5nyp/s/8B8SAPK2T79McMyccP3wSW13LHkmM1jwKe3ACFXBvqGQN0IbcH49hu0FKhYFM/GPDJcIHFBsiyMBXChpye9vBaTNEBCtU3KjjyG0hRT2mAQ9h+bkPmOvlEo/aH0xR68Z9hw4PF13w=="
                                    :keystore-file "keystore.jks"
                                    :keystore-password "changeit"
                                    :key-alias "stelios"})
       app (routes saml-routes
                   #'main-routes)]
   (println "Starting server at" base-uri)
   (run-jetty (handler/site app) {:port port})) )
