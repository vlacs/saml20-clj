(ns web
  (:require [ring.adapter.jetty :refer [run-jetty]]
            [compojure.core :refer [defroutes routes ANY GET POST]]
            [compojure.handler :as handler]
            [saml20-clj.sp :as saml-sp]
            [saml20-clj.xml :as saml-xml]
            [saml20-clj.shared :as saml-shared]
            [hiccup.core :as hiccup]
            [hiccup.page :refer [html5]]
            [hiccup.util :refer [escape-html]])
  (:gen-class))

(defn basic-page [content]
  (html5
  [:html
   [:head
    [:title "Blank page"]]
   [:body
    [:pre content]]]))

(defn wrap-app-state
  [state]
  ;; Get mutables setup so we can setup everything else.
  (let [state (assoc state :mutables (saml-sp/generate-mutables))
        saml-req-factory! (saml-sp/create-request-factory
                           (:mutables state)
                           (get-in state [:saml :format])
                           (:app-name state)
                           (:acs-url state))
        prune-fn! (partial saml-sp/prune-timed-out-ids!
                           (get-in state [:mutables :saml-id-timeouts]))]
    (-> state
        (assoc :saml-req-factory! saml-req-factory!)
        (assoc :timeout-pruner-fn! prune-fn!)
        (assoc :routes
               (routes
                 (GET "/saml" [] (saml-sp/get-idp-redirect
                                   (get-in state [:saml :idp-url])
                                   (saml-req-factory!)
                                   (:acs-url state)))
                 (POST "/saml" [& params]
                       (let [saml-resp (:SAMLResponse params)
                             validity (saml-xml/validate-xml-doc
                                        saml-resp
                                        (get-in state [:saml :certificate-x509]))
                             request-map (saml-sp/parse-saml-response saml-resp)]
                         ;;;(prn request-map)
                         (basic-page (str "Valid: " validity "<br />" (escape-html (prn-str request-map)))))))))))

(defn start!
  [state]
  (let [jetty-app (compojure.handler/site (:routes state))]
    (-> state
        (assoc :http-handler jetty-app)
        (assoc :http-server (run-jetty jetty-app {:port (:app-port state)
                                                    :join? false})))))

(defn stop!
  [state]
  (.stop (:http-server state))
  (-> state
      (dissoc :http-server)
      (dissoc :http-handler)))

