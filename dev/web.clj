(ns web
  (:require [ring.adapter.jetty :refer [run-jetty]]
            [compojure.core :refer [defroutes routes ANY GET POST]]
            [compojure.handler :as handler]
            [saml20-clj.sp :as saml-sp]
            [saml20-clj.xml :as saml-xml]
            [saml20-clj.shared :as saml-shared]
            [saml20-clj.routes :as saml-routes]
            [hiccup.core :as hiccup]
            [hiccup.page :refer [html5]]
            [hiccup.util :refer [escape-html]]
            [helmsman])
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
  (assoc state :handler
         (helmsman/create-ring-handler
           (saml-routes/helmsman-routes state))))

(defn start!
  [state]
  (assoc
    state :http-server
    (run-jetty (:handler state)
               {:port (:app-port state)
                :join? false})))

(defn stop!
  [state]
  (.stop (:http-server state))
  (dissoc state :http-server :handler))

