(ns saml20-clj.web
  (:require [liberator.core :refer [resource defresource]]
            [ring.adapter.jetty :refer [run-jetty]]
            [compojure.core :refer [defroutes ANY]]
            [clojure.edn :as edn]
            [saml20-clj.sp :as saml-sp]
            [saml20-clj.shared :as saml-shared]
            [saml20-clj.shared :as saml-shared]
            [hiccup.core :as hiccup]
            [hiccup.page :refer [html5]]
            [hiccup.util :refer [escape-html]])
  (:gen-class))

(def config
  (edn/read-string (slurp "config.edn")))
(def acs-url (let [acs (get-in config [:saml :acs])]
               (str (:protocol acs) "://" (:name acs) ":" (:port acs) (:path acs))))
(def idp-url (get-in config [:saml :idp-url]))
(def saml-request-factory (saml-sp/create-request-factory!
                            (get-in config [:saml :format])
                            (get-in config [:app-name])
                            acs-url))
(defn basic-page [content]
  (html5
  [:html
   [:head
    [:title "Blank page"]]
   [:body
    [:div.body content]]]))


(defroutes app
  (ANY "/" [] "<html>Hello world.</html>")
  (ANY "/saml" [] (saml-sp/get-idp-redirect idp-url (saml-request-factory) acs-url))
  (ANY "/saml-barf" [] (saml-request-factory))
  )

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (run-jetty #'app {:port (:app-port config)}))

