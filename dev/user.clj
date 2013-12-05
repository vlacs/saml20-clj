(ns user
  (:require [saml20-clj.sp :as sp]
            [saml20-clj.shared :as shared]
            [saml20-clj.xml :as xml]
            [web]
            [clojure.edn :as edn]
            [clojure.pprint :refer (pprint)]
            [clojure.repl :refer :all]
            [clojure.test :refer :all]
            [clojure.tools.namespace.repl :refer (refresh refresh-all)]))

(def app-state (atom nil))

(defn replace-state!
  [new-state]
  (reset! app-state new-state))

(defn start-ring!
  []
  (replace-state! (web/start! @app-state)))

(defn stop-ring!
  []
  (replace-state! (web/stop! @app-state)))

(defn new-saml-instance
  [conf-path]
  (web/wrap-app-state (let [conf-hash (edn/read-string (slurp conf-path))
                            acs-url (let [acs (get-in conf-hash [:saml :acs])]
                                      (str (:protocol acs)
                                           "://"
                                           (:name acs)
                                           ":"
                                           (:port acs)
                                           (:path acs)))]
                        (assoc conf-hash :acs-url acs-url))))

(defn reset-state!
  [conf-path]
  (reset! app-state (new-saml-instance conf-path)))

