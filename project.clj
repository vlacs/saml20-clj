(defproject saml20-clj "0.1.0"
  :description "Basic SAML 2.0 library for SSO."
  :url "https://github.com/vlacs/saml20-clj"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :source-paths ["src"]
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [liberator "0.9.0"]
                 [compojure "1.1.6"]
                 [ring "1.2.1"]
                 [org.clojure/data.xml "0.0.7"]
                 [org.clojure/data.codec "0.1.0"]
                 [hiccup "1.0.4"]
                 [clj-time "0.6.0"]
                 [gzip-util "0.1.0-SNAPSHOT"]]
  :profiles {:dev {:source-paths ["dev" "test"]
                   :dependencies [[org.clojure/tools.namespace "0.2.4"]
                                  [org.clojure/tools.nrepl "0.2.3"]]}})
