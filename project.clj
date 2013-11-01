(defproject saml20-clj "0.0.1"
  :description "Basic SAML 2.0 library for SSO."
  :url "http://doesnotexist.com"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :source-paths ["src/clj"]
  :dependencies [
                 ;;; Clojure deps
                 [org.clojure/clojure "1.5.1"]
                 [liberator "0.9.0"]
                 [compojure "1.1.6"]
                 [ring "1.2.1"]
                 [org.clojure/data.xml "0.0.7"]
                 [org.clojure/data.codec "0.1.0"]
                 [hiccup "1.0.4"]
                 [clj-time "0.6.0"]
                 [gzip-util "0.1.0-SNAPSHOT"]
                 
                 ;;; ClojureScript deps
                 [org.clojure/clojurescript "0.0-1978"]
                 [prismatic/dommy "0.1.1"]]
  :plugins [[lein-cljsbuild "0.3.4"]]
  :cljsbuild {
              :builds [{:source-paths ["src/cljs"]
                        :compiler {
                                   :output-to "resources/public/js/main.js"
                                   :optimizations :whitespace
                                   :pretty-print true}}]}
  :hooks [leiningen.cljsbuild]
  :main saml20-clj.web)
