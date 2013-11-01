(ns aspire-auth.client
  (:require [clojure.browser.net :as gnet]
            [clojure.browser.event :as gevent]
            [dommy.core :as dommy])
  (:use-macros
    [dommy.macros :only [sel1]]))

(defn callback-error [msg]
  (.log js/console "Error: " msg))
