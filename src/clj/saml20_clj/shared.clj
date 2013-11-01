(ns saml20-clj.shared
  (:require [clj-time.core :as ctime]
            [clj-time.format :as ctimeformat]
            [clojure.data.codec.base64 :as b64]
            [ring.util.codec :refer [form-encode url-encode base64-encode]]
            [gzip-util.core :as gz]
            [hiccup.util :refer [escape-html]]
            ))

(def instant-format (ctimeformat/formatters :date-hour-minute-second))

(defn make-filter-after-fn
  "Creates a function for clojure.core/filter to keep all dates after
  a given date."
    [fdate]
    (fn [i] (ctime/after? i fdate)))
 
(defn clean-x509-filter-new
  "Turns a base64 string into a byte array to be decoded, which includes sanitization."
  [x509-string]
  (-> x509-string
      (str/replace #"[\n ]" "")
      ((partial map byte))
      byte-array
      bytes))

(defn certificate-x509
  "Takes in a raw X.509 certificate string, parses it, and creates a Java certificate."
  [x509-string]
  (let [x509-byte-array (clean-x509-filter x509-string)
        fty (java.security.cert.CertificateFactory/getInstance "X.509")
        bais (new java.io.ByteArrayInputStream (bytes (b64/decode x509-byte-array)))]
    (.generateCertificate fty bais)))
 
(defn make-issue-instant
  "Converts a date-time to a SAML 2.0 time string."
  [ii-date]
  (ctimeformat/unparse instant-format ii-date))
 
(defn encode-gzip-str
  [str-to-gzip]
  (apply str (map char (gz/str->gzipped-bytes str-to-gzip))))

(defn form-encode-b64
  [req]
  (into {}
        (map
         (fn [[k v]] [k (base64-encode (.getBytes v))])
         req)))

(defn saml-form-encode [form]
  (-> form
      form-encode-b64
      form-encode))

 
