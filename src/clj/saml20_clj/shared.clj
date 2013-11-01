(ns saml20-clj.shared
  (:require [clj-time.core :as ctime]
            [clojure.data.codec.base64 :as b64]
            [ring.util.codec :refer [url-encode]]
            [clj-time.format :as ctimeformat]
            [gzip-util.core :as gz]
            [hiccup.util :refer [escape-html]]
            ))

(def instant-format (ctimeformat/formatters :date-hour-minute-second))

(defn make-filter-after-fn
  "Creates a function for clojure.core/filter to keep all dates after
  a given date."
    [fdate]
    (fn [i] (ctime/after? i fdate)))
 
(defn char-filter
  "Returns a pred fn that is true if the char does not exist in the set
  provided for fn construction."
  [char-vec]
  (let [char-set (set char-vec)]
   (fn [i]
     (not (contains? char-set i)))))
 
(defn clean-x509-filter
  "Turns a base64 string into a byte array to be decoded, which includes sanitization."
  [x509-string]
  (bytes (byte-array (vec (map byte (filter (char-filter [\newline \space]) x509-string))))))

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

(defn encode-b64-str
  [str-to-base64]
  (apply str (map char (b64/encode (.getBytes str-to-base64)))))

(defn first-equals-second
  [col]
  (str (first col) "=" (second col)))

(defn make-query-string
  [qsm]
  (apply str (interpose "&" (map first-equals-second (map (partial map url-encode) qsm)))))
 
