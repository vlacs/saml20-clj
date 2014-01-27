(ns saml20-clj.shared
  (:import  (java.io FileInputStream InputStreamReader BufferedReader))
  (:require [clj-time.core :as ctime]
            [clj-time.format :as ctimeformat]
            [clojure.data.codec.base64 :as b64]
            [ring.util.codec :refer [form-encode url-encode base64-encode]]
            [hiccup.util :refer [escape-html]]
            [clojure.string :as str]
            [clojure.java.io :as io]
            [clojure.zip]
            [clojure.xml])
  (:import [java.io ByteArrayInputStream]))

(def instant-format (ctimeformat/formatters :date-hour-minute-second))
(def charset-format (java.nio.charset.Charset/forName "UTF-8"))

(def status-code-success "urn:oasis:names:tc:SAML:2.0:status:Success")

(defn saml-successful?
  [id-str]
  (if (= id-str status-code-success)
    true false))

(defn read-to-end
  [stream]
  (let [sb (StringBuilder.)]
    (with-open [reader (-> stream
                           InputStreamReader.
                           BufferedReader.)]
      (loop [c (.read reader)]
        (if (neg? c)
          (str sb)
          (do
            (.append sb (char c))
            (recur (.read reader))))))))

(defn jcert->public-key
  "Extracts a public key object from a java cert object."
  [java-cert-obj]
  (.getPublicKey java-cert-obj)) 

(defn parse-xml-str
  [xml-str]
  (clojure.zip/xml-zip (clojure.xml/parse (java.io.ByteArrayInputStream. (.getBytes xml-str)))))

 
(defn clean-x509-filter
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

(defn jcert->public-key
  "Extracts a public key object from a java cert object."
  [java-cert-obj]
  (.getPublicKey java-cert-obj)) 

(defn str->inputstream
  "Unravels a string into an input stream so we can work with Java constructs."
  [unravel]
  (ByteArrayInputStream. (.getBytes unravel charset-format)))

(defn make-issue-instant
  "Converts a date-time to a SAML 2.0 time string."
  [ii-date]
  (ctimeformat/unparse instant-format ii-date))

(defn str->bytes
  [some-string]
  (.getBytes some-string charset-format))

(defn bytes->str
  [some-bytes]
  (String. some-bytes charset-format))

(defn byte-deflate
  [str-bytes]
  (let [out (java.io.ByteArrayOutputStream.)
        deflater (java.util.zip.DeflaterOutputStream.
                   out
                   (java.util.zip.Deflater. -1 true) 1024)]
    (.write deflater str-bytes)
    (.close deflater)
    (.toByteArray out)))

(defn byte-inflate
  [comp-bytes]
  (let [input (java.io.ByteArrayInputStream. comp-bytes)
        inflater (java.util.zip.InflaterInputStream.
                   input (java.util.zip.Inflater. true) 1024)
        result (read-to-end inflater)]
    (.close inflater)
    result)) 

(defn str->base64
  [base64able-string]
  (-> base64able-string str->bytes b64/encode bytes->str))

(defn base64->str
  [stringable-base64]
  (-> stringable-base64 str->bytes b64/decode bytes->str))

(defn str->deflate->base64
  [deflatable-str]
  (let [byte-str (str->bytes deflatable-str)]
    (bytes->str (b64/encode (byte-deflate byte-str)))))

(defn uri-query-str
  [clean-hash]
  (form-encode clean-hash))

(defn form-encode-b64
  [req]
  (into {}
        (map
          (fn [[k v]] [k (str->base64 v)])
          req)))

(defn saml-form-encode [form]
  (-> form
      form-encode-b64
      form-encode))

(defn time-since
  [time-span]
  (ctime/minus (ctime/now) time-span))

(defn make-timeout-filter-fn
  "Creates a function for clojure.core/filter to keep all dates after
  a given date."
  [timespan]
    (fn [i]
      (ctime/after? (second i) (time-since timespan))))

