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

(def instant-format (ctimeformat/formatters :date-time-no-ms))
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

(defn base64->inflate->str
  [string]
  (let [byte-str (str->bytes string)]
    (bytes->str (b64/decode byte-str))))

(defn random-bytes 
  ([size]
   (let [ba (byte-array size)
         r (new java.util.Random)]
     (.nextBytes r ba)
     ba) )
  ([]
   (random-bytes 20)))

(def bytes->hex
  (let [digits (into {} (map-indexed vector "0123456789ABCDEF") )]
    (fn [^bytes bytes-str]
      (let [ret (char-array (* 2 (alength bytes-str)))]
        (loop  [idx 0]
          (if (< idx  (alength bytes-str))
            (let [pos (* 2 idx)
                  b (aget bytes-str idx)
                  d1 (unsigned-bit-shift-right (bit-and 0xF0 b) 4)
                  d2 (bit-and 0x0F b)]
              (aset-char ret pos (digits d1))
              (aset-char ret (unchecked-inc pos) (digits d2))
              (recur (unchecked-inc idx)))
            (String. ret)))))))

(defn new-secret-key-spec []
  (new javax.crypto.spec.SecretKeySpec (random-bytes) "HmacSHA1"))

(defn hmac-str [^javax.crypto.spec.SecretKeySpec key-spec ^String string]
  (let [mac (doto (javax.crypto.Mac/getInstance "HmacSHA1")
              (.init key-spec))
        hs (.doFinal mac (.getBytes string "UTF-8"))]
    (bytes->hex hs)))

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

(defn load-key-store [keystore-filename keystore-password]
  (with-open [is (clojure.java.io/input-stream keystore-filename)]
    (doto (java.security.KeyStore/getInstance "JKS")
      (.load is (.toCharArray keystore-password)))))

(defn get-certificate-b64 [keystore-filename keystore-password cert-alias]
  (let [ks (load-key-store keystore-filename keystore-password)]
    (-> ks (.getCertificate cert-alias) (.getEncoded) b64/encode (String. "UTF-8"))))


;; https://www.purdue.edu/apps/account/docs/Shibboleth/Shibboleth_information.jsp
;;  Or
;; https://wiki.library.ucsf.edu/display/IAM/EDS+Attributes
(def saml2-attr->name
  (let [names {"urn:oid:0.9.2342.19200300.100.1.1" "uid"
               "urn:oid:0.9.2342.19200300.100.1.3" "mail"
               "urn:oid:2.16.840.1.113730.3.1.241" "displayName"
               "urn:oid:2.5.4.3" "cn"
               "urn:oid:2.5.4.4" "sn"
               "urn:oid:2.5.4.12" "title"
               "urn:oid:2.5.4.20" "phone"
               "urn:oid:2.5.4.42" "givenName"
               "urn:oid:2.5.6.8" "organizationalRole"
               "urn:oid:2.16.840.1.113730.3.1.3" "employeeNumber"
               "urn:oid:2.16.840.1.113730.3.1.4" "employeeType"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.1" "eduPersonAffiliation"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.2" "eduPersonNickname"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.6" "eduPersonPrincipalName"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.9" "eduPersonScopedAffiliation"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.10" "eduPersonTargetedID"
               "urn:oid:1.3.6.1.4.1.5923.1.6.1.1" "eduCourseOffering"}]
    (fn [attr-oid]
      (get names attr-oid attr-oid) )))
