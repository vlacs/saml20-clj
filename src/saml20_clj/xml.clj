(ns saml20-clj.xml
  (:require [hiccup.core]
            [hiccup.page]
            [saml20-clj.shared :as saml-shared])
  (:import [javax.xml.crypto KeySelector]
           [javax.xml.crypto.dsig XMLSignature XMLSignatureFactory]
           [javax.xml.crypto.dsig.dom DOMValidateContext]
           [java.io ByteArrayInputStream]
           [javax.xml.parsers DocumentBuilderFactory]
           [org.w3c.dom Document]
           [org.w3c.dom NodeList]
           [org.apache.xml.security.c14n Canonicalizer]))

(defn make-xml-string
  "Creates an XML string using hiccup."
  [structure]
  (str
    (hiccup.page/xml-declaration "UTF-8")
    (hiccup.core/html structure)))

(defn singleton-key-selector
  "Always uses a provided key as a selector."
  [jkey]
  (KeySelector/singletonKeySelector jkey))

(defn new-doc-builder
  []
  (let [doc (DocumentBuilderFactory/newInstance)]
    (.setNamespaceAware doc true)
    (.setFeature doc "http://xml.org/sax/features/external-general-entities" false)
    (.setFeature doc "http://xml.org/sax/features/external-parameter-entities" false)
    (.setFeature doc "http://apache.org/xml/features/nonvalidating/load-external-dtd" false)
    (.setExpandEntityReferences doc false)
    (.newDocumentBuilder doc)))

(defn new-xml-sig-factory
  []
  (XMLSignatureFactory/getInstance "DOM"))

(defn str->xmldoc
  [parsable-str]
  (let [document (new-doc-builder)]
    (.parse document (saml-shared/str->inputstream parsable-str))))

(defn xmlsig-from-xmldoc
  [xmldoc]
  (let [nodes (.getElementsByTagNameNS xmldoc XMLSignature/XMLNS "Signature")]
    ;;; Zero nodes means that we can't find a XML signature.
    (if (= (.getLength nodes) 0)
      ;;(throw (Throwable. "This XML document has no signature to verify."))
      nil
      (.item nodes 0)))) ;;; Take the first node.

(defn get-dom-context
  [kv-selector signature-node]
  (DOMValidateContext. kv-selector signature-node))

(defn validate-xml-signature
  "Checks if this XML document's signature is valid using the supplied certificate"
  [xml-string cert-string]
  (let [sig-factory (new-xml-sig-factory)
        public-key (saml-shared/jcert->public-key (saml-shared/certificate-x509 cert-string))
        xmldoc (str->xmldoc xml-string)
        xml-sig-node (xmlsig-from-xmldoc xmldoc)
        validate-signature #(let [context (get-dom-context (singleton-key-selector public-key) xml-sig-node)
                                  signature (.unmarshalXMLSignature sig-factory context)]
                              (.validate signature context))] 
    (if xml-sig-node (validate-signature)
      true)))

(defn dom-node->str [dom-node]
  (let [canonicalizer (Canonicalizer/getInstance Canonicalizer/ALGO_ID_C14N_EXCL_OMIT_COMMENTS)]
    (String. (.canonicalizeSubtree canonicalizer dom-node))))
