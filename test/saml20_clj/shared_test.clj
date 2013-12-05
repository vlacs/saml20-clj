(ns saml20-clj.shared-test
  (:require [clojure.test :refer :all]
            [saml20-clj.shared :as shared]))

(def arb-str "Th1s 15 50m3 s7r1ng w17h 13773r5 and numb3rs!")
(def arb-xml "<tag1 hasmore=\"1\"><tag2 hasmore=\"1\"><tag3>foobar</tag3></tag2><tag4>inter arma enim silent leges</tag4></tag1>")
(def arb-xml-rep [{:tag :tag1
                   :attrs {:hasmore "1"}
                   :content [{:tag :tag2
                              :attrs {:hasmore "1"}
                              :content[{:tag :tag3
                                        :attrs nil
                                        :content ["foobar"]}]}
                             {:tag :tag4
                              :attrs nil
                              :content ["inter arma enim silent leges"]}]}
                  nil])

(deftest test-str-to-stream-to-str
  (testing "Testing string to stream and stream to string transformations.")
  (is (= (shared/read-to-end (shared/str->inputstream arb-str)) arb-str)))

(deftest test-parse-xml-str
  (testing "Testing xml parsing from a string."
  (let [parsed (shared/parse-xml-str arb-xml)]
    (is (= parsed arb-xml-rep)))))
