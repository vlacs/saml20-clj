(ns saml20-clj.sp-test
  (:require [clojure.test :refer :all]
            [clj-time.core :as ctime]
            [saml20-clj.sp :refer :all]))

(deftest test-saml-next-id
  (testing "Changing saml last id state."
    (let [mutable (atom 0)
          ival @mutable]
      (is (= (inc ival) (next-saml-id! mutable))))))


(deftest test-saml-timeout-bump
  (testing "Attempt to bump a stateful saml timeout on a fake request."
    (let [mutable (ref {})
          saml-id 12345
          time-now (ctime/now)]
      (bump-saml-id-timeout! mutable saml-id time-now)
      (is (= (get @mutable saml-id) time-now)))))

(deftest test-prune-timed-out-ids
  (testing "Attempt to remove a stale record from a mutable hash."
    (let [mutable (ref {1 (ctime/date-time 2013 10 10)
                        2 (ctime/now)})
          timeout (ctime/minutes 10)]
      (prune-timed-out-ids! mutable timeout)
      (is (= (count @mutable) 1))
      (is (= (get @mutable 1) nil))
      (is (not= (get @mutable 2) nil)))))

