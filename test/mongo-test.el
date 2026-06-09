;;; mongo-test.el --- ERT tests for mongo.el -*- lexical-binding: t; -*-

;; Copyright (C) 2025-2026 Lucius Chen
;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Commentary:

;; Unit tests for the standalone MongoDB wire protocol client.

;;; Code:

(require 'cl-lib)
(require 'ert)
(require 'mongo)



(ert-deftest mongo-test-bson-roundtrip ()
  "The standalone mongo protocol layer should encode and decode core BSON."
  (let* ((document `(("name" . "Ann")
                     ("n" . 42)
                     ("score" . 12.5)
                     ("active" . t)
                     ("deleted" . :false)
                     ("missing" . nil)
                     ("_id" . ,(mongo-object-id
                                "64f000000000000000000001"))
                     ("payload" . ,(mongo-binary 0 "abc"))
                     ("rx" . ,(mongo-regex "^ann" "mi"))
                     ("ts" . ,(mongo-timestamp 1700000000 7))
                     ("decimal" . ,(mongo-decimal128 "1.23"))
                     ("undef" . ,(mongo-undefined))
                     ("code" . ,(mongo-code "return n"))
                     ("sym" . ,(mongo-symbol "legacy"))
                     ("lo" . ,(mongo-min-key))
                     ("hi" . ,(mongo-max-key))
                     ("nested" . ,(mongo-document
                                   '(("ok" . t))))
                     ("tags" . ["a" "b"])))
         (decoded (mongo--decode-document-from-string
                   (mongo--encode-document document))))
    (should (equal (cdr (assoc "name" decoded)) "Ann"))
    (should (= (cdr (assoc "n" decoded)) 42))
    (should (= (cdr (assoc "score" decoded)) 12.5))
    (should (eq (cdr (assoc "active" decoded)) t))
    (should (eq (cdr (assoc "deleted" decoded)) :false))
    (should (null (cdr (assoc "missing" decoded))))
    (should (equal (cdr (assoc "_id" decoded))
                   '(("$oid" . "64f000000000000000000001"))))
    (should (equal (cdr (assoc "payload" decoded))
                   '(("$binary" . (("subType" . "00")
                                   ("bytes" . "YWJj"))))))
    (should (equal (cdr (assoc "rx" decoded))
                   '(("$regularExpression" .
                      (("pattern" . "^ann")
                       ("options" . "im"))))))
    (should (equal (cdr (assoc "ts" decoded))
                   '(("$timestamp" .
                      (("t" . 1700000000)
                       ("i" . 7))))))
    (should (equal (cdr (assoc "decimal" decoded))
                   '(("$numberDecimal" . "1.23"))))
    (should (equal (cdr (assoc "undef" decoded))
                   '(("$undefined" . t))))
    (should (equal (cdr (assoc "code" decoded))
                   '(("$code" . "return n"))))
    (should (equal (cdr (assoc "sym" decoded))
                   '(("$symbol" . "legacy"))))
    (should (equal (cdr (assoc "lo" decoded))
                   '(("$minKey" . 1))))
    (should (equal (cdr (assoc "hi" decoded))
                   '(("$maxKey" . 1))))
    (should (equal (cdr (assoc "nested" decoded))
                   '(("ok" . t))))
    (should (equal (cdr (assoc "tags" decoded))
                   '("a" "b")))))



(ert-deftest mongo-test-public-caller-helpers ()
  "Public caller helper APIs should cover adapter needs."
  (should (mongo-document-value-p '(("x" . 1))))
  (should (equal (mongo-document-elements
                  (mongo-document '(("x" . 1))))
                 '(("x" . 1))))
  (should (equal (mongo-byte-string "abc") "abc"))
  (should (equal (mongo-bytes-to-hex (unibyte-string 0 15 255))
                 "000fff"))
  (should (mongo-response-ok-p '(("ok" . 1))))
  (should (equal (mongo-extended-json-to-bson-value
                  '(("$timestamp" . (("t" . 1) ("i" . 2)))))
                 (mongo-timestamp 1 2))))



(ert-deftest mongo-test-new-object-id-uses-bson-layout ()
  "Generated ObjectIds should use timestamp, random bytes, and counter."
  (let ((mongo--object-id-random (unibyte-string 1 2 3 4 5))
        (mongo--object-id-counter 1))
    (should (equal (mongo-object-id-hex
                    (mongo-new-object-id
                     (seconds-to-time 1700000000)))
                   "6553f1000102030405000001"))
    (should (equal (mongo-object-id-hex
                    (mongo-new-object-id
                     (seconds-to-time 1700000000)))
                   "6553f1000102030405000002"))))



(ert-deftest mongo-test-bson-double-encodes-ieee754 ()
  "MongoDB BSON double values should use little-endian IEEE-754 binary64."
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document '(("x" . 1.5))))
           "10000000017800000000000000f83f00"))
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document '(("x" . -2.25))))
           "1000000001780000000000000002c000"))
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document '(("x" . -0.0))))
           "10000000017800000000000000008000")))



(ert-deftest mongo-test-bson-datetime-encodes-millis ()
  "MongoDB BSON datetime values should encode as little-endian epoch millis."
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-datetime 1704164645678)))))
           "100000000978002edb20c88c01000000"))
  (should (equal
           (cdr (assoc "x"
                       (mongo--decode-document-from-string
                        (mongo--encode-document
                         (list (cons "x"
                                     (mongo-datetime 1704164645678)))))))
           '(("$date" . 1704164645678)))))



(ert-deftest mongo-test-bson-timestamp-encodes-increment-and-seconds ()
  "MongoDB BSON timestamp values should encode increment first, then seconds."
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-timestamp 1700000000 7)))))
           "100000001178000700000000f1536500"))
  (should (equal
           (cdr (assoc "x"
                       (mongo--decode-document-from-string
                        (mongo--encode-document
                         (list (cons "x"
                                     (mongo-timestamp 1700000000 7)))))))
           '(("$timestamp" . (("t" . 1700000000)
                              ("i" . 7))))))
  (should-error
   (mongo--encode-document
    (list (cons "x" (mongo-timestamp -1 0))))
   :type 'mongo-error))



(ert-deftest mongo-test-bson-int64-wrapper-encodes-long ()
  "MongoDB BSON int64 wrapper should force long encoding for small integers."
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-int64 7)))))
           "10000000127800070000000000000000"))
  (should-error
   (mongo--encode-document
    (list (cons "x" (mongo-int64 (expt 2 63)))))
   :type 'mongo-error))



(ert-deftest mongo-test-bson-int32-wrapper-encodes-int ()
  "MongoDB BSON int32 wrapper should force int encoding and validate range."
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-int32 7)))))
           "0c0000001078000700000000"))
  (should-error
   (mongo--encode-document
    (list (cons "x" (mongo-int32 (1+ mongo--int32-max)))))
   :type 'mongo-error))



(ert-deftest mongo-test-bson-decimal128-encodes-native-bytes ()
  "MongoDB BSON Decimal128 values should use the native type 0x13 payload."
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-decimal128 "1.23")))))
           "180000001378007b000000000000000000000000003c3000"))
  (should (equal
           (cdr (assoc "x"
                       (mongo--decode-document-from-string
                        (mongo--encode-document
                         (list (cons "x" (mongo-decimal128 "12.3400")))))))
           '(("$numberDecimal" . "12.3400"))))
  (should (equal
           (cdr (assoc "x"
                       (mongo--decode-document-from-string
                        (mongo--encode-document
                         (list (cons "x" (mongo-decimal128 "NaN")))))))
           '(("$numberDecimal" . "NaN"))))
  (should (equal
           (cdr (assoc "x"
                       (mongo--decode-document-from-string
                        (mongo--encode-document
                         (list (cons "x" (mongo-decimal128 "-Infinity")))))))
           '(("$numberDecimal" . "-Infinity"))))
  (should-error
   (mongo--encode-document
    (list (cons "x" (mongo-decimal128
                     "1.2345678901234567890123456789012345"))))
   :type 'mongo-error))



(ert-deftest mongo-test-bson-legacy-types-encode-decode ()
  "MongoDB BSON legacy compatibility types should not break result decoding."
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-undefined)))))
           "0800000006780000"))
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-code "return 1")))))
           "150000000d78000900000072657475726e20310000"))
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-code
                              "return x"
                              (mongo-document '(("x" . 1))))))))
           (concat
            "250000000f78001d0000000900000072657475726e207800"
            "0c000000107800010000000000")))
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-symbol "abc")))))
           "100000000e7800040000006162630000"))
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-db-pointer
                              "users"
                              "64f000000000000000000001")))))
           (concat
            "1e0000000c780006000000757365727300"
            "64f00000000000000000000100")))
  (let* ((document
          `(("undef" . ,(mongo-undefined))
            ("code" . ,(mongo-code "return x" (mongo-document '(("x" . 1)))))
            ("sym" . ,(mongo-symbol "abc"))
            ("ptr" . ,(mongo-db-pointer
                       "users"
                       (mongo-object-id "64f000000000000000000001")))))
         (decoded (mongo--decode-document-from-string
                   (mongo--encode-document document))))
    (should (equal (cdr (assoc "undef" decoded))
                   '(("$undefined" . t))))
    (should (equal (cdr (assoc "code" decoded))
                   '(("$code" . "return x")
                     ("$scope" . (("x" . 1))))))
    (should (equal (cdr (assoc "sym" decoded))
                   '(("$symbol" . "abc"))))
    (should (equal (cdr (assoc "ptr" decoded))
                   '(("$dbPointer" .
                      (("$ref" . "users")
                       ("$id" . (("$oid" . "64f000000000000000000001"))))))))))



(ert-deftest mongo-test-bson-binary-constructors-encode-subtypes ()
  "MongoDB BSON binary helpers should encode modern UUID and old binary."
  (let ((uuid (mongo-uuid "00112233-4455-6677-8899-aabbccddeeff")))
    (should (mongo-binary-p uuid))
    (should (= (mongo-binary-subtype uuid) 4))
    (should (equal (mongo--bytes-to-hex (mongo-binary-data uuid))
                   "00112233445566778899aabbccddeeff"))
    (should (equal
             (mongo--bytes-to-hex
              (mongo--encode-document
               (list (cons "x" uuid))))
             "1d000000057800100000000400112233445566778899aabbccddeeff00")))
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-binary 2 "abc")))))
           "1400000005780007000000020300000061626300"))
  (should (equal
           (cdr (assoc "x"
                       (mongo--decode-document-from-string
                        (mongo--encode-document
                         (list (cons "x" (mongo-binary 2 "abc")))))))
           '(("$binary" . (("subType" . "02")
                           ("bytes" . "YWJj"))))))
  (should-error
   (mongo-uuid "not-a-uuid")
   :type 'mongo-error))



(ert-deftest mongo-test-bson-regex-encodes-type-11 ()
  "MongoDB BSON regex values should encode as type 0x0B with sorted options."
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-regex "^ann" "mi")))))
           "100000000b78005e616e6e00696d0000")))



(ert-deftest mongo-test-bson-min-max-key-encode-as-boundary-types ()
  "MongoDB BSON MinKey and MaxKey should encode as boundary type markers."
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-min-key)))))
           "08000000ff780000"))
  (should (equal
           (mongo--bytes-to-hex
            (mongo--encode-document
             (list (cons "x" (mongo-max-key)))))
           "080000007f780000"))
  (should (equal
           (cdr (assoc "x"
                       (mongo--decode-document-from-string
                        (mongo--encode-document
                         (list (cons "x" (mongo-min-key)))))))
           '(("$minKey" . 1))))
  (should (equal
           (cdr (assoc "x"
                       (mongo--decode-document-from-string
                        (mongo--encode-document
                         (list (cons "x" (mongo-max-key)))))))
           '(("$maxKey" . 1)))))



(ert-deftest mongo-test-find-includes-cursor-options ()
  "MongoDB find command should include supported cursor option fields."
  (let ((filter (mongo-document '(("active" . t))))
        (projection (mongo-document '(("name" . 1))))
        (sort (mongo-document '(("createdAt" . -1))))
        (hint (mongo-document '(("active" . 1)
                                ("createdAt" . -1))))
        (max (mongo-document '(("createdAt" . 999))))
        (min (mongo-document '(("createdAt" . 1))))
        (let-doc (mongo-document '(("cutoff" . 7))))
        (collation (mongo-document '(("locale" . "en"))))
        captured)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (conn database command &optional _timeout)
                 (setq captured (list conn database command))
                 '(("cursor" . (("firstBatch" . [])))))))
      (mongo-find
       'wire "app" "users" filter projection 10 5
       `(("sort" . ,sort)
         ("hint" . ,hint)
         ("max" . ,max)
         ("min" . ,min)
         ("maxTimeMS" . 250)
         ("batchSize" . 50)
         ("comment" . "clutch")
         ("let" . ,let-doc)
         ("allowDiskUse" . t)
         ("allowPartialResults" . :false)
         ("awaitData" . t)
         ("tailable" . t)
         ("maxAwaitTimeMS" . 750)
         ("noCursorTimeout" . t)
         ("returnKey" . :false)
         ("showRecordId" . t)
         ("collation" . ,collation))))
    (pcase-let ((`(,conn ,database ,command) captured))
      (should (eq conn 'wire))
      (should (equal database "app"))
      (should (equal (cdr (assoc "find" command)) "users"))
      (should (eq (cdr (assoc "filter" command)) filter))
      (should (eq (cdr (assoc "projection" command)) projection))
      (should (= (cdr (assoc "limit" command)) 10))
      (should (= (cdr (assoc "skip" command)) 5))
      (should (= (cdr (assoc "batchSize" command)) 50))
      (should (eq (cdr (assoc "sort" command)) sort))
      (should (eq (cdr (assoc "hint" command)) hint))
      (should (eq (cdr (assoc "max" command)) max))
      (should (eq (cdr (assoc "min" command)) min))
      (should (= (cdr (assoc "maxTimeMS" command)) 250))
      (should (equal (cdr (assoc "comment" command)) "clutch"))
      (should (eq (cdr (assoc "let" command)) let-doc))
      (should (eq (cdr (assoc "allowDiskUse" command)) t))
      (should (eq (cdr (assoc "allowPartialResults" command)) :false))
      (should (eq (cdr (assoc "awaitData" command)) t))
      (should (eq (cdr (assoc "tailable" command)) t))
      (should-not (assoc "maxAwaitTimeMS" command))
      (should (eq (cdr (assoc "noCursorTimeout" command)) t))
      (should (eq (cdr (assoc "returnKey" command)) :false))
      (should (eq (cdr (assoc "showRecordId" command)) t))
      (should (eq (cdr (assoc "collation" command)) collation)))))



(ert-deftest mongo-test-find-passes-getmore-cursor-options ()
  "MongoDB find should use batchSize and maxAwaitTimeMS on getMore."
  (let ((calls 0))
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (setq calls (1+ calls))
                 (pcase calls
                   (1
                    (should (equal database "app"))
                    (should (equal (cdr (assoc "find" command)) "users"))
                    (should (= (cdr (assoc "batchSize" command)) 3))
                    (should (eq (cdr (assoc "tailable" command)) t))
                    (should (eq (cdr (assoc "awaitData" command)) t))
                    (should-not (assoc "maxAwaitTimeMS" command))
                    '(("cursor" . (("id" . 42)
                                   ("ns" . "app.users")
                                   ("firstBatch" . ((("n" . 1))))))))
                   (2
                    (should (equal database "app"))
                    (should (equal command
                                   '(("getMore" . 42)
                                     ("collection" . "users")
                                     ("batchSize" . 3)
                                     ("maxTimeMS" . 750))))
                    '(("cursor" . (("id" . 0)
                                   ("ns" . "app.users")
                                   ("nextBatch" . ((("n" . 2))))))))
                   (_
                    (ert-fail "unexpected extra MongoDB command"))))))
      (should (equal (mongo-find
                      'wire "app" "users" nil nil nil nil
                     '(("batchSize" . 3)
                        ("tailable" . t)
                        ("awaitData" . t)
                        ("maxAwaitTimeMS" . 750)))
                     '((("n" . 1))
                       (("n" . 2))))))))



(ert-deftest mongo-test-find-stops-awaitable-cursor-on-empty-batch ()
  "Awaitable tailable cursors should not loop forever on empty getMore batches."
  (let ((calls 0))
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (setq calls (1+ calls))
                 (pcase calls
                   (1
                    (should (equal database "app"))
                    (should (equal (cdr (assoc "find" command)) "events"))
                    '(("cursor" . (("id" . 42)
                                   ("ns" . "app.events")
                                   ("firstBatch" . ((("n" . 1))))))))
                   (2
                    (should (equal database "app"))
                    (should (equal command
                                   '(("getMore" . 42)
                                     ("collection" . "events")
                                     ("batchSize" . 2)
                                     ("maxTimeMS" . 25))))
                    '(("cursor" . (("id" . 42)
                                   ("ns" . "app.events")
                                   ("nextBatch" . nil)))))
                   (3
                    (should (equal database "app"))
                    (should (equal command
                                   '(("killCursors" . "events")
                                     ("cursors" . [42]))))
                    '(("ok" . 1)
                      ("cursorsKilled" . [42])))
                   (_
                    (ert-fail "unexpected extra MongoDB command"))))))
      (should (equal (mongo-find
                      'wire "app" "events" nil nil nil nil
                      '(("batchSize" . 2)
                        ("tailable" . t)
                        ("awaitData" . t)
                        ("maxAwaitTimeMS" . 25)))
                     '((("n" . 1)))))
      (should (= calls 3)))))



(ert-deftest mongo-test-count-distinct-and-index-commands ()
  "MongoDB collection helper commands should build expected command shapes."
  (let ((filter (mongo-document '(("active" . t))))
        (keys (mongo-document '(("active" . 1)
                                ("createdAt" . -1))))
        (collection-options (mongo-document '(("capped" . t)
                                              ("size" . 4096))))
        commands)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (push (list database command) commands)
                 (pcase (car command)
                   (`("count" . ,_)
                    '(("ok" . 1) ("n" . 7)))
                   (`("distinct" . ,_)
                    '(("ok" . 1) ("values" . ("a" "b"))))
                   (`("listIndexes" . ,_)
                    '(("cursor" . (("firstBatch" . ((("name" . "_id_"))))
                                   ("id" . 0)))))
                   (_ '(("ok" . 1)))))))
      (should (= (mongo-count-documents
                  'wire "app" "users" filter
                  '(("limit" . 10)))
                 7))
      (should (equal (mongo-distinct
                      'wire "app" "users" "name" filter)
                     '("a" "b")))
      (should (equal (mongo-list-indexes 'wire "app" "users")
                     '((("name" . "_id_")))))
      (mongo-create-collection
       'wire "app" "events" collection-options)
      (mongo-create-index
       'wire "app" "users" keys
       '(("name" . "active_created")
         ("unique" . t)))
      (mongo-drop-index 'wire "app" "users" "active_created"))
    (setq commands (nreverse commands))
    (let ((count-command (cadr (nth 0 commands)))
          (distinct-command (cadr (nth 1 commands)))
          (list-indexes-command (cadr (nth 2 commands)))
          (create-collection-command (cadr (nth 3 commands)))
          (create-index-command (cadr (nth 4 commands)))
          (drop-index-command (cadr (nth 5 commands))))
      (should (equal count-command
                     `(("count" . "users")
                       ("query" . ,filter)
                       ("limit" . 10))))
      (should (equal distinct-command
                     `(("distinct" . "users")
                       ("key" . "name")
                       ("query" . ,filter))))
      (should (equal (cdr (assoc "listIndexes" list-indexes-command))
                     "users"))
      (should (mongo-document-p
               (cdr (assoc "cursor" list-indexes-command))))
      (should (equal create-collection-command
                     '(("create" . "events")
                       ("capped" . t)
                       ("size" . 4096))))
      (let* ((indexes (cdr (assoc "indexes" create-index-command)))
             (spec (aref indexes 0)))
        (should (equal (cdr (assoc "createIndexes" create-index-command))
                       "users"))
        (should (eq (cdr (assoc "key" spec)) keys))
        (should (equal (cdr (assoc "name" spec)) "active_created"))
        (should (eq (cdr (assoc "unique" spec)) t)))
      (should (equal drop-index-command
                     '(("dropIndexes" . "users")
                       ("index" . "active_created")))))))



(ert-deftest mongo-test-aggregate-includes-command-options ()
  "MongoDB aggregate should include supported command option fields."
  (let ((pipeline [(("$match" . (("active" . t))))])
        (collation (mongo-document '(("locale" . "en"))))
        (let-doc (mongo-document '(("cutoff" . 7))))
        captured)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (conn database command &optional _timeout)
                 (setq captured (list conn database command))
                 '(("cursor" . (("firstBatch" . [])))))))
      (mongo-aggregate
       'wire "app" "users" pipeline
       `(("allowDiskUse" . t)
         ("batchSize" . 25)
         ("comment" . "agg")
         ("collation" . ,collation)
         ("let" . ,let-doc)
         ("maxTimeMS" . 500))))
    (pcase-let ((`(,conn ,database ,command) captured))
      (should (eq conn 'wire))
      (should (equal database "app"))
      (should (equal (cdr (assoc "aggregate" command)) "users"))
      (should (eq (cdr (assoc "pipeline" command)) pipeline))
      (let ((cursor (cdr (assoc "cursor" command))))
        (should (mongo-document-p cursor))
        (should (equal (mongo-document-pairs cursor)
                       '(("batchSize" . 25)))))
      (should-not (assoc "batchSize" command))
      (should (eq (cdr (assoc "allowDiskUse" command)) t))
      (should (equal (cdr (assoc "comment" command)) "agg"))
      (should (eq (cdr (assoc "collation" command)) collation))
      (should (eq (cdr (assoc "let" command)) let-doc))
      (should (= (cdr (assoc "maxTimeMS" command)) 500)))))



(ert-deftest mongo-test-aggregate-database-uses-command-cursor ()
  "Database-level aggregate should use the command cursor namespace for getMore."
  (let ((pipeline [(("$documents" . [((("n" . 1)))]))])
        (calls 0)
        commands)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (push (list database command) commands)
                 (setq calls (1+ calls))
                 (pcase calls
                   (1
                    (should (equal database "app"))
                    (should (equal (cdr (assoc "aggregate" command)) 1))
                    (should (eq (cdr (assoc "pipeline" command)) pipeline))
                    '(("cursor" . (("id" . 42)
                                   ("ns" . "app.$cmd.aggregate")
                                   ("firstBatch" . ((("n" . 1))))))))
                   (2
                    (should (equal database "app"))
                    (should (equal command
                                   '(("getMore" . 42)
                                     ("collection" . "$cmd.aggregate")
                                     ("batchSize" . 25))))
                    '(("cursor" . (("id" . 0)
                                   ("ns" . "app.$cmd.aggregate")
                                   ("nextBatch" . ((("n" . 2))))))))
                   (_
                    (ert-fail "unexpected extra MongoDB command"))))))
      (should (equal (mongo-aggregate-database
                      'wire "app" pipeline
                      '(("comment" . "db-agg")
                        ("batchSize" . 25)))
                     '((("n" . 1))
                       (("n" . 2))))))
    (setq commands (nreverse commands))
    (let ((aggregate-command (cadr (car commands))))
      (should (equal (cdr (assoc "comment" aggregate-command))
                     "db-agg"))
      (let ((cursor (cdr (assoc "cursor" aggregate-command))))
        (should (mongo-document-p cursor))
        (should (equal (mongo-document-pairs cursor)
                       '(("batchSize" . 25))))))))



(ert-deftest mongo-test-watch-command-maps-change-stream-options ()
  "MongoDB watch should map options to $changeStream, cursor, and command fields."
  (let* ((resume (mongo-document '(("_data" . "token"))))
         (collation (mongo-document '(("locale" . "en"))))
         (pipeline [(("$match" . (("operationType" . "insert"))))])
         (command
          (mongo-watch-command
           "users" pipeline
           `(("fullDocument" . "updateLookup")
             ("resumeAfter" . ,resume)
             ("showExpandedEvents" . t)
             ("batchSize" . 5)
             ("maxAwaitTimeMS" . 25)
             ("collation" . ,collation)
             ("comment" . "watch"))))
         (watch-pipeline (cdr (assoc "pipeline" command)))
         (change-stream-stage (aref watch-pipeline 0))
         (change-stream-options
          (cdr (assoc "$changeStream"
                      (mongo-document-pairs change-stream-stage))))
         (cursor (cdr (assoc "cursor" command))))
    (should (equal (cdr (assoc "aggregate" command)) "users"))
    (should (= (length watch-pipeline) 2))
    (should (mongo-document-p change-stream-stage))
    (should (mongo-document-p change-stream-options))
    (should (equal (cdr (assoc "fullDocument"
                               (mongo-document-pairs change-stream-options)))
                   "updateLookup"))
    (should (eq (cdr (assoc "resumeAfter"
                            (mongo-document-pairs change-stream-options)))
                resume))
    (should (eq (cdr (assoc "showExpandedEvents"
                            (mongo-document-pairs change-stream-options)))
                t))
    (should (eq (aref watch-pipeline 1)
                (aref pipeline 0)))
    (should (mongo-document-p cursor))
    (should (equal (mongo-document-pairs cursor)
                   '(("batchSize" . 5))))
    (should (eq (cdr (assoc "collation" command)) collation))
    (should (equal (cdr (assoc "comment" command)) "watch"))
    (should-not (assoc "maxAwaitTimeMS" command))
    (should-not (assoc "fullDocument" command))))



(ert-deftest mongo-test-watch-stops-on-empty-batch ()
  "MongoDB watch should close the cursor after the first empty await batch."
  (let ((calls 0))
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (setq calls (1+ calls))
                 (pcase calls
                   (1
                    (should (equal database "app"))
                    (should (equal (cdr (assoc "aggregate" command)) "users"))
                    '(("cursor" . (("id" . 42)
                                   ("ns" . "app.users")
                                   ("firstBatch" .
                                    ((("operationType" . "insert"))))))))
                   (2
                    (should (equal command
                                   '(("getMore" . 42)
                                     ("collection" . "users")
                                     ("batchSize" . 2)
                                     ("maxTimeMS" . 25))))
                    '(("cursor" . (("id" . 42)
                                   ("ns" . "app.users")
                                   ("nextBatch" . nil)))))
                   (3
                    (should (equal command
                                   '(("killCursors" . "users")
                                     ("cursors" . [42]))))
                    '(("ok" . 1)))
                   (_
                    (ert-fail "unexpected extra MongoDB command"))))))
      (should (equal (mongo-watch
                      'wire "app" "users" []
                      '(("batchSize" . 2)
                        ("maxAwaitTimeMS" . 25)))
                     '((("operationType" . "insert")))))
      (should (= calls 3)))))



(ert-deftest mongo-test-explain-wraps-command ()
  "MongoDB explain should wrap command documents and normalize verbosity."
  (let (captured)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (conn database command &optional _timeout)
                 (setq captured (list conn database command))
                 '(("ok" . 1)
                   ("queryPlanner" . (("namespace" . "app.users")))))))
      (mongo-explain
       'wire "app"
       (mongo-find-command
        "users"
        (mongo-document '(("active" . t))))
       t))
    (pcase-let ((`(,conn ,database ,command) captured))
      (should (eq conn 'wire))
      (should (equal database "app"))
      (should (equal (cdr (assoc "verbosity" command))
                     "allPlansExecution"))
      (let ((explained (cdr (assoc "explain" command))))
        (should (mongo-document-p explained))
        (should (equal (mongo-document-pairs explained)
                       `(("find" . "users")
                         ("filter" . ,(mongo-document
                                        '(("active" . t))))
                         ("batchSize" . 1000))))))))



(ert-deftest mongo-test-insert-delete-use-document-sequences ()
  "MongoDB insert/delete helpers should put batch specs in OP_MSG sequences."
  (let ((first (mongo-document '(("_id" . "a"))))
        (second (mongo-document '(("_id" . "b"))))
        (filter (mongo-document '(("active" . :false))))
        calls)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout sequences)
                 (push (list database command sequences) calls)
                 '(("ok" . 1)))))
      (mongo-insert 'wire "app" "users" (vector first second) :false)
      (mongo-delete 'wire "app" "users" filter 1))
    (setq calls (nreverse calls))
    (pcase-let* ((`(,insert-db ,insert-command ,insert-sequences)
                  (nth 0 calls))
                 (insert-documents (cdr (assoc "documents" insert-sequences))))
      (should (equal insert-db "app"))
      (should (equal insert-command
                     '(("insert" . "users")
                       ("ordered" . :false))))
      (should-not (assoc "documents" insert-command))
      (should (= (length insert-documents) 2))
      (should (eq (aref insert-documents 0) first))
      (should (eq (aref insert-documents 1) second)))
    (pcase-let* ((`(,delete-db ,delete-command ,delete-sequences)
                  (nth 1 calls))
                 (delete-specs (cdr (assoc "deletes" delete-sequences)))
                 (delete-spec (aref delete-specs 0)))
      (should (equal delete-db "app"))
      (should (equal delete-command
                     '(("delete" . "users"))))
      (should-not (assoc "deletes" delete-command))
      (should (eq (cdr (assoc "q" delete-spec)) filter))
      (should (= (cdr (assoc "limit" delete-spec)) 1)))))



(ert-deftest mongo-test-insert-generates-missing-document-ids ()
  "MongoDB insert helper should generate `_id' for documents missing one."
  (let ((missing-id (mongo-document '(("name" . "Ann"))))
        (existing-id (mongo-document '(("_id" . "known")
                                       ("name" . "Bob"))))
        captured)
    (cl-letf (((symbol-function 'mongo-new-object-id)
               (lambda (&optional _time)
                 (mongo-object-id "64f000000000000000000001")))
              ((symbol-function 'mongo-command)
               (lambda (_conn _database _command &optional _timeout sequences)
                 (setq captured sequences)
                 '(("ok" . 1)))))
      (mongo-insert 'wire "app" "users" (vector missing-id existing-id)))
    (let* ((docs (cdr (assoc "documents" captured)))
           (generated (aref docs 0)))
      (should (mongo-document-p generated))
      (should-not (eq generated missing-id))
      (should (equal (cdr (assoc "_id" (mongo-document-pairs generated)))
                     (mongo-object-id "64f000000000000000000001")))
      (should (equal (cdr (assoc "name" (mongo-document-pairs generated)))
                     "Ann"))
      (should (eq (aref docs 1) existing-id)))))



(ert-deftest mongo-test-insert-splits-at-max-write-batch-size ()
  "MongoDB insert helper should split batches at hello maxWriteBatchSize."
  (let* ((conn (make-mongo-conn :max-write-batch-size 2))
         (docs (vector (mongo-document '(("_id" . "a")))
                       (mongo-document '(("_id" . "b")))
                       (mongo-document '(("_id" . "c")))
                       (mongo-document '(("_id" . "d")))
                       (mongo-document '(("_id" . "e")))))
         batches
         commands)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn _database command &optional _timeout sequences)
                 (push command commands)
                 (push (cdr (assoc "documents" sequences)) batches)
                 '(("ok" . 1)))))
      (mongo-insert conn "app" "users" docs))
    (setq batches (nreverse batches)
          commands (nreverse commands))
    (should (= (length batches) 3))
    (should (equal (mapcar #'length batches) '(2 2 1)))
    (should (equal (mapcar (lambda (batch)
                             (mapcar (lambda (doc)
                                       (cdr (assoc "_id"
                                                   (mongo-document-pairs doc))))
                                     (append batch nil)))
                           batches)
                   '(("a" "b") ("c" "d") ("e"))))
    (should (equal commands
                   '((("insert" . "users")
                      ("ordered" . t))
                     (("insert" . "users")
                      ("ordered" . t))
                     (("insert" . "users")
                      ("ordered" . t)))))))



(ert-deftest mongo-test-insert-splits-at-max-message-size ()
  "MongoDB insert helper should split batches before maxMessageSizeBytes."
  (let* ((command '(("insert" . "users")
                    ("ordered" . t)))
         (docs (vector (mongo-document '(("_id" . "a")
                                         ("payload" . "aaaaaaaaaa")))
                       (mongo-document '(("_id" . "b")
                                         ("payload" . "bbbbbbbbbb")))
                       (mongo-document '(("_id" . "c")
                                         ("payload" . "cccccccccc")))))
         (base-conn (make-mongo-conn :max-write-batch-size 100
                                     :max-bson-object-size 1000))
         (first-size (length (mongo--encode-document (aref docs 0))))
         (second-size (length (mongo--encode-document (aref docs 1))))
         (message-overhead
          (+ (length (mongo--make-op-msg
                      1
                      (mongo--command-for-size-estimate
                       base-conn "app" command)
                      nil nil nil))
             (mongo--document-sequence-overhead-bytes "documents")
             mongo--write-batch-message-safety-bytes))
         (conn (make-mongo-conn
                :max-write-batch-size 100
                :max-bson-object-size 1000
                :max-message-size-bytes
                (+ message-overhead first-size second-size -1)))
         batches)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn _database _command &optional _timeout sequences)
                 (push (cdr (assoc "documents" sequences)) batches)
                 '(("ok" . 1)))))
      (mongo-insert conn "app" "users" docs))
    (setq batches (nreverse batches))
    (should (= (length batches) 3))
    (should (equal (mapcar #'length batches) '(1 1 1)))
    (should (equal (mapcar (lambda (batch)
                             (cdr (assoc "_id"
                                         (mongo-document-pairs
                                          (aref batch 0)))))
                           batches)
                   '("a" "b" "c")))))



(ert-deftest mongo-test-insert-rejects-too-large-document ()
  "MongoDB insert helper should reject documents above maxBsonObjectSize."
  (let* ((doc (mongo-document '(("_id" . "a")
                                ("payload" . "aaaaaaaaaa"))))
         (conn (make-mongo-conn
                :max-write-batch-size 100
                :max-bson-object-size
                (1- (length (mongo--encode-document doc)))
                :max-message-size-bytes 48000000)))
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (&rest _args)
                 (ert-fail "oversized insert document should not be sent"))))
      (should-error
       (mongo-insert conn "app" "users" (vector doc))
       :type 'mongo-error))))



(ert-deftest mongo-test-update-includes-update-options ()
  "MongoDB update command should include q/u/multi and update options."
  (let ((filter (mongo-document '(("active" . t))))
        (update (mongo-document '(("$set" . (("seen" . t))))))
        (collation (mongo-document '(("locale" . "en"))))
        captured)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (conn database command &optional _timeout sequences)
                 (setq captured (list conn database command sequences))
                 '(("ok" . 1)
                   ("matchedCount" . 1)))))
      (mongo-update
       'wire "app" "users" filter update t
       `(("upsert" . t)
         ("collation" . ,collation)
         ("hint" . "active_1"))))
    (pcase-let* ((`(,conn ,database ,command ,sequences) captured)
                 (updates (cdr (assoc "updates" sequences)))
                 (spec (aref updates 0)))
      (should (eq conn 'wire))
      (should (equal database "app"))
      (should (equal (cdr (assoc "update" command)) "users"))
      (should-not (assoc "updates" command))
      (should (eq (cdr (assoc "q" spec)) filter))
      (should (eq (cdr (assoc "u" spec)) update))
      (should (eq (cdr (assoc "multi" spec)) t))
      (should (eq (cdr (assoc "upsert" spec)) t))
      (should (eq (cdr (assoc "collation" spec)) collation))
      (should (equal (cdr (assoc "hint" spec)) "active_1")))))



(ert-deftest mongo-test-find-and-modify-maps-options ()
  "MongoDB findAndModify command should map shell-style options."
  (let ((filter (mongo-document '(("_id" . "a"))))
        (update (mongo-document '(("$set" . (("seen" . t))))))
        (projection (mongo-document '(("_id" . 1)
                                      ("seen" . 1))))
        (sort (mongo-document '(("createdAt" . -1))))
        captured)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (conn database command &optional _timeout)
                 (setq captured (list conn database command))
                 '(("ok" . 1)
                   ("value" . nil)))))
      (mongo-find-and-modify
       'wire "app" "users" filter update nil
       `(("projection" . ,projection)
         ("sort" . ,sort)
         ("upsert" . t)
         ("returnDocument" . "after"))))
    (pcase-let ((`(,conn ,database ,command) captured))
      (should (eq conn 'wire))
      (should (equal database "app"))
      (should (equal (cdr (assoc "findAndModify" command)) "users"))
      (should (eq (cdr (assoc "query" command)) filter))
      (should (eq (cdr (assoc "update" command)) update))
      (should (eq (cdr (assoc "fields" command)) projection))
      (should (eq (cdr (assoc "sort" command)) sort))
      (should (eq (cdr (assoc "upsert" command)) t))
      (should (eq (cdr (assoc "new" command)) t)))))



(ert-deftest mongo-test-pbkdf2-sha256-vector ()
  "The SCRAM PBKDF2 implementation should match published SHA-256 vectors."
  (should
   (equal
    (mongo--bytes-to-hex
     (mongo--pbkdf2-hmac-sha256 "password" "salt" 1))
    "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"))
  (should
   (equal
    (mongo--bytes-to-hex
     (mongo--pbkdf2-hmac-sha256 "password" "salt" 2))
    "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")))



(ert-deftest mongo-test-pbkdf2-sha1-vector ()
  "The SCRAM PBKDF2 implementation should match published SHA-1 vectors."
  (should
   (equal
    (mongo--bytes-to-hex
     (mongo--pbkdf2-hmac-sha1 "password" "salt" 1))
    "0c60c80f961f0e71f3a9b524af6012062fe037a6"))
  (should
   (equal
    (mongo--bytes-to-hex
     (mongo--pbkdf2-hmac-sha1 "password" "salt" 2))
    "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")))



(ert-deftest mongo-test-crc32c-vector ()
  "MongoDB OP_MSG CRC-32C should match the Castagnoli test vector."
  (should (= (mongo--crc32c "123456789") #xe3069283)))



(ert-deftest mongo-test-op-msg-roundtrip-body ()
  "The standalone mongo protocol layer should frame OP_MSG bodies."
  (let* ((body '(("ping" . 1) ("$db" . "admin")))
         (message (mongo--make-op-msg 7 body)))
    (should (equal (mongo--decode-op-msg message) body))))



(ert-deftest mongo-test-op-msg-frame-preserves-metadata ()
  "OP_MSG frame decoding should preserve wire header metadata."
  (let* ((body '(("ok" . 1)))
         (message (mongo--make-op-msg 7 body nil nil nil 42))
         (frame (mongo--decode-message-frame message)))
    (should (= (mongo--decoded-message-request-id frame) 7))
    (should (= (mongo--decoded-message-response-to frame) 42))
    (should (= (mongo--decoded-message-opcode frame) mongo--op-msg))
    (should (= (mongo--decoded-message-flags frame) 0))
    (should (equal (mongo--decoded-message-document frame) body))))



(ert-deftest mongo-test-op-msg-encodes-document-sequence ()
  "OP_MSG requests should encode kind 1 document sequence sections."
  (let* ((body '(("insert" . "users") ("$db" . "app")))
         (first '(("_id" . "a")))
         (second '(("_id" . "b")))
         (message
          (mongo--make-op-msg
           7 body nil nil
           `(("documents" . ,(vector first second)))))
         (reader (make-mongo--reader :data message :pos 0)))
    (should (= (mongo--read-int32 reader) (length message)))
    (should (= (mongo--read-int32 reader) 7))
    (should (= (mongo--read-int32 reader) 0))
    (should (= (mongo--read-int32 reader) mongo--op-msg))
    (should (= (mongo--read-int32 reader) 0))
    (should (= (mongo--read-byte reader) 0))
    (should (equal (mongo--decode-document reader) body))
    (should (= (mongo--read-byte reader) 1))
    (let* ((section-start (mongo--reader-pos reader))
           (section-size (mongo--read-int32 reader))
           (section-end (+ section-start section-size)))
      (should (equal (mongo--read-cstring reader) "documents"))
      (should (equal (mongo--decode-document reader) first))
      (should (equal (mongo--decode-document reader) second))
      (should (= (mongo--reader-pos reader) section-end))
      (should (= section-end (length message))))))



(ert-deftest mongo-test-op-msg-validates-checksum-trailer ()
  "The OP_MSG decoder should validate CRC-32C checksum trailers."
  (let* ((body '(("ok" . 1)))
         (message (mongo--make-op-msg 7 body nil t)))
    (should (equal (mongo--decode-op-msg message) body))))



(ert-deftest mongo-test-op-msg-rejects-bad-checksum ()
  "The OP_MSG decoder should reject mismatched CRC-32C checksum trailers."
  (let* ((body '(("ok" . 1)))
         (message (mongo--make-op-msg 7 body nil #x01020304)))
    (should-error (mongo--decode-op-msg message) :type 'mongo-error)))



(ert-deftest mongo-test-op-msg-rejects-unknown-required-flag ()
  "The OP_MSG decoder should reject unknown required flag bits."
  (let* ((body '(("ok" . 1)))
         (message (mongo--make-op-msg 7 body #x4)))
    (should-error (mongo--decode-op-msg message) :type 'mongo-error)))



(ert-deftest mongo-test-op-msg-ignores-optional-flag ()
  "The OP_MSG decoder should ignore optional high flag bits."
  (let* ((body '(("ok" . 1)))
         (message (mongo--make-op-msg 7 body #x10000)))
    (should (equal (mongo--decode-op-msg message) body))))



(ert-deftest mongo-test-op-msg-rejects-unexpected-more-to-come ()
  "The OP_MSG decoder should reject moreToCome without exhaustAllowed."
  (let* ((body '(("ok" . 1)))
         (message (mongo--make-op-msg
                   7 body mongo--op-msg-more-to-come)))
    (should-error (mongo--decode-op-msg message) :type 'mongo-error)))



(ert-deftest mongo-test-op-msg-allows-requested-more-to-come ()
  "The OP_MSG frame decoder should allow moreToCome when explicitly requested."
  (let* ((body '(("ok" . 1)))
         (message (mongo--make-op-msg
                   7 body mongo--op-msg-more-to-come))
         (frame (mongo--decode-op-msg-frame message t)))
    (should (= (logand (mongo--decoded-message-flags frame)
                       mongo--op-msg-more-to-come)
               mongo--op-msg-more-to-come))
    (should (equal (mongo--decoded-message-document frame) body))))



(ert-deftest mongo-test-response-to-validation ()
  "MongoDB wire replies should match the request id they answer."
  (let* ((body '(("ok" . 1)))
         (frame (mongo--decode-op-msg-frame
                 (mongo--make-op-msg 7 body nil nil nil 42))))
    (should-not (mongo--validate-response-to frame 42))
    (should-error (mongo--validate-response-to frame 41)
                  :type 'mongo-error)))



(ert-deftest mongo-test-op-compressed-zlib-decodes ()
  "The OP_COMPRESSED decoder should unwrap zlib-compressed OP_MSG replies."
  (unless (and (fboundp 'zlib-available-p)
               (zlib-available-p))
    (ert-skip "Emacs zlib support is unavailable"))
  (let ((message
         (base64-decode-string
          "LQAAAAgAAAAHAAAA3AcAAN0HAAASAAAAAnicY2AAAl4gFsjPZmAEcQAHtQD5")))
    (should (equal (mongo--decode-message message)
                   '(("ok" . 1))))))



(ert-deftest mongo-test-op-compressed-zlib-encodes-request ()
  "The OP_COMPRESSED encoder should wrap OP_MSG request bodies."
  (unless (and (fboundp 'zlib-available-p)
               (zlib-available-p))
    (ert-skip "Emacs zlib support is unavailable"))
  (let* ((body '(("find" . "users") ("$db" . "app")))
         (message (mongo--make-op-msg 9 body))
         (compressed (mongo--make-op-compressed message "zlib"))
         (reader (make-mongo--reader :data compressed :pos 0)))
    (should (= (mongo--read-int32 reader) (length compressed)))
    (should (= (mongo--read-int32 reader) 9))
    (should (= (mongo--read-int32 reader) 0))
    (should (= (mongo--read-int32 reader) mongo--op-compressed))
    (should (= (mongo--read-int32 reader) mongo--op-msg))
    (should (= (mongo--read-int32 reader) (- (length message) 16)))
    (should (= (mongo--read-byte reader) mongo--compressor-zlib))
    (should (equal (mongo--decode-message compressed) body))))



(ert-deftest mongo-test-snappy-roundtrip ()
  "Native mongo.el should encode and decode Snappy block data."
  (let ((data (make-string 300 ?a)))
    (should (equal (mongo--snappy-decompress
                    (mongo--snappy-compress data))
                   data)))
  ;; Uncompressed length 9, literal "abc", COPY_2 length 6 offset 3.
  (should (equal (mongo--snappy-decompress
                  (concat (unibyte-string 9 #x08)
                          "abc"
                          (unibyte-string #x16 #x03 #x00)))
                 "abcabcabc"))
  (should-error
   (mongo--snappy-decompress
    (concat (unibyte-string 5 #x08) "abc"))
   :type 'mongo-error))



(ert-deftest mongo-test-op-compressed-snappy-encodes-request ()
  "The OP_COMPRESSED encoder should wrap OP_MSG request bodies with snappy."
  (let* ((body '(("find" . "users") ("$db" . "app")))
         (message (mongo--make-op-msg 9 body))
         (compressed (mongo--make-op-compressed message "snappy"))
         (reader (make-mongo--reader :data compressed :pos 0)))
    (should (= (mongo--read-int32 reader) (length compressed)))
    (should (= (mongo--read-int32 reader) 9))
    (should (= (mongo--read-int32 reader) 0))
    (should (= (mongo--read-int32 reader) mongo--op-compressed))
    (should (= (mongo--read-int32 reader) mongo--op-msg))
    (should (= (mongo--read-int32 reader) (- (length message) 16)))
    (should (= (mongo--read-byte reader) mongo--compressor-snappy))
    (should (equal (mongo--decode-message compressed) body))))



(ert-deftest mongo-test-zstd-roundtrip ()
  "Native mongo.el should encode and decode zstd frame data when zstd exists."
  (unless (mongo--zstd-available-p)
    (ert-skip "zstd executable is unavailable"))
  (let ((data (concat "abc" (make-string 300 ?a))))
    (should (equal (mongo--zstd-decompress
                    (mongo--zstd-compress data))
                   data))))



(ert-deftest mongo-test-op-compressed-zstd-encodes-request ()
  "The OP_COMPRESSED encoder should wrap OP_MSG request bodies with zstd."
  (unless (mongo--zstd-available-p)
    (ert-skip "zstd executable is unavailable"))
  (let* ((body '(("find" . "users") ("$db" . "app")))
         (message (mongo--make-op-msg 9 body))
         (compressed (mongo--make-op-compressed message "zstd"))
         (reader (make-mongo--reader :data compressed :pos 0)))
    (should (= (mongo--read-int32 reader) (length compressed)))
    (should (= (mongo--read-int32 reader) 9))
    (should (= (mongo--read-int32 reader) 0))
    (should (= (mongo--read-int32 reader) mongo--op-compressed))
    (should (= (mongo--read-int32 reader) mongo--op-msg))
    (should (= (mongo--read-int32 reader) (- (length message) 16)))
    (should (= (mongo--read-byte reader) mongo--compressor-zstd))
    (should (equal (mongo--decode-message compressed) body))))



(ert-deftest mongo-test-op-compressed-preserves-response-metadata ()
  "OP_COMPRESSED frame decoding should preserve responseTo metadata."
  (let* ((body '(("ok" . 1)))
         (message (mongo--make-op-msg 9 body nil nil nil 8))
         (compressed (mongo--make-op-compressed message "noop"))
         (frame (mongo--decode-message-frame compressed)))
    (should (= (mongo--decoded-message-request-id frame) 9))
    (should (= (mongo--decoded-message-response-to frame) 8))
    (should (equal (mongo--decoded-message-document frame) body))))



(ert-deftest mongo-test-send-document-compresses-negotiated-zlib ()
  "Normal OP_MSG commands should use zlib OP_COMPRESSED after negotiation."
  (unless (and (fboundp 'zlib-available-p)
               (zlib-available-p))
    (ert-skip "Emacs zlib support is unavailable"))
  (let ((conn (make-mongo-conn :process 'proc
                               :request-id 0
                               :compressors '("zlib")))
        sent)
    (cl-letf (((symbol-function 'process-send-string)
               (lambda (_proc data)
                 (setq sent data))))
      (should (= (mongo--send-document
                  conn
                  '(("ping" . 1) ("$db" . "admin")))
                 1)))
    (let ((reader (make-mongo--reader :data sent :pos 12)))
      (should (= (mongo--read-int32 reader) mongo--op-compressed)))
    (should (equal (mongo--decode-message sent)
                   '(("ping" . 1) ("$db" . "admin"))))))



(ert-deftest mongo-test-send-document-compresses-negotiated-snappy ()
  "Normal OP_MSG commands should use snappy OP_COMPRESSED after negotiation."
  (let ((conn (make-mongo-conn :process 'proc
                               :request-id 0
                               :compressors '("snappy")))
        sent)
    (cl-letf (((symbol-function 'process-send-string)
               (lambda (_proc data)
                 (setq sent data))))
      (should (= (mongo--send-document
                  conn
                  '(("ping" . 1) ("$db" . "admin")))
                 1)))
    (let ((reader (make-mongo--reader :data sent :pos 12)))
      (should (= (mongo--read-int32 reader) mongo--op-compressed)))
    (should (equal (mongo--decode-message sent)
                   '(("ping" . 1) ("$db" . "admin"))))))



(ert-deftest mongo-test-send-document-compresses-negotiated-zstd ()
  "Normal OP_MSG commands should use zstd OP_COMPRESSED after negotiation."
  (unless (mongo--zstd-available-p)
    (ert-skip "zstd executable is unavailable"))
  (let ((conn (make-mongo-conn :process 'proc
                               :request-id 0
                               :compressors '("zstd")))
        sent)
    (cl-letf (((symbol-function 'process-send-string)
               (lambda (_proc data)
                 (setq sent data))))
      (should (= (mongo--send-document
                  conn
                  '(("ping" . 1) ("$db" . "admin")))
                 1)))
    (let ((reader (make-mongo--reader :data sent :pos 12)))
      (should (= (mongo--read-int32 reader) mongo--op-compressed)))
    (should (equal (mongo--decode-message sent)
                   '(("ping" . 1) ("$db" . "admin"))))))



(ert-deftest mongo-test-send-document-with-flags-sets-exhaust-allowed ()
  "OP_MSG send helpers should be able to set the exhaustAllowed flag."
  (let ((conn (make-mongo-conn :process 'proc
                               :request-id 0))
        sent)
    (cl-letf (((symbol-function 'process-send-string)
               (lambda (_proc data)
                 (setq sent data))))
      (should (= (mongo--send-document-with-flags
                  conn
                  '(("hello" . 1) ("$db" . "admin"))
                  nil
                  mongo--op-msg-exhaust-allowed)
                 1)))
    (let ((frame (mongo--decode-message-frame sent t)))
      (should (= (logand (mongo--decoded-message-flags frame)
                         mongo--op-msg-exhaust-allowed)
                 mongo--op-msg-exhaust-allowed))
      (should (equal (mongo--decoded-message-document frame)
                     '(("hello" . 1) ("$db" . "admin")))))))



(ert-deftest mongo-test-send-document-leaves-auth-uncompressed ()
  "Auth and handshake commands should not be wrapped in OP_COMPRESSED."
  (let ((conn (make-mongo-conn :process 'proc
                               :request-id 0
                               :compressors '("zlib")))
        sent)
    (cl-letf (((symbol-function 'process-send-string)
               (lambda (_proc data)
                 (setq sent data))))
      (mongo--send-document
       conn
       '(("saslStart" . 1)
         ("mechanism" . "SCRAM-SHA-256")
         ("$db" . "admin"))))
    (let ((reader (make-mongo--reader :data sent :pos 12)))
      (should (= (mongo--read-int32 reader) mongo--op-msg)))))



(ert-deftest mongo-test-send-document-validates-op-msg-size ()
  "Low-level OP_MSG sends should enforce size limits before writing."
  (let* ((document '(("hello" . 1) ("$db" . "admin")))
         (message-size (length (mongo--make-op-msg 1 document)))
         (conn (make-mongo-conn :process 'proc
                                :request-id 0
                                :max-bson-object-size 1000
                                :max-message-size-bytes
                                (1- message-size))))
    (cl-letf (((symbol-function 'process-send-string)
               (lambda (&rest _args)
                 (ert-fail "oversized OP_MSG should not be sent"))))
      (should-error
       (mongo--send-document conn document)
       :type 'mongo-error))
    (should (= (mongo-conn-request-id conn) 0))))



(ert-deftest mongo-test-recv-message-uses-connection-socket-timeout ()
  "OP_MSG receive should use connection socket timeout by default."
  (let* ((buffer (generate-new-buffer " *mongo-test*"))
         (message (mongo--make-op-msg 7 '(("ok" . 1))))
         (conn (make-mongo-conn :buffer buffer
                                :process 'proc
                                :socket-timeout 1.5))
         timeouts)
    (unwind-protect
        (progn
          (with-current-buffer buffer
            (set-buffer-multibyte nil)
            (insert message))
          (cl-letf (((symbol-function 'mongo--wait-for-bytes)
                     (lambda (_conn _count timeout)
                       (push timeout timeouts))))
            (should (equal (mongo--recv-message conn)
                           '(("ok" . 1)))))
          (should (equal (nreverse timeouts) '(1.5 1.5))))
      (kill-buffer buffer))))



(ert-deftest mongo-test-recv-message-validates-response-to ()
  "OP_MSG receive should reject replies for a different request id."
  (let* ((buffer (generate-new-buffer " *mongo-test*"))
         (message (mongo--make-op-msg 7 '(("ok" . 1)) nil nil nil 41))
         (conn (make-mongo-conn :buffer buffer
                                :process 'proc
                                :socket-timeout 1.5)))
    (unwind-protect
        (progn
          (with-current-buffer buffer
            (set-buffer-multibyte nil)
            (insert message))
          (cl-letf (((symbol-function 'mongo--wait-for-bytes)
                     (lambda (&rest _args) nil)))
            (should-error (mongo--recv-message conn nil 42)
                          :type 'mongo-error)))
      (kill-buffer buffer))))



(ert-deftest mongo-test-recv-handshake-validates-response-to ()
  "Legacy handshake receive should reject replies for a different request id."
  (let* ((buffer (generate-new-buffer " *mongo-test*"))
         (document '(("ok" . 1)))
         (body (concat (mongo--pack-int32 0)
                       (mongo--pack-int64 0)
                       (mongo--pack-int32 0)
                       (mongo--pack-int32 1)
                       (mongo--encode-document document)))
         (message (concat (mongo--pack-int32 (+ 16 (length body)))
                          (mongo--pack-int32 7)
                          (mongo--pack-int32 41)
                          (mongo--pack-int32 mongo--op-reply)
                          body))
         (conn (make-mongo-conn :buffer buffer
                                :process 'proc
                                :socket-timeout 1.5)))
    (unwind-protect
        (progn
          (with-current-buffer buffer
            (set-buffer-multibyte nil)
            (insert message))
          (cl-letf (((symbol-function 'mongo--wait-for-bytes)
                     (lambda (&rest _args) nil)))
            (should-error (mongo--recv-handshake-message conn nil 42)
                          :type 'mongo-error)))
      (kill-buffer buffer))))



(ert-deftest mongo-test-handshake-command-includes-client-metadata ()
  "The MongoDB initial handshake should include driver and OS metadata."
  (let* ((command (mongo--initial-handshake-command))
         (client (cdr (assoc "client" command)))
         (driver (cdr (assoc "driver" client)))
         (os (cdr (assoc "os" client))))
    (should (equal (cdr (assoc "isMaster" command)) 1))
    (should (eq (cdr (assoc "helloOk" command)) t))
    (should-not (assoc "hello" command))
    (should (equal (cdr (assoc "name" driver)) "mongo.el"))
    (should (stringp (cdr (assoc "version" driver))))
    (should (stringp (cdr (assoc "type" os))))
    (should-not (assoc "saslSupportedMechs" command))
    (should-not (assoc "compression" command))
    (should-not (assoc "application" client))))



(ert-deftest mongo-test-handshake-command-includes-app-name ()
  "The MongoDB initial handshake should include configured appName metadata."
  (let* ((command (mongo--initial-handshake-command
                   nil nil nil nil nil "Clutch"))
         (client (cdr (assoc "client" command)))
         (application (cdr (assoc "application" client))))
    (should (equal (cdr (assoc "name" application)) "Clutch"))))



(ert-deftest mongo-test-handshake-app-name-validates-byte-limit ()
  "MongoDB appName metadata should enforce the 128 UTF-8 byte limit."
  (should (equal (mongo--params-app-name
                  '(:app-name "Clutch"))
                 "Clutch"))
  (should (equal (mongo--params-app-name
                  '(:url "mongodb://127.0.0.1/app?appName=Clutch%20Native"))
                 "Clutch Native"))
  (should-error (mongo--params-app-name
                 `(:app-name ,(make-string 129 ?a)))
                :type 'mongo-error))



(ert-deftest mongo-test-handshake-command-uses-hello-for-stable-api ()
  "Stable API handshakes should use modern hello instead of legacy hello."
  (let* ((api (mongo--params-server-api '(:server-api "1")))
         (command (mongo--initial-handshake-command nil nil api)))
    (should (equal (cdr (assoc "hello" command)) 1))
    (should-not (assoc "isMaster" command))
    (should-not (assoc "helloOk" command))))



(ert-deftest mongo-test-handshake-command-uses-hello-for-load-balanced ()
  "Load-balanced handshakes should use modern hello with loadBalanced=true."
  (let ((command (mongo--initial-handshake-command nil nil nil t)))
    (should (equal (cdr (assoc "hello" command)) 1))
    (should (eq (cdr (assoc "loadBalanced" command)) t))
    (should-not (assoc "isMaster" command))
    (should-not (assoc "helloOk" command))))



(ert-deftest mongo-test-handshake-command-negotiates-compression ()
  "The MongoDB initial handshake should request wire compression when configured."
  (let ((command (mongo--initial-handshake-command nil '("zlib"))))
    (should (equal (cdr (assoc "compression" command))
                   ["zlib"]))))



(ert-deftest mongo-test-handshake-command-negotiates-scram ()
  "The MongoDB initial handshake should request supported mechanisms for auth."
  (let* ((credential (make-mongo--credential
                      :username "reporter"
                      :password "secret"
                      :source "admin"))
         (command (mongo--initial-handshake-command credential)))
    (should (equal (cdr (assoc "saslSupportedMechs" command))
                   "admin.reporter"))))



(ert-deftest mongo-test-handshake-command-speculative-scram ()
  "The MongoDB initial handshake should include speculative SCRAM auth."
  (let* ((credential (make-mongo--credential
                      :username "user"
                      :password "pencil"
                      :source "admin"))
         command speculative)
    (cl-letf (((symbol-function 'mongo--scram-client-nonce)
               (lambda () "clientnonce")))
      (let ((state (mongo--speculative-auth-state credential)))
        (setq command
              (mongo--initial-handshake-command
               credential nil nil nil state))))
    (setq speculative (cdr (assoc "speculativeAuthenticate" command)))
    (should (equal (cdr (assoc "saslSupportedMechs" command))
                   "admin.user"))
    (should (equal (cdr (assoc "mechanism" speculative))
                   "SCRAM-SHA-256"))
    (should (equal (cdr (assoc "db" speculative)) "admin"))
    (should (equal (cdr (assoc "options" speculative))
                   '(("skipEmptyExchange" . t))))
    (should (equal
             (mongo--scram-payload-string
	             (cdr (assoc "payload" speculative)))
	            "n,,n=user,r=clientnonce"))))



(ert-deftest mongo-test-handshake-command-speculative-default-auth ()
  "authMechanism=DEFAULT should use SCRAM-SHA-256 for speculative auth."
  (let* ((credential (make-mongo--credential
                      :username "user"
                      :password "pencil"
                      :source "admin"
                      :mechanism "DEFAULT"))
         state command speculative)
    (cl-letf (((symbol-function 'mongo--scram-client-nonce)
               (lambda () "clientnonce")))
      (setq state (mongo--speculative-auth-state credential)
            command (mongo--initial-handshake-command
                     credential nil nil nil state)))
    (setq speculative (cdr (assoc "speculativeAuthenticate" command)))
    (should (equal (plist-get state :mechanism) "SCRAM-SHA-256"))
    (should (equal (cdr (assoc "mechanism" speculative))
                   "SCRAM-SHA-256"))))



(ert-deftest mongo-test-command-with-db-adds-stable-api-fields ()
  "MongoDB Stable API fields should be added to every command."
  (let ((api (mongo--params-server-api
              '(:server-api "1"
                :api-strict nil
                :api-deprecation-errors t))))
    (should (equal (mongo--command-with-db
                    '(("ping" . 1))
                    "admin"
                    api)
                   '(("ping" . 1)
                     ("$db" . "admin")
                     ("apiVersion" . "1")
                     ("apiStrict" . :false)
                     ("apiDeprecationErrors" . t))))))



(ert-deftest mongo-test-command-with-db-adds-session-id ()
  "MongoDB commands should include lsid when logical sessions are active."
  (let ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop")))))
    (should (equal (mongo--command-with-db
                    '(("ping" . 1))
                    "admin"
                    nil
                    session-id)
                   `(("ping" . 1)
                     ("$db" . "admin")
                     ("lsid" . ,session-id))))
    (should (equal (mongo--command-with-db
                    '(("endSessions" . []))
                    "admin"
                    nil
                    session-id)
                   '(("endSessions" . [])
                     ("$db" . "admin"))))))



(ert-deftest mongo-test-command-with-db-adds-read-preference ()
  "MongoDB read commands should include OP_MSG $readPreference when configured."
  (let ((read-preference
         (mongo--params-read-preference
          '(:read-preference secondary-preferred
            :max-staleness-seconds 120
            :read-preference-tags ((("dc" . "ny")))))))
    (let ((read-command (mongo--command-with-db
                         '(("find" . "users"))
                         "app"
                         nil
                         nil
                         read-preference))
          (write-command (mongo--command-with-db
                          '(("insert" . "users")
                            ("documents" . []))
                          "app"
                          nil
                          nil
                          read-preference)))
      (should (equal read-command
                     '(("find" . "users")
                       ("$db" . "app")
                       ("$readPreference" .
                        (("mode" . "secondaryPreferred")
                         ("tags" . [(("dc" . "ny"))])
                         ("maxStalenessSeconds" . 120))))))
      (should (equal write-command
                     '(("insert" . "users")
                       ("documents" . [])
                       ("$db" . "app")))))))



(ert-deftest mongo-test-command-adds-single-secondary-read-preference ()
  "Single topology reads from a replica-set secondary should use primaryPreferred."
  (let* ((conn (make-mongo-conn
                :host "seed-a"
                :port 27018
                :database "app"
                :params '(:url
                          "mongodb://seed-a:27018/app?directConnection=true")
                :process 'proc
                :closed nil))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("secondary" . t)))
         captured)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (push document captured)
                 42))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-command conn "app" '(("find" . "users")))
      (should (equal (cdr (assoc "$readPreference" (car captured)))
                     '(("mode" . "primaryPreferred"))))
      (setf (mongo-conn-read-preference conn)
            (mongo--params-read-preference
             '(:read-preference secondary)))
      (mongo-command conn "app" '(("find" . "users")))
      (should (equal (cdr (assoc "$readPreference" (car captured)))
                     '(("mode" . "secondary")))))))



(ert-deftest mongo-test-command-with-db-adds-read-write-concern ()
  "MongoDB commands should include readConcern/writeConcern by operation kind."
  (let ((read-concern
         (mongo--params-read-concern '(:read-concern-level majority)))
        (write-concern
         (mongo--params-write-concern
          '(:w majority
            :w-timeout-ms 5000
            :journal t))))
    (should (equal (mongo--command-with-db
                    '(("find" . "users"))
                    "app"
                    nil
                    nil
                    nil
                    read-concern
                    write-concern)
                   '(("find" . "users")
                     ("$db" . "app")
                     ("readConcern" . (("level" . "majority"))))))
    (should (equal (mongo--command-with-db
                    '(("insert" . "users")
                      ("documents" . []))
                    "app"
                    nil
                    nil
                    nil
                    read-concern
                    write-concern)
                   '(("insert" . "users")
                     ("documents" . [])
                     ("$db" . "app")
                     ("writeConcern" .
                      (("w" . "majority")
                       ("wtimeout" . 5000)
                       ("j" . t)))))))
  (let ((read-concern
         (mongo--params-read-concern '(:read-concern-level majority)))
        (write-concern
         (mongo--params-write-concern '(:w 2))))
    (should (equal (mongo--command-with-db
                    '(("find" . "users")
                      ("readConcern" . (("level" . "local"))))
                    "app"
                    nil
                    nil
                    nil
                    read-concern
                    write-concern)
                   '(("find" . "users")
                     ("readConcern" . (("level" . "local")))
                     ("$db" . "app"))))))



(ert-deftest mongo-test-command-with-db-adds-transaction-fields ()
  "MongoDB transaction commands should use transaction metadata only."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (read-preference
          (mongo--params-read-preference
           '(:read-preference secondary)))
         (read-concern
          (mongo--params-read-concern '(:read-concern-level majority)))
         (write-concern
          (mongo--params-write-concern '(:w majority)))
         (transaction-read-concern
          (mongo--params-read-concern '(:read-concern-level snapshot)))
         (txn-number (mongo-int64 7)))
    (should (equal (mongo--command-with-db
                    '(("find" . "users"))
                    "app"
                    nil
                    session-id
                    read-preference
                    read-concern
                    write-concern
                    txn-number
                    'starting
                    transaction-read-concern)
                   `(("find" . "users")
                     ("$db" . "app")
                     ("lsid" . ,session-id)
                     ("txnNumber" . ,txn-number)
                     ("autocommit" . :false)
                     ("startTransaction" . t)
                     ("readConcern" . (("level" . "snapshot"))))))
    (should (equal (mongo--command-with-db
                    '(("insert" . "users"))
                    "app"
                    nil
                    session-id
                    nil
                    read-concern
                    write-concern
                    txn-number
                    'in-progress
                    transaction-read-concern)
                   `(("insert" . "users")
                     ("$db" . "app")
                     ("lsid" . ,session-id)
                     ("txnNumber" . ,txn-number)
                     ("autocommit" . :false))))))



(ert-deftest mongo-test-command-with-db-skips-session-for-hello ()
  "MongoDB hello commands should not carry an implicit lsid."
  (let ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop")))))
    (should (equal (mongo--command-with-db
                    '(("hello" . 1))
                    "admin"
                    nil
                    session-id)
                   '(("hello" . 1)
                     ("$db" . "admin"))))
    (should (equal (mongo--command-with-db
                    '(("isMaster" . 1))
                    "admin"
                    nil
                    session-id)
                   '(("isMaster" . 1)
                     ("$db" . "admin"))))))



(defun mongo-test--cluster-time (seconds increment)
  "Return a decoded MongoDB $clusterTime fixture."
  `(("clusterTime" .
     (("$timestamp" .
       (("t" . ,seconds)
        ("i" . ,increment)))))
    ("signature" .
     (("hash" .
       (("$binary" .
         (("subType" . "00")
          ("bytes" . "YWJj")))))
      ("keyId" . 9)))))



(ert-deftest mongo-test-command-with-db-adds-cluster-time ()
  "MongoDB non-SDAM commands should gossip the highest seen $clusterTime."
  (let* ((cluster-time (mongo-test--cluster-time 1700000000 7))
         (command (mongo--command-with-db
                   '(("ping" . 1))
                   "admin"
                   nil nil nil nil nil nil nil nil
                   cluster-time))
         (sent-cluster-time (cdr (assoc "$clusterTime" command)))
         (sent-pairs (mongo-document-pairs sent-cluster-time))
         (sent-timestamp (cdr (assoc "clusterTime" sent-pairs)))
         (sent-signature (cdr (assoc "signature" sent-pairs)))
         (sent-hash (cdr (assoc "hash"
                                (mongo-document-pairs sent-signature)))))
    (should (mongo-document-p sent-cluster-time))
    (should (mongo-timestamp-p sent-timestamp))
    (should (= (mongo-timestamp-seconds sent-timestamp) 1700000000))
    (should (= (mongo-timestamp-increment sent-timestamp) 7))
    (should (mongo-document-p sent-signature))
    (should (mongo-binary-p sent-hash))
    (should (= (mongo-binary-subtype sent-hash) 0))
    (should (equal (mongo-binary-data sent-hash) "abc"))
    (should (equal (mongo--command-with-db
                    '(("hello" . 1))
                    "admin"
                    nil nil nil nil nil nil nil nil
                    cluster-time)
                   '(("hello" . 1)
                     ("$db" . "admin"))))))



(ert-deftest mongo-test-advances-cluster-time-from-response ()
  "MongoDB responses should advance, but not regress, tracked cluster time."
  (let* ((conn (make-mongo-conn :max-wire-version 17))
         (low (mongo-test--cluster-time 100 9))
         (same-time-higher-increment
          (mongo-test--cluster-time 100 10))
         (high (mongo-test--cluster-time 101 0)))
    (mongo--advance-cluster-time-from-response
     conn
     '(("find" . "users"))
     `(("ok" . 1)
       ("$clusterTime" . ,low)))
    (should (equal (mongo-conn-cluster-time conn) low))
    (should (equal (mongo-conn-session-cluster-time conn) low))
    (mongo--advance-cluster-time-from-response
     conn
     '(("find" . "users"))
     `(("ok" . 1)
       ("$clusterTime" . ,same-time-higher-increment)))
    (should (equal (mongo-conn-cluster-time conn)
                   same-time-higher-increment))
    (mongo--advance-cluster-time-from-response
     conn
     '(("find" . "users"))
     `(("ok" . 1)
       ("$clusterTime" . ,high)))
    (should (equal (mongo-conn-cluster-time conn) high))
    (mongo--advance-cluster-time-from-response
     conn
     '(("find" . "users"))
     `(("ok" . 1)
       ("$clusterTime" . ,low)))
    (should (equal (mongo-conn-cluster-time conn) high))
    (mongo--advance-cluster-time-from-response
     conn
     '(("hello" . 1))
     `(("ok" . 1)
       ("$clusterTime" . ,(mongo-test--cluster-time 102 0))))
    (should (equal (mongo-conn-cluster-time conn) high))))



(ert-deftest mongo-test-command-gossips-cluster-time ()
  "MongoDB command execution should include tracked $clusterTime on the wire."
  (let* ((cluster-time (mongo-test--cluster-time 1700000000 7))
         (conn (make-mongo-conn :closed nil
                                :max-wire-version 17
                                :cluster-time cluster-time))
         captured)
    (cl-letf (((symbol-function 'mongo-live-p)
               (lambda (_conn) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-command conn "admin" '(("ping" . 1))))
    (should (assoc "$clusterTime" captured))
    (let* ((sent-cluster-time (cdr (assoc "$clusterTime" captured)))
           (sent-timestamp
            (cdr (assoc "clusterTime"
                        (mongo-document-pairs sent-cluster-time)))))
      (should (mongo-timestamp-p sent-timestamp))
      (should (= (mongo-timestamp-seconds sent-timestamp) 1700000000))
      (should (= (mongo-timestamp-increment sent-timestamp) 7)))))



(ert-deftest mongo-test-command-receives-matching-response-id ()
  "MongoDB command execution should receive the reply for its request id."
  (let ((conn (make-mongo-conn :process 'proc
                               :closed nil
                               :database "app"
                               :max-wire-version 17))
        expected-response-to)
    (cl-letf (((symbol-function 'mongo-live-p)
               (lambda (_conn) t))
              ((symbol-function 'mongo--ensure-writable-server)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--ensure-readable-server)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 73))
              ((symbol-function 'mongo--recv-message)
               (lambda (_conn _timeout response-to &optional _allow-more)
                 (setq expected-response-to response-to)
                 '(("ok" . 1)))))
      (should (equal (mongo-command conn "app" '(("ping" . 1)))
	                     '(("ok" . 1)))))
    (should (= expected-response-to 73))))



(ert-deftest mongo-test-command-monitoring-events-include-service-id ()
  "Command monitoring events should include load-balanced serviceId."
  (let* ((service-id '(("$oid" . "64f0000000000000000000aa")))
         (conn (make-mongo-conn :process 'proc
                                :closed nil
                                :host "lb.example.test"
                                :port 27017
                                :database "app"
                                :request-id 0
                                :max-wire-version 17
                                :load-balanced t
                                :service-id service-id
                                :last-hello '(("connectionId" . 42))))
         events)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'process-send-string)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (let ((mongo-command-event-hook
             (list (lambda (event)
                     (push event events)))))
        (should (equal (mongo-command conn "app" '(("ping" . 1)))
                       '(("ok" . 1))))))
    (let ((ordered (nreverse events)))
      (should (equal (mapcar (lambda (event)
                               (alist-get 'type event))
                             ordered)
                     '(command-started command-succeeded)))
      (dolist (event ordered)
        (should (equal (alist-get 'command-name event) "ping"))
        (should (equal (alist-get 'database-name event) "app"))
        (should (= (alist-get 'request-id event) 1))
        (should-not (alist-get 'operation-id event))
        (should (equal (alist-get 'connection-id event)
                       "lb.example.test:27017"))
        (should (= (alist-get 'server-connection-id event) 42))
        (should (equal (alist-get 'service-id event) service-id)))
      (should (assoc "$db" (alist-get 'command (car ordered))))
      (should (numberp (alist-get 'duration-ms (cadr ordered))))
      (should (equal (alist-get 'reply (cadr ordered))
                     '(("ok" . 1)))))))



(ert-deftest mongo-test-command-monitoring-emits-failed-for-server-error ()
  "Command monitoring should treat ok:0 replies as command-failed."
  (let ((conn (make-mongo-conn :process 'proc
                               :closed nil
                               :host "db.example.test"
                               :port 27017
                               :database "app"
                               :request-id 0
                               :max-wire-version 17))
        events)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'process-send-string)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 0)
                   ("errmsg" . "bad command")
                   ("code" . 123)))))
      (let ((mongo-command-event-hook
             (list (lambda (event)
                     (push event events)))))
        (should-error
         (mongo-command conn "app" '(("ping" . 1)))
         :type 'mongo-error)))
    (let ((ordered (nreverse events)))
      (should (equal (mapcar (lambda (event)
                               (alist-get 'type event))
                             ordered)
                     '(command-started command-failed)))
      (should (= (alist-get 'request-id (car ordered))
                 (alist-get 'request-id (cadr ordered))))
      (should (equal (alist-get 'failure (cadr ordered))
                     '(("ok" . 0)
                       ("errmsg" . "bad command")
                       ("code" . 123)))))))



(ert-deftest mongo-test-command-monitoring-redacts-sensitive-commands ()
  "Command monitoring should redact sensitive command documents and replies."
  (let ((conn (make-mongo-conn :process 'proc
                               :closed nil
                               :host "db.example.test"
                               :port 27017
                               :database "admin"
                               :request-id 0
                               :max-wire-version 17))
        events)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'process-send-string)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("payload" . "secret")))))
      (let ((mongo-command-event-hook
             (list (lambda (event)
                     (push event events)))))
        (mongo-command
         conn "admin"
         '(("saslStart" . 1)
           ("mechanism" . "SCRAM-SHA-256")
           ("payload" . "secret")))))
    (let ((ordered (nreverse events)))
      (should (equal (mapcar (lambda (event)
                               (alist-get 'type event))
                             ordered)
                     '(command-started command-succeeded)))
      (should-not (alist-get 'command (car ordered)))
      (should-not (alist-get 'reply (cadr ordered))))))



(ert-deftest mongo-test-command-monitoring-started-merges-sequences ()
  "Command-started events should expose OP_MSG sequences as array fields."
  (let ((conn (make-mongo-conn :process 'proc
                               :closed nil
                               :host "db.example.test"
                               :port 27017
                               :database "app"
                               :request-id 0
                               :max-wire-version 17))
        events
        (docs [(("name" . "Ann"))]))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'process-send-string)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--ensure-writable-server)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (let ((mongo-command-event-hook
             (list (lambda (event)
                     (push event events)))))
        (mongo-command
         conn "app"
         '(("insert" . "users"))
         nil
         `(("documents" . ,docs)))))
    (let ((command (alist-get 'command (car (nreverse events)))))
      (should (equal (cdr (assoc "documents" command)) docs)))))



(ert-deftest mongo-test-command-monitoring-bulk-write-operation-id ()
  "Split bulkWrite command events should share one operation-id."
  (let ((conn (make-mongo-conn :process 'proc
                               :closed nil
                               :host "db.example.test"
                               :port 27017
                               :database "admin"
                               :request-id 0
                               :max-wire-version 17
                               :max-write-batch-size 2))
        (mongo--next-command-operation-id 0)
        events
        responses)
    (setq responses
          (list
           '(("ok" . 1)
             ("nInserted" . 2)
             ("cursor" .
              (("id" . 0)
               ("ns" . "admin.$cmd.bulkWrite")
               ("firstBatch" . [(("ok" . 1) ("idx" . 0))
                                (("ok" . 1) ("idx" . 1))]))))
           '(("ok" . 1)
             ("nInserted" . 1)
             ("cursor" .
              (("id" . 0)
               ("ns" . "admin.$cmd.bulkWrite")
               ("firstBatch" . [(("ok" . 1) ("idx" . 0))]))))))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'process-send-string)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--ensure-writable-server)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (pop responses))))
      (let ((mongo-command-event-hook
             (list (lambda (event)
                     (push event events)))))
        (should
         (equal
          (mongo-bulk-write
           conn
           '((("insert" . "app.users")
              ("document" . (("name" . "Ann"))))
             (("insert" . "app.users")
              ("document" . (("name" . "Bob"))))
             (("insert" . "app.users")
              ("document" . (("name" . "Cal")))))
           '(("ordered" . :false)
             ("verboseResults" . t)))
          '(("ok" . 1)
            ("cursor" .
             (("id" . 0)
              ("ns" . "admin.$cmd.bulkWrite")
              ("firstBatch" . [(("ok" . 1) ("idx" . 0))])))
            ("nInserted" . 3)
            ("results" . [(("ok" . 1) ("idx" . 0))
                          (("ok" . 1) ("idx" . 1))
                          (("ok" . 1) ("idx" . 2))]))))))
    (let* ((ordered (nreverse events))
           (operation-ids (mapcar (lambda (event)
                                    (alist-get 'operation-id event))
                                  ordered)))
      (should (equal (mapcar (lambda (event)
                               (alist-get 'type event))
                             ordered)
                     '(command-started command-succeeded
                       command-started command-succeeded)))
      (should (equal operation-ids '(1 1 1 1)))
      (should (equal (mapcar (lambda (event)
                               (alist-get 'request-id event))
                             ordered)
                     '(1 1 2 2)))
      (should (equal (mapcar (lambda (event)
                               (alist-get 'command-name event))
                             ordered)
                     '("bulkWrite" "bulkWrite" "bulkWrite" "bulkWrite"))))))



(ert-deftest mongo-test-monitor-heartbeat-suppresses-command-events ()
  "Internal monitor heartbeats should not publish command monitoring events."
  (let ((conn (make-mongo-conn :process 'proc
                               :closed nil
                               :host "db.example.test"
                               :port 27017
                               :database "admin"
                               :request-id 0
                               :max-wire-version 17
                               :server-monitoring-mode 'poll))
        events)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'process-send-string)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("maxWireVersion" . 17)))))
      (let ((mongo-command-event-hook
             (list (lambda (event)
                     (push event events)))))
        (should (equal (mongo-monitor-once conn 250 3)
                       '(("ok" . 1)
                         ("maxWireVersion" . 17))))))
    (should-not events)))



(ert-deftest mongo-test-command-uses-operation-timeout ()
  "MongoDB commands should default to timeoutMS when no call timeout is given."
  (let ((conn (make-mongo-conn :operation-timeout 2.5
                               :socket-timeout 9))
        captured-timeout)
    (cl-letf (((symbol-function 'mongo--send-command-and-receive)
               (lambda (_conn _database _command timeout _sequences
                              _txn-number)
                 (setq captured-timeout timeout)
                 '(("ok" . 1)))))
      (should (equal (mongo-command conn "app" '(("ping" . 1)))
                     '(("ok" . 1)))))
    (should (= captured-timeout 2.5))))



(ert-deftest mongo-test-command-timeout-overrides-operation-timeout ()
  "Per-call MongoDB command timeouts should override timeoutMS."
  (let ((conn (make-mongo-conn :operation-timeout 2.5
                               :socket-timeout 9))
        captured-timeout)
    (cl-letf (((symbol-function 'mongo--send-command-and-receive)
               (lambda (_conn _database _command timeout _sequences
                              _txn-number)
                 (setq captured-timeout timeout)
                 '(("ok" . 1)))))
      (should (equal (mongo-command conn "app" '(("ping" . 1)) 1.25)
                     '(("ok" . 1)))))
    (should (= captured-timeout 1.25))))



(ert-deftest mongo-test-command-exhaust-consumes-more-to-come ()
  "MongoDB exhaust commands should drain frames until moreToCome is clear."
  (let ((conn (make-mongo-conn :process 'proc
                               :closed nil
                               :database "app"
                               :max-wire-version 17))
        (frames
         (list
          (make-mongo--decoded-message
           :request-id 90
           :response-to 73
           :opcode mongo--op-msg
           :flags mongo--op-msg-more-to-come
           :document '(("ok" . 1) ("n" . 1)))
          (make-mongo--decoded-message
           :request-id 91
           :response-to 73
           :opcode mongo--op-msg
           :flags 0
           :document '(("ok" . 1) ("n" . 2)))))
        captured
        recv-args)
    (cl-letf (((symbol-function 'mongo-live-p)
               (lambda (_conn) t))
              ((symbol-function 'mongo--ensure-writable-server)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--ensure-readable-server)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--send-document-with-flags)
               (lambda (_conn document sequences flags)
                 (setq captured
                       (list :document document
                             :sequences sequences
                             :flags flags))
                 73))
              ((symbol-function 'mongo--recv-message-frame)
               (lambda (_conn timeout response-to allow-more-to-come)
                 (push (list timeout response-to allow-more-to-come)
                       recv-args)
                 (pop frames))))
      (should (equal
               (mongo-command-exhaust
                conn "app" '(("hello" . 1)) 2)
               '((("ok" . 1) ("n" . 1))
                 (("ok" . 1) ("n" . 2))))))
    (should-not frames)
    (should (equal (plist-get captured :document)
                   '(("hello" . 1)
                     ("$db" . "app"))))
    (should-not (plist-get captured :sequences))
    (should (= (plist-get captured :flags)
               mongo--op-msg-exhaust-allowed))
    (should (equal (nreverse recv-args)
                   '((2 73 t)
                     (2 73 t))))))



(ert-deftest mongo-test-command-exhaust-uses-operation-timeout ()
  "MongoDB exhaust commands should default to timeoutMS."
  (let ((conn (make-mongo-conn :operation-timeout 2.5
                               :socket-timeout 9))
        captured-timeout)
    (cl-letf (((symbol-function 'mongo--send-command-exhaust-and-receive)
               (lambda (_conn _database _command timeout _sequences)
                 (setq captured-timeout timeout)
                 (list '(("ok" . 1))))))
      (should (equal (mongo-command-exhaust conn "app" '(("hello" . 1)))
                     (list '(("ok" . 1))))))
    (should (= captured-timeout 2.5))))



(ert-deftest mongo-test-command-exhaust-requires-op-msg-wire-version ()
  "MongoDB exhaust commands should reject pre-OP_MSG servers."
  (let ((conn (make-mongo-conn :process 'proc
                               :closed nil
                               :database "app"
                               :max-wire-version 5)))
    (cl-letf (((symbol-function 'mongo-live-p)
               (lambda (_conn) t)))
      (should-error
       (mongo-command-exhaust conn "app" '(("hello" . 1)))
       :type 'mongo-error))))



(ert-deftest mongo-test-session-cluster-time-can-advance-locally ()
  "MongoDB session cluster time can advance without changing client time."
  (let* ((client-time (mongo-test--cluster-time 100 0))
         (session-time (mongo-test--cluster-time 101 0))
         (conn (make-mongo-conn :max-wire-version 17
                                :cluster-time client-time)))
    (mongo-advance-cluster-time conn session-time)
    (should (equal (mongo-conn-cluster-time conn) client-time))
    (should (equal (mongo-conn-session-cluster-time conn) session-time))
    (should (equal (mongo--cluster-time-to-send conn) session-time))
    (setf (mongo-conn-max-wire-version conn) 5)
    (should-not (mongo--cluster-time-to-send conn))))



(ert-deftest mongo-test-apply-hello-limits ()
  "MongoDB hello size and write batch limits should be cached on connections."
  (let ((conn (make-mongo-conn)))
    (mongo--apply-hello-limits
     conn
     '(("ok" . 1)))
    (should (= (mongo-conn-max-bson-object-size conn)
               mongo--default-max-bson-object-size))
    (should (= (mongo-conn-max-message-size-bytes conn)
               mongo--default-max-message-size-bytes))
    (should (= (mongo-conn-max-write-batch-size conn)
               mongo--default-max-write-batch-size))
    (mongo--apply-hello-limits
     conn
     '(("ok" . 1)
       ("maxBsonObjectSize" . 1024)
       ("maxMessageSizeBytes" . 8192)
       ("maxWriteBatchSize" . 50)))
    (should (= (mongo-conn-max-bson-object-size conn) 1024))
    (should (= (mongo-conn-max-message-size-bytes conn) 8192))
    (should (= (mongo-conn-max-write-batch-size conn) 50))
    (should-error
     (mongo--apply-hello-limits
      conn
      '(("ok" . 1)
        ("maxWriteBatchSize" . 0)))
     :type 'mongo-error)))



(ert-deftest mongo-test-session-id-is-uuid-v4-binary ()
  "Locally generated MongoDB session IDs should use UUID subtype 4."
  (let* ((session-id (mongo--make-session-id))
         (id (cdr (assoc "id" session-id)))
         (bytes (mongo-binary-data id)))
    (should (= (mongo-binary-subtype id) 4))
    (should (= (length bytes) 16))
    (should (= (logand (aref bytes 6) #xf0) #x40))
    (should (= (logand (aref bytes 8) #xc0) #x80))))



(ert-deftest mongo-test-initialize-session-from-hello ()
  "MongoDB should enable implicit sessions when hello reports support."
  (let ((conn (make-mongo-conn :closed nil)))
    (mongo--initialize-session
     conn
     '(("ok" . 1)
       ("logicalSessionTimeoutMinutes" . 30)))
    (should (mongo-conn-session-id conn))
    (let ((id (cdr (assoc "id" (mongo-conn-session-id conn)))))
      (should (mongo-binary-p id))
      (should (= (mongo-binary-subtype id) 4)))))


(ert-deftest mongo-test-initialize-session-for-load-balanced ()
  "Load-balanced connections should support sessions without timeout metadata."
  (let ((conn (make-mongo-conn :closed nil
                               :load-balanced t)))
    (mongo--initialize-session
     conn
     '(("ok" . 1)
       ("serviceId" . (("$oid" . "64f0000000000000000000aa")))))
    (should (mongo-conn-session-id conn))
    (let ((id (cdr (assoc "id" (mongo-conn-session-id conn)))))
      (should (mongo-binary-p id))
      (should (= (mongo-binary-subtype id) 4)))))



(ert-deftest mongo-test-disconnect-ends-session ()
  "MongoDB disconnect should end an open logical session."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :session-id session-id
                                :closed nil
                                :monitor-timer 'fake-monitor-timer))
         captured-command
         cancelled)
    (cl-letf (((symbol-function 'mongo-live-p)
               (lambda (_conn) t))
              ((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (should (equal database "admin"))
                 (setq captured-command command)
                 '(("ok" . 1))))
              ((symbol-function 'cancel-timer)
               (lambda (timer)
                 (push timer cancelled)
                 '(("ok" . 1)))))
      (mongo-disconnect conn))
    (should (equal captured-command
                   `(("endSessions" . [,session-id]))))
    (should (equal cancelled '(fake-monitor-timer)))
    (should-not (mongo-conn-monitor-timer conn))
    (should-not (mongo-conn-session-id conn))
    (should (mongo-conn-closed conn))))



(ert-deftest mongo-test-disconnect-aborts-active-transaction ()
  "MongoDB disconnect should abort an active transaction before ending a session."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :session-id session-id
                                :transaction-state 'in-progress
                                :closed nil))
         commands
         aborted)
    (cl-letf (((symbol-function 'mongo-live-p)
               (lambda (_conn) t))
              ((symbol-function 'mongo-abort-transaction)
               (lambda (abort-conn)
                 (should (eq abort-conn conn))
                 (setq aborted t)
                 (mongo--clear-transaction abort-conn)
                 '(("ok" . 1))))
              ((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (push (list database command) commands)
                 '(("ok" . 1)))))
      (mongo-disconnect conn))
    (should aborted)
    (should (equal (nreverse commands)
                   `(("admin" (("endSessions" . [,session-id]))))))
    (should-not (mongo-conn-transaction-state conn))
    (should-not (mongo-conn-session-id conn))
    (should (mongo-conn-closed conn))))



(ert-deftest mongo-test-cursor-results-fetches-next-batches ()
  "MongoDB cursor helpers should drain getMore batches."
  (let (commands)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (push (list database command) commands)
                 (cond
                  ((assoc "getMore" command)
                   (should (equal database "app"))
                   (should (= (cdr (assoc "getMore" command)) 42))
                   (should (equal (cdr (assoc "collection" command))
                                  "users"))
                   '(("cursor" . (("id" . 0)
                                   ("nextBatch" . ((("n" . 2))))))))
                  (t
                   (ert-fail
                    (format "unexpected command: %S" command)))))))
      (should
       (equal
        (mongo--cursor-results
         'conn "app" "users"
         '(("cursor" . (("id" . 42)
                        ("firstBatch" . ((("n" . 1)))))))
         "firstBatch")
        '((("n" . 1))
          (("n" . 2)))))
      (should (= (length commands) 1)))))



(ert-deftest mongo-test-cursor-results-kills-on-getmore-error ()
  "MongoDB cursor helpers should clean up open cursors on getMore errors."
  (let (killed-command)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn _database command &optional _timeout)
                 (cond
                  ((assoc "getMore" command)
                   (signal 'mongo-error (list "getMore failed")))
                  ((assoc "killCursors" command)
                   (setq killed-command command)
                   '(("ok" . 1)))
                  (t
                   (ert-fail
                    (format "unexpected command: %S" command)))))))
      (should-error
       (mongo--cursor-results
        'conn "app" "users"
        '(("cursor" . (("id" . 42)
                       ("firstBatch" . ((("n" . 1)))))))
        "firstBatch")
       :type 'mongo-error)
      (should (equal killed-command
                     '(("killCursors" . "users")
                       ("cursors" . [42])))))))



(ert-deftest mongo-test-params-credential-parses-uri-auth ()
  "Native mongo.el should parse MongoDB URI credentials for SCRAM auth."
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://reporter:s%20p@127.0.0.1:27018/app?authSource=admin&authMechanism=SCRAM-SHA-256"))))
    (should (equal (mongo--credential-username credential) "reporter"))
    (should (equal (mongo--credential-password credential) "s p"))
	    (should (equal (mongo--credential-source credential) "admin"))
	    (should (equal (mongo--credential-mechanism credential)
	                   "SCRAM-SHA-256"))))



(ert-deftest mongo-test-params-credential-parses-default-auth ()
  "Native mongo.el should accept authMechanism=DEFAULT from MongoDB URIs."
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://reporter:secret@127.0.0.1/app?authMechanism=DEFAULT"))))
    (should (equal (mongo--credential-username credential) "reporter"))
    (should (equal (mongo--credential-password credential) "secret"))
    (should (equal (mongo--credential-mechanism credential) "DEFAULT"))))



(ert-deftest mongo-test-params-credential-parses-x509-auth ()
  "Native mongo.el should parse MONGODB-X509 credentials without a password."
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://127.0.0.1/app?authMechanism=MONGODB-X509&tls=true"))))
    (should-not (mongo--credential-username credential))
    (should-not (mongo--credential-password credential))
    (should (equal (mongo--credential-source credential) "$external"))
    (should (equal (mongo--credential-mechanism credential)
                   "MONGODB-X509")))
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://CN%3Dclient@127.0.0.1/app?authMechanism=MONGODB-X509&authSource=%24external&tls=true"))))
    (should (equal (mongo--credential-username credential) "CN=client"))
    (should-not (mongo--credential-password credential))
    (should (equal (mongo--credential-source credential) "$external"))))



(ert-deftest mongo-test-params-credential-validates-x509-auth ()
  "Native mongo.el should enforce MONGODB-X509 credential constraints."
  (should-error
   (mongo--params-credential
    '(:url "mongodb://user:secret@127.0.0.1/app?authMechanism=MONGODB-X509&tls=true"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://127.0.0.1/app?authMechanism=MONGODB-X509&authSource=admin&tls=true"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://127.0.0.1/app?authMechanism=MONGODB-X509"))
   :type 'mongo-error))



(ert-deftest mongo-test-params-credential-parses-plain-auth ()
  "Native mongo.el should parse PLAIN SASL credentials."
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://ldap:secret@127.0.0.1/app?authMechanism=PLAIN"))))
    (should (equal (mongo--credential-username credential) "ldap"))
    (should (equal (mongo--credential-password credential) "secret"))
    (should (equal (mongo--credential-source credential) "$external"))
    (should (equal (mongo--credential-mechanism credential) "PLAIN"))))



(ert-deftest mongo-test-params-credential-validates-plain-auth ()
  "Native mongo.el should enforce PLAIN SASL credential constraints."
  (should-error
   (mongo--params-credential
    '(:url "mongodb://ldap:secret@127.0.0.1/app?authMechanism=PLAIN&authSource=admin"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://ldap@127.0.0.1/app?authMechanism=PLAIN"))
   :type 'mongo-error))



(ert-deftest mongo-test-params-credential-parses-aws-auth ()
  "Native mongo.el should parse MONGODB-AWS credentials and properties."
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://AKID:SECRET@cluster.example.net/app?authMechanism=MONGODB-AWS&authMechanismProperties=AWS_SESSION_TOKEN:SESSION"))))
    (should (equal (mongo--credential-username credential) "AKID"))
    (should (equal (mongo--credential-password credential) "SECRET"))
    (should (equal (mongo--credential-source credential) "$external"))
    (should (equal (mongo--credential-mechanism credential) "MONGODB-AWS"))
    (should (equal (mongo--mechanism-property
                    (mongo--credential-mechanism-properties credential)
                    "AWS_SESSION_TOKEN")
                   "SESSION")))
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-AWS"
            :auth-mechanism-properties (:aws-session-token "SESSION")))))
    (should-not (mongo--credential-username credential))
    (should-not (mongo--credential-password credential))
    (should (equal (mongo--credential-source credential) "$external"))
    (should (equal (mongo--mechanism-property
                    (mongo--credential-mechanism-properties credential)
                    :aws-session-token)
                   "SESSION")))
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-AWS"
            :aws-credential-provider ignore))))
    (should (eq (mongo--credential-aws-credential-provider credential)
                'ignore))))



(ert-deftest mongo-test-params-credential-validates-aws-auth ()
  "Native mongo.el should enforce MONGODB-AWS credential constraints."
  (should-error
   (mongo--params-credential
    '(:url "mongodb://AKID:SECRET@cluster.example.net/app?authMechanism=MONGODB-AWS&authSource=admin"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://AKID@cluster.example.net/app?authMechanism=MONGODB-AWS"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://AKID:SECRET@cluster.example.net/app?authMechanism=MONGODB-AWS&authMechanismProperties=SERVICE_NAME:mongodb"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://AKID:SECRET@cluster.example.net/app?authMechanism=SCRAM-SHA-256&authMechanismProperties=AWS_SESSION_TOKEN:SESSION"))
   :type 'mongo-error))



(ert-deftest mongo-test-params-credential-parses-oidc-auth ()
  "Native mongo.el should parse MONGODB-OIDC credentials and token sources."
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://principal@cluster.example.net/app?authMechanism=MONGODB-OIDC"
            :oidc-token "jwt-token"))))
    (should (equal (mongo--credential-username credential) "principal"))
    (should-not (mongo--credential-password credential))
    (should (equal (mongo--credential-source credential) "$external"))
    (should (equal (mongo--credential-mechanism credential) "MONGODB-OIDC"))
    (should (equal (mongo--credential-oidc-token credential) "jwt-token")))
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-OIDC&authMechanismProperties=ENVIRONMENT:k8s"
            :oidc-token-file "/tmp/token"
            :oidc-refresh-token "refresh"))))
    (should-not (mongo--credential-username credential))
    (should (equal (mongo--credential-source credential) "$external"))
    (should (equal (mongo--mechanism-property
                    (mongo--credential-mechanism-properties credential)
                    "ENVIRONMENT")
                   "k8s"))
    (should (equal (mongo--credential-oidc-token-file credential)
                   "/tmp/token"))
    (should (equal (mongo--credential-oidc-refresh-token credential)
                   "refresh")))
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://client-id@cluster.example.net/app?authMechanism=MONGODB-OIDC&authMechanismProperties=ENVIRONMENT:azure,TOKEN_RESOURCE:api%3A%2F%2Fclient"))))
    (should (equal (mongo--credential-username credential) "client-id"))
    (should (equal (mongo--mechanism-property
                    (mongo--credential-mechanism-properties credential)
                    "ENVIRONMENT")
                   "azure"))
    (should (equal (mongo--mechanism-property
                    (mongo--credential-mechanism-properties credential)
                    "TOKEN_RESOURCE")
                   "api://client")))
  (let ((credential
         (mongo--params-credential
          '(:url "mongodb://principal@cluster.example.net/app?authMechanism=MONGODB-OIDC"
            :oidc-human-callback ignore
            :oidc-allowed-hosts ("*.example.net" "localhost")))))
    (should (eq (mongo--credential-oidc-human-callback credential)
                'ignore))
    (should (equal (mongo--credential-oidc-allowed-hosts credential)
                   '("*.example.net" "localhost")))))



(ert-deftest mongo-test-params-credential-validates-oidc-auth ()
  "Native mongo.el should enforce MONGODB-OIDC credential constraints."
  (should-error
   (mongo--params-credential
    '(:url "mongodb://user:secret@cluster.example.net/app?authMechanism=MONGODB-OIDC"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-OIDC&authSource=admin"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-OIDC&authMechanismProperties=SERVICE_NAME:mongodb"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-OIDC&authMechanismProperties=ENVIRONMENT:bogus"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-OIDC&authMechanismProperties=ENVIRONMENT:azure"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-OIDC&authMechanismProperties=TOKEN_RESOURCE:api%3A%2F%2Fclient"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-OIDC&authMechanismProperties=ENVIRONMENT:k8s,TOKEN_RESOURCE:api%3A%2F%2Fclient"))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-OIDC&authMechanismProperties=ENVIRONMENT:k8s"
      :oidc-callback ignore))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-OIDC"
      :oidc-callback ignore
      :oidc-human-callback ignore))
   :type 'mongo-error)
  (should-error
   (mongo--params-credential
    '(:url "mongodb://cluster.example.net/app?authMechanism=MONGODB-OIDC"
      :oidc-allowed-hosts ("")))
   :type 'mongo-error))



(ert-deftest mongo-test-auth-mechanism-selects-scram-sha1 ()
  "Native mongo.el should fall back to SCRAM-SHA-1 when SHA-256 is unavailable."
  (let ((credential (make-mongo--credential
                     :username "user"
                     :password "secret"
                     :source "admin")))
    (should (equal
             (mongo--choose-auth-mechanism
              credential
              '(("saslSupportedMechs" . ("SCRAM-SHA-1"))))
             "SCRAM-SHA-1"))
    (setf (mongo--credential-mechanism credential) "SCRAM-SHA-1")
    (should (equal
             (mongo--choose-auth-mechanism
              credential
              '(("saslSupportedMechs" . ("SCRAM-SHA-1"))))
             "SCRAM-SHA-1"))))



(ert-deftest mongo-test-auth-mechanism-selects-x509 ()
  "Native mongo.el should select MONGODB-X509 without SCRAM negotiation."
  (let ((credential (make-mongo--credential
                     :source "$external"
                     :mechanism "MONGODB-X509")))
    (should (equal
             (mongo--choose-auth-mechanism
              credential
              '(("saslSupportedMechs" . ("SCRAM-SHA-1"))))
             "MONGODB-X509"))
    (should-not (mongo--speculative-auth-state credential))))



(ert-deftest mongo-test-auth-mechanism-selects-plain ()
  "Native mongo.el should select explicit PLAIN without SCRAM negotiation."
  (let ((credential (make-mongo--credential
                     :username "ldap"
                     :password "secret"
                     :source "$external"
                     :mechanism "PLAIN")))
    (should (equal
             (mongo--choose-auth-mechanism
              credential
              '(("saslSupportedMechs" . ("SCRAM-SHA-1"))))
             "PLAIN"))
    (should-not (mongo--speculative-auth-state credential))))



(ert-deftest mongo-test-auth-mechanism-selects-aws ()
  "Native mongo.el should select explicit MONGODB-AWS without SCRAM negotiation."
  (let* ((credential (make-mongo--credential
                      :username "AKID"
                      :password "SECRET"
                      :source "$external"
                      :mechanism "MONGODB-AWS"))
         (handshake (mongo--initial-handshake-command credential)))
    (should (equal
             (mongo--choose-auth-mechanism
              credential
              '(("saslSupportedMechs" . ("SCRAM-SHA-1"))))
             "MONGODB-AWS"))
    (should-not (mongo--speculative-auth-state credential))
    (should-not (assoc "saslSupportedMechs" handshake))))



(ert-deftest mongo-test-auth-mechanism-selects-oidc ()
  "Native mongo.el should select explicit MONGODB-OIDC without SCRAM negotiation."
  (let* ((credential (make-mongo--credential
                      :source "$external"
                      :mechanism "MONGODB-OIDC"
                      :oidc-token "jwt"))
         (handshake (mongo--initial-handshake-command credential)))
    (should (equal
             (mongo--choose-auth-mechanism
              credential
              '(("saslSupportedMechs" . ("SCRAM-SHA-1"))))
             "MONGODB-OIDC"))
    (should-not (mongo--speculative-auth-state credential))
    (should-not (assoc "saslSupportedMechs" handshake))))



(ert-deftest mongo-test-auth-mechanism-defaults-from-handshake ()
  "Native mongo.el should follow MongoDB SCRAM mechanism negotiation."
  (let ((credential (make-mongo--credential
                     :username "user"
                     :password "secret"
                     :source "admin")))
    (should (equal
             (mongo--choose-auth-mechanism
              credential
              '(("saslSupportedMechs" . ("SCRAM-SHA-1"
                                         "SCRAM-SHA-256"))))
             "SCRAM-SHA-256"))
    (should (equal
	            (mongo--choose-auth-mechanism credential '())
	            "SCRAM-SHA-1"))))



(ert-deftest mongo-test-auth-mechanism-default-is-negotiated ()
  "authMechanism=DEFAULT should negotiate the best supported SCRAM mechanism."
  (let ((credential (make-mongo--credential
                     :username "user"
                     :password "secret"
                     :source "admin"
                     :mechanism "DEFAULT")))
    (should (equal
             (mongo--choose-auth-mechanism
              credential
              '(("saslSupportedMechs" . ("SCRAM-SHA-1"
                                         "SCRAM-SHA-256"))))
             "SCRAM-SHA-256"))
    (should (equal
             (mongo--choose-auth-mechanism
              credential
              '(("saslSupportedMechs" . ("SCRAM-SHA-1"))))
             "SCRAM-SHA-1"))))



(ert-deftest mongo-test-x509-authenticates-with-external-command ()
  "Native mongo.el should authenticate X.509 credentials with authenticate."
  (let ((credential (make-mongo--credential
                     :source "$external"
                     :mechanism "MONGODB-X509"))
        captured-db
        captured-command)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout _sequences)
                 (setq captured-db database
                       captured-command command)
                 '(("ok" . 1)))))
      (should (equal (mongo--authenticate 'conn credential '())
                     '(("ok" . 1)))))
    (should (equal captured-db "$external"))
    (should (equal captured-command
                   '(("authenticate" . 1)
                     ("mechanism" . "MONGODB-X509")))))
  (let ((credential (make-mongo--credential
                     :username "CN=client"
                     :source "$external"
                     :mechanism "MONGODB-X509"))
        captured-command)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn _database command &optional _timeout _sequences)
                 (setq captured-command command)
                 '(("ok" . 1)))))
      (mongo--authenticate-x509 'conn credential))
    (should (equal captured-command
                   '(("authenticate" . 1)
                     ("mechanism" . "MONGODB-X509")
                     ("user" . "CN=client"))))))



(ert-deftest mongo-test-plain-authenticates-with-sasl-start ()
  "Native mongo.el should authenticate PLAIN credentials with saslStart."
  (let ((credential (make-mongo--credential
                     :username "ldap"
                     :password "secret"
                     :source "$external"
                     :mechanism "PLAIN"))
        captured-db
        captured-command)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout _sequences)
                 (setq captured-db database
                       captured-command command)
                 '(("ok" . 1) ("done" . t)))))
      (should (equal (mongo--authenticate 'conn credential '())
                     '(("ok" . 1) ("done" . t)))))
    (should (equal captured-db "$external"))
    (should (equal (cdr (assoc "saslStart" captured-command)) 1))
    (should (equal (cdr (assoc "mechanism" captured-command)) "PLAIN"))
    (should (= (cdr (assoc "autoAuthorize" captured-command)) 1))
    (let ((payload (cdr (assoc "payload" captured-command))))
      (should (mongo-binary-p payload))
      (should (= (mongo-binary-subtype payload) 0))
      (should (equal (mongo-binary-data payload)
                     "\0ldap\0secret")))))



(ert-deftest mongo-test-plain-auth-requires-done ()
  "Native mongo.el should reject incomplete PLAIN SASL conversations."
  (let ((credential (make-mongo--credential
                     :username "ldap"
                     :password "secret"
                     :source "$external"
                     :mechanism "PLAIN")))
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (&rest _args)
                 '(("ok" . 1) ("done" . :false)))))
      (should-error (mongo--authenticate-plain 'conn credential)
                    :type 'mongo-error))))



(ert-deftest mongo-test-aws-authenticates-with-sasl-conversation ()
  "Native mongo.el should authenticate MONGODB-AWS with BSON SASL payloads."
  (let* ((client-nonce "abcdefghijklmnopqrstuvwxyz123456")
         (server-nonce (concat client-nonce "ABCDEFGHIJKLMNOPQRSTUVWXYZ789012"))
         (credential (make-mongo--credential
                      :username "AKID"
                      :password "SECRET"
                      :source "$external"
                      :mechanism "MONGODB-AWS"))
         captured)
    (cl-letf (((symbol-function 'mongo--random-bytes)
               (lambda (count)
                 (should (= count 32))
                 client-nonce))
              ((symbol-function 'mongo--aws-date)
               (lambda () "20191107T002607Z"))
              ((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout _sequences)
                 (push (list database command) captured)
                 (cond
                  ((assoc "saslStart" command)
                   (should (equal database "$external"))
                   (should (equal (cdr (assoc "mechanism" command))
                                  "MONGODB-AWS"))
                   (let* ((payload (cdr (assoc "payload" command)))
                          (document
                           (mongo--decode-document-from-string
                            (mongo-binary-data payload))))
                     (should (equal (mongo--binary-value-data
                                     (cdr (assoc "r" document)))
                                    client-nonce))
                     (should (= (cdr (assoc "p" document)) ?n)))
                   `(("conversationId" . 7)
                     ("done" . :false)
                     ("payload" . ,(mongo-binary
                                    0
                                    (mongo--encode-document
                                     `(("s" . ,(mongo-binary
                                                0 server-nonce))
                                       ("h" . "sts.amazonaws.com")))))
                     ("ok" . 1)))
                  ((assoc "saslContinue" command)
                   (should (equal database "$external"))
                   (should (= (cdr (assoc "conversationId" command)) 7))
                   (let* ((payload (cdr (assoc "payload" command)))
                          (document
                           (mongo--decode-document-from-string
                            (mongo-binary-data payload)))
                          (authorization (cdr (assoc "a" document))))
                     (should (string-prefix-p "AWS4-HMAC-SHA256 "
                                              authorization))
                     (should (string-match-p
                              "Credential=AKID/20191107/us-east-1/sts/aws4_request"
                              authorization))
                     (should (string-match-p
                              "SignedHeaders=content-length;content-type;host;x-amz-date;x-mongodb-gs2-cb-flag;x-mongodb-server-nonce"
                              authorization))
                     (should (string-match-p "Signature=[0-9a-f]\\{64\\}"
                                             authorization))
                     (should (equal (cdr (assoc "d" document))
                                    "20191107T002607Z"))
                     (should-not (assoc "t" document)))
                   '(("conversationId" . 7)
                     ("done" . t)
                     ("payload" . "")
                     ("ok" . 1)))
                  (t
                   (ert-fail (format "unexpected command: %S" command)))))))
      (should (equal (mongo--authenticate 'conn credential '())
                     '(("conversationId" . 7)
                       ("done" . t)
                       ("payload" . "")
                       ("ok" . 1)))))
    (should (= (length captured) 2))))



(ert-deftest mongo-test-aws-auth-uses-session-token-and-env ()
  "Native MONGODB-AWS auth should use env credentials and session tokens."
  (let* ((client-nonce "abcdefghijklmnopqrstuvwxyz123456")
         (server-nonce (concat client-nonce "ABCDEFGHIJKLMNOPQRSTUVWXYZ789012"))
         (credential (make-mongo--credential
                      :source "$external"
                      :mechanism "MONGODB-AWS"))
         captured-token)
    (cl-letf (((symbol-function 'getenv)
               (lambda (name)
                 (cdr (assoc name
                             '(("AWS_ACCESS_KEY_ID" . "ENVAKID")
                               ("AWS_SECRET_ACCESS_KEY" . "ENVSECRET")
                               ("AWS_SESSION_TOKEN" . "ENVSESSION"))))))
              ((symbol-function 'mongo--random-bytes)
               (lambda (_count) client-nonce))
              ((symbol-function 'mongo--aws-date)
               (lambda () "20191107T002607Z"))
              ((symbol-function 'mongo-command)
               (lambda (_conn _database command &optional _timeout _sequences)
                 (cond
                  ((assoc "saslStart" command)
                   `(("conversationId" . 8)
                     ("done" . :false)
                     ("payload" . ,(mongo-binary
                                    0
                                    (mongo--encode-document
                                     `(("s" . ,(mongo-binary
                                                0 server-nonce))
                                       ("h" . "sts.us-west-2.amazonaws.com")))))
                     ("ok" . 1)))
                  ((assoc "saslContinue" command)
                   (let* ((payload (cdr (assoc "payload" command)))
                          (document
                           (mongo--decode-document-from-string
                            (mongo-binary-data payload)))
                          (authorization (cdr (assoc "a" document))))
                     (setq captured-token (cdr (assoc "t" document)))
                     (should (string-match-p
                              "Credential=ENVAKID/20191107/us-west-2/sts/aws4_request"
                              authorization))
                     (should (string-match-p
                              "x-amz-security-token"
                              authorization)))
                   '(("conversationId" . 8)
                     ("done" . t)
                     ("payload" . "")
                     ("ok" . 1)))
                  (t
                   (ert-fail (format "unexpected command: %S" command)))))))
      (mongo--authenticate-aws 'conn credential))
    (should (equal captured-token "ENVSESSION"))))



(ert-deftest mongo-test-aws-auth-uses-custom-provider-before-env ()
  "Native MONGODB-AWS auth should allow a custom credential provider."
  (let* ((provider-params nil)
         (credential (make-mongo--credential
                      :source "$external"
                      :mechanism "MONGODB-AWS"
                      :aws-credential-provider
                      (lambda (params)
                        (setq provider-params params)
                        '(:access-key-id "PROVIDERAKID"
                          :secret-access-key "PROVIDERSECRET"
                          :session-token "PROVIDERSESSION")))))
    (cl-letf (((symbol-function 'getenv)
               (lambda (name)
                 (cdr (assoc name
                             '(("AWS_ACCESS_KEY_ID" . "ENVAKID")
                               ("AWS_SECRET_ACCESS_KEY" . "ENVSECRET")))))))
      (let ((credentials (mongo--aws-credentials credential)))
        (should (= (plist-get provider-params :timeout-seconds) 10))
        (should (equal (mongo--aws-credentials-access-key-id credentials)
                       "PROVIDERAKID"))
        (should (equal (mongo--aws-credentials-secret-access-key credentials)
                       "PROVIDERSECRET"))
        (should (equal (mongo--aws-credentials-session-token credentials)
                       "PROVIDERSESSION"))))))



(ert-deftest mongo-test-aws-auth-fetches-web-identity-credentials ()
  "Native MONGODB-AWS auth should support AssumeRoleWithWebIdentity."
  (let ((file (make-temp-file "mongo-aws-web-identity-token"))
        captured-url
        captured-method
        captured-headers
        captured-timeout)
    (unwind-protect
        (progn
          (with-temp-file file
            (insert "web-token\n"))
          (cl-letf (((symbol-function 'getenv)
                     (lambda (name)
                       (cdr (assoc name
                                   `(("AWS_WEB_IDENTITY_TOKEN_FILE" . ,file)
                                     ("AWS_ROLE_ARN" . "arn:aws:iam::123:role/demo")
                                     ("AWS_ROLE_SESSION_NAME" . "clutch-session"))))))
                    ((symbol-function 'url-retrieve-synchronously)
                     (lambda (url &optional _silent _inhibit-cookies timeout)
                       (setq captured-url url
                             captured-method url-request-method
                             captured-headers url-request-extra-headers
                             captured-timeout timeout)
                       (with-current-buffer
                           (generate-new-buffer " *mongo-aws-web-id-test*")
                         (insert (concat
                                  "HTTP/1.1 200 OK\r\n\r\n"
                                  "{\"Credentials\":{\"AccessKeyId\":\"WEBAKID\","
                                  "\"SecretAccessKey\":\"WEBSECRET\","
                                  "\"SessionToken\":\"WEBSESSION\","
                                  "\"Expiration\":\"2035-01-01T00:00:00Z\"}}"))
                         (current-buffer)))))
            (let* ((credential (make-mongo--credential
                                :source "$external"
                                :mechanism "MONGODB-AWS"))
                   (credentials (mongo--aws-credentials credential)))
              (should (equal (mongo--aws-credentials-access-key-id credentials)
                             "WEBAKID"))
              (should (equal (mongo--aws-credentials-session-token credentials)
                             "WEBSESSION"))
              (should (eq (mongo--credential-aws-cached-credentials credential)
                          credentials)))))
      (delete-file file))
    (should (equal captured-method "POST"))
    (should (= captured-timeout 10))
    (should (string-prefix-p "https://sts.amazonaws.com/?" captured-url))
    (should (string-match-p
             (regexp-quote
              (concat "RoleArn="
                      (url-hexify-string "arn:aws:iam::123:role/demo")))
             captured-url))
    (should (string-match-p
             (regexp-quote
              (concat "WebIdentityToken=" (url-hexify-string "web-token")))
             captured-url))
    (should (equal captured-headers '(("Accept" . "application/json"))))))



(ert-deftest mongo-test-aws-auth-fetches-and-caches-ecs-credentials ()
  "Native MONGODB-AWS auth should support ECS task credentials."
  (let ((request-count 0))
    (cl-letf (((symbol-function 'getenv)
               (lambda (name)
                 (and (equal name "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
                      "/v2/credentials/task")))
              ((symbol-function 'url-retrieve-synchronously)
               (lambda (url &optional _silent _inhibit-cookies _timeout)
                 (cl-incf request-count)
                 (should (equal url
                                "http://169.254.170.2/v2/credentials/task"))
                 (should (equal url-request-method "GET"))
                 (with-current-buffer
                     (generate-new-buffer " *mongo-aws-ecs-test*")
                   (insert (concat
                            "HTTP/1.1 200 OK\r\n\r\n"
                            "{\"AccessKeyId\":\"ECSAKID\","
                            "\"SecretAccessKey\":\"ECSSECRET\","
                            "\"Token\":\"ECSSESSION\","
                            "\"Expiration\":\"2035-01-01T00:00:00Z\"}"))
                   (current-buffer)))))
      (let* ((credential (make-mongo--credential
                          :source "$external"
                          :mechanism "MONGODB-AWS"))
             (first (mongo--aws-credentials credential))
             (second (mongo--aws-credentials credential)))
        (should (eq first second))
        (should (= request-count 1))
        (should (equal (mongo--aws-credentials-access-key-id second)
                       "ECSAKID"))
        (should (equal (mongo--aws-credentials-session-token second)
                       "ECSSESSION"))))))



(ert-deftest mongo-test-aws-auth-fetches-ec2-imds-credentials ()
  "Native MONGODB-AWS auth should support EC2 IMDSv2 credentials."
  (let (requests)
    (cl-letf (((symbol-function 'getenv)
               (lambda (_name) nil))
              ((symbol-function 'url-retrieve-synchronously)
               (lambda (url &optional _silent _inhibit-cookies _timeout)
                 (push (list url url-request-method url-request-extra-headers)
                       requests)
                 (with-current-buffer
                     (generate-new-buffer " *mongo-aws-ec2-test*")
                   (insert
                    (cond
                     ((equal url "http://169.254.169.254/latest/api/token")
                      (should (equal url-request-method "PUT"))
                      "HTTP/1.1 200 OK\r\n\r\nimds-token")
                     ((equal url "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
                      (should (equal url-request-method "GET"))
                      (should (equal url-request-extra-headers
                                     '(("X-aws-ec2-metadata-token" . "imds-token"))))
                      "HTTP/1.1 200 OK\r\n\r\ndemo-role\n")
                     ((equal url "http://169.254.169.254/latest/meta-data/iam/security-credentials/demo-role")
                      (should (equal url-request-method "GET"))
                      (should (equal url-request-extra-headers
                                     '(("X-aws-ec2-metadata-token" . "imds-token"))))
                      (concat
                       "HTTP/1.1 200 OK\r\n\r\n"
                       "{\"Code\":\"Success\","
                       "\"AccessKeyId\":\"EC2AKID\","
                       "\"SecretAccessKey\":\"EC2SECRET\","
                       "\"Token\":\"EC2SESSION\","
                       "\"Expiration\":\"2035-01-01T00:00:00Z\"}"))
                     (t
                      (ert-fail (format "unexpected URL: %s" url)))))
                   (current-buffer)))))
      (let* ((credential (make-mongo--credential
                          :source "$external"
                          :mechanism "MONGODB-AWS"))
             (credentials (mongo--aws-credentials credential)))
        (should (= (length requests) 3))
        (should (equal (mongo--aws-credentials-access-key-id credentials)
                       "EC2AKID"))
        (should (equal (mongo--aws-credentials-session-token credentials)
                       "EC2SESSION"))))))



(ert-deftest mongo-test-aws-auth-validates-server-first ()
  "Native MONGODB-AWS auth should validate server nonce and STS host."
  (let* ((client-nonce "abcdefghijklmnopqrstuvwxyz123456")
         (server-nonce (concat "wrongwrongwrongwrongwrongwrong12"
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ789012")))
    (should-error
     (mongo--aws-server-first
      `(("conversationId" . 9)
        ("payload" . ,(mongo-binary
                       0
                       (mongo--encode-document
                        `(("s" . ,(mongo-binary 0 server-nonce))
                          ("h" . "sts.amazonaws.com"))))))
      client-nonce)
     :type 'mongo-error)
    (should-error
     (mongo--aws-server-first
      `(("conversationId" . 9)
        ("payload" . ,(mongo-binary
                       0
                       (mongo--encode-document
                        `(("s" . ,(mongo-binary
                                   0
                                   (concat client-nonce
                                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ789012")))
                          ("h" . "sts..amazonaws.com"))))))
      client-nonce)
     :type 'mongo-error)))



(ert-deftest mongo-test-aws-auth-requires-credentials ()
  "Native MONGODB-AWS auth should fail clearly without AWS credentials."
  (let ((credential (make-mongo--credential
                     :source "$external"
                     :mechanism "MONGODB-AWS")))
    (cl-letf (((symbol-function 'getenv) (lambda (_name) nil))
              ((symbol-function 'mongo--aws-ec2-credentials)
               (lambda ()
                 (signal 'mongo-error
                         (list "no EC2 credentials")))))
      (should-error (mongo--aws-credentials credential)
                    :type 'mongo-error))))



(ert-deftest mongo-test-aws-auth-clears-cache-on-failure ()
  "Native MONGODB-AWS auth should clear cached credentials after failures."
  (let* ((credentials (make-mongo--aws-credentials
                       :access-key-id "CACHEAKID"
                       :secret-access-key "CACHESECRET"
                       :session-token "CACHESESSION"
                       :expiration (float-time
                                    (date-to-time "2035-01-01T00:00:00Z"))))
         (credential (make-mongo--credential
                      :source "$external"
                      :mechanism "MONGODB-AWS"
                      :aws-cached-credentials credentials)))
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (&rest _args)
                 (signal 'mongo-error (list "auth failed")))))
      (should-error (mongo--authenticate-aws 'conn credential)
                    :type 'mongo-error))
    (should-not (mongo--credential-aws-cached-credentials credential))))



(ert-deftest mongo-test-oidc-token-sources ()
  "Native MONGODB-OIDC auth should resolve direct, file, env, and callback tokens."
  (let ((file (make-temp-file "mongo-oidc-token")))
    (unwind-protect
        (progn
          (with-temp-file file
            (insert " file-token\n"))
          (should (equal
                   (mongo--oidc-token
                    (make-mongo--credential
                     :source "$external"
                     :mechanism "MONGODB-OIDC"
                     :oidc-token "direct-token"))
                   "direct-token"))
          (should (equal
                   (mongo--oidc-token
                    (make-mongo--credential
                     :source "$external"
                     :mechanism "MONGODB-OIDC"
                     :oidc-token-file file))
                   "file-token"))
          (cl-letf (((symbol-function 'getenv)
                     (lambda (name)
                       (and (equal name "AWS_WEB_IDENTITY_TOKEN_FILE")
                            file))))
            (should (equal
                     (mongo--oidc-token
                      (make-mongo--credential
                       :source "$external"
                       :mechanism "MONGODB-OIDC"
                       :mechanism-properties '(("ENVIRONMENT" . "k8s"))))
                     "file-token")))
          (should (equal
                   (mongo--oidc-token
                    (make-mongo--credential
                     :username "principal"
                     :source "$external"
                     :mechanism "MONGODB-OIDC"
                     :oidc-callback
                     (lambda (params)
                       (should (= (plist-get params :timeout-ms) 60000))
                       (should (equal (plist-get params :username)
                                      "principal"))
                       (should (= (plist-get params :version) 1))
                       '(:access-token "callback-token"))))
                   "callback-token")))
      (delete-file file))))



(ert-deftest mongo-test-oidc-azure-provider-fetches-token ()
  "Native MONGODB-OIDC should fetch Azure metadata tokens."
  (let (captured-url
        captured-headers
        captured-timeout)
    (cl-letf (((symbol-function 'url-retrieve-synchronously)
               (lambda (url &optional _silent _inhibit-cookies timeout)
                 (setq captured-url url
                       captured-headers url-request-extra-headers
                       captured-timeout timeout)
                 (with-current-buffer
                     (generate-new-buffer " *mongo-oidc-azure-test*")
                   (insert (concat "HTTP/1.1 200 OK\r\n"
                                   "Content-Type: application/json\r\n"
                                   "\r\n"
                                   "{\"access_token\":\"azure-token\"}"))
                   (current-buffer)))))
      (should (equal
               (mongo--oidc-token
                (make-mongo--credential
                 :username "client-id"
                 :source "$external"
                 :mechanism "MONGODB-OIDC"
                 :mechanism-properties
                 '(("ENVIRONMENT" . "azure")
                   ("TOKEN_RESOURCE" . "api://client"))))
               "azure-token")))
    (should (string-prefix-p
             "http://169.254.169.254/metadata/identity/oauth2/token?"
             captured-url))
    (should (string-match-p
             (regexp-quote
              (concat "resource=" (url-hexify-string "api://client")))
             captured-url))
    (should (string-match-p
             (regexp-quote
              (concat "client_id=" (url-hexify-string "client-id")))
             captured-url))
    (should (equal captured-headers
                   '(("Accept" . "application/json")
                     ("Metadata" . "true"))))
    (should (= captured-timeout 60.0))))



(ert-deftest mongo-test-oidc-gcp-provider-fetches-token ()
  "Native MONGODB-OIDC should fetch GCP metadata tokens."
  (let (captured-url
        captured-headers
        captured-timeout)
    (cl-letf (((symbol-function 'url-retrieve-synchronously)
               (lambda (url &optional _silent _inhibit-cookies timeout)
                 (setq captured-url url
                       captured-headers url-request-extra-headers
                       captured-timeout timeout)
                 (with-current-buffer
                     (generate-new-buffer " *mongo-oidc-gcp-test*")
                   (insert "HTTP/1.1 200 OK\r\n\r\ngcp-token\n")
                   (current-buffer)))))
      (should (equal
               (mongo--oidc-token
                (make-mongo--credential
                 :source "$external"
                 :mechanism "MONGODB-OIDC"
                 :mechanism-properties
                 '(("ENVIRONMENT" . "gcp")
                   ("TOKEN_RESOURCE" . "api://client"))))
               "gcp-token")))
    (should (equal
             captured-url
             (concat
              "http://metadata/computeMetadata/v1/instance/"
              "service-accounts/default/identity?audience="
              (url-hexify-string "api://client"))))
    (should (equal captured-headers
                   '(("Metadata-Flavor" . "Google"))))
    (should (= captured-timeout 60.0))))



(ert-deftest mongo-test-oidc-metadata-provider-reports-http-errors ()
  "Native MONGODB-OIDC should surface metadata HTTP failures."
  (cl-letf (((symbol-function 'url-retrieve-synchronously)
             (lambda (&rest _args)
               (with-current-buffer
                   (generate-new-buffer " *mongo-oidc-http-error-test*")
                 (insert "HTTP/1.1 500 Internal Server Error\r\n\r\nfailed")
                 (current-buffer)))))
    (should-error
     (mongo--oidc-token
      (make-mongo--credential
       :source "$external"
       :mechanism "MONGODB-OIDC"
       :mechanism-properties
       '(("ENVIRONMENT" . "gcp")
         ("TOKEN_RESOURCE" . "api://client"))))
     :type 'mongo-error)))



(ert-deftest mongo-test-oidc-human-callback-host-matching ()
  "Native MONGODB-OIDC should match human callback allowed hosts."
  (should (mongo--oidc-allowed-host-p "cluster.mongodb.net" nil))
  (should (mongo--oidc-allowed-host-p "a.b.mongodb.net" nil))
  (should-not (mongo--oidc-allowed-host-p "mongodb.net" nil))
  (should (mongo--oidc-allowed-host-p "LOCALHOST." nil))
  (should (mongo--oidc-allowed-host-p "[::1]" nil))
  (should (mongo--oidc-allowed-host-p "db.example.com"
                                      '("*.example.com")))
  (should-not (mongo--oidc-allowed-host-p "example.com"
                                          '("*.example.com"))))



(ert-deftest mongo-test-oidc-human-callback-rejects-disallowed-host ()
  "Native MONGODB-OIDC should reject human callbacks on disallowed hosts."
  (let* ((callback-called nil)
         (command-called nil)
         (credential
          (make-mongo--credential
           :source "$external"
           :mechanism "MONGODB-OIDC"
           :oidc-human-callback
           (lambda (_params)
             (setq callback-called t)
             "jwt")))
         (conn (make-mongo-conn :host "evil.example.com")))
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (&rest _args)
                 (setq command-called t)
                 '(("ok" . 1)))))
      (should-error (mongo--authenticate-oidc conn credential)
                    :type 'mongo-error))
    (should-not callback-called)
    (should-not command-called)))



(ert-deftest mongo-test-oidc-authenticates-with-one-step-sasl ()
  "Native mongo.el should authenticate MONGODB-OIDC with JwtStepRequest."
  (let ((credential (make-mongo--credential
                     :source "$external"
                     :mechanism "MONGODB-OIDC"
                     :oidc-token "abcd1234"))
        captured-db
        captured-command)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout _sequences)
                 (setq captured-db database
                       captured-command command)
                 '(("conversationId" . 1)
                   ("done" . t)
                   ("payload" . "")
                   ("ok" . 1)))))
      (should (equal (mongo--authenticate 'conn credential '())
                     '(("conversationId" . 1)
                       ("done" . t)
                       ("payload" . "")
                       ("ok" . 1)))))
    (should (equal captured-db "$external"))
    (should (equal (cdr (assoc "saslStart" captured-command)) 1))
    (should (equal (cdr (assoc "mechanism" captured-command))
                   "MONGODB-OIDC"))
    (should (= (cdr (assoc "autoAuthorize" captured-command)) 1))
    (let* ((payload (cdr (assoc "payload" captured-command)))
           (document (mongo--decode-document-from-string
                      (mongo-binary-data payload))))
      (should (mongo-binary-p payload))
      (should (= (mongo-binary-subtype payload) 0))
      (should (equal (cdr (assoc "jwt" document)) "abcd1234")))))



(ert-deftest mongo-test-oidc-authenticates-with-two-step-sasl ()
  "Native mongo.el should authenticate MONGODB-OIDC with IdPInfo and callback."
  (let* ((idp-info '(("issuer" . "https://issuer.example.test")
                     ("clientId" . "client-1")
                     ("requestScopes" . ["openid" "mongodb"])))
         (conn (make-mongo-conn :host "cluster.mongodb.net"))
         (credential (make-mongo--credential
                      :username "myidp"
                      :source "$external"
                      :mechanism "MONGODB-OIDC"
                      :oidc-refresh-token "old-refresh"
                      :oidc-human-callback
                      (lambda (params)
                        (should (= (plist-get params :timeout-ms) 60000))
                        (should (equal (plist-get params :username)
                                       "myidp"))
                        (should (= (plist-get params :version) 1))
                        (should (equal (plist-get params :refresh-token)
                                       "old-refresh"))
                        (should (equal (plist-get params :idp-info)
                                       idp-info))
                        '(:access-token "abcd1234"
                          :refresh-token "new-refresh"))))
         commands)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout _sequences)
                 (push (list database command) commands)
                 (cond
                  ((assoc "saslStart" command)
                   (should (equal database "$external"))
                   (should (equal (cdr (assoc "mechanism" command))
                                  "MONGODB-OIDC"))
                   (let* ((payload (cdr (assoc "payload" command)))
                          (document
                           (mongo--decode-document-from-string
                            (mongo-binary-data payload))))
                     (should (equal (cdr (assoc "n" document)) "myidp")))
                   `(("conversationId" . 11)
                     ("done" . :false)
                     ("payload" . ,(mongo-binary
                                    0
                                    (mongo--encode-document idp-info)))
                     ("ok" . 1)))
                  ((assoc "saslContinue" command)
                   (should (equal database "$external"))
                   (should (= (cdr (assoc "conversationId" command)) 11))
                   (let* ((payload (cdr (assoc "payload" command)))
                          (document
                           (mongo--decode-document-from-string
                            (mongo-binary-data payload))))
                     (should (equal (cdr (assoc "jwt" document))
                                    "abcd1234")))
                   '(("conversationId" . 11)
                     ("done" . t)
                     ("payload" . "")
                     ("ok" . 1)))
                  (t
                   (ert-fail (format "unexpected command: %S" command)))))))
      (should (equal (mongo--authenticate conn credential '())
                     '(("conversationId" . 11)
                       ("done" . t)
                       ("payload" . "")
                       ("ok" . 1)))))
    (should (= (length commands) 2))
    (should (equal (mongo--credential-oidc-refresh-token credential)
                   "new-refresh"))
    (should (equal (mongo--credential-oidc-idp-info credential)
                   idp-info))))



(ert-deftest mongo-test-oidc-auth-requires-done ()
  "Native mongo.el should reject incomplete one-step OIDC conversations."
  (let ((credential (make-mongo--credential
                     :source "$external"
                     :mechanism "MONGODB-OIDC"
                     :oidc-token "jwt")))
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (&rest _args)
                 '(("conversationId" . 1) ("done" . :false) ("ok" . 1)))))
      (should-error (mongo--authenticate-oidc 'conn credential)
                    :type 'mongo-error))))



(ert-deftest mongo-test-saslprep-normalizes-password ()
  "SCRAM-SHA-256 passwords should be prepared with SASLprep."
  (should (equal (mongo--saslprep
                  (concat "I" (string #x00AD) "X"
                          (string #x00AA) (string #x2168)))
                 "IXaIX"))
  (should (equal (mongo--saslprep
                  (concat "a" (string #x00A0) "b"
                          (string #x3000) "c"))
                 "a b c")))



(ert-deftest mongo-test-saslprep-rejects-prohibited ()
  "SCRAM-SHA-256 SASLprep should reject prohibited code points."
  (should-error (mongo--saslprep (concat "a" (string #x0007) "b"))
                :type 'mongo-error)
  (should-error (mongo--saslprep (string #xE000))
                :type 'mongo-error)
  (should-error (mongo--saslprep (string #xFDD0))
                :type 'mongo-error))



(ert-deftest mongo-test-saslprep-rejects-invalid-bidi ()
  "SCRAM-SHA-256 SASLprep should enforce bidirectional text rules."
  (let ((alef (string #x0627)))
    (should (equal (mongo--saslprep (concat alef "1" alef))
                   (concat alef "1" alef)))
    (should-error (mongo--saslprep (concat alef "a" alef))
                  :type 'mongo-error)
    (should-error (mongo--saslprep (concat "1" alef))
                  :type 'mongo-error)))



(ert-deftest mongo-test-scram-sha256-saslprep-password ()
  "SCRAM-SHA-256 key derivation should use the SASLprep password form."
  (let ((server-first
         "r=clientnonceSERVER,s=QSXCR+Q6sek8bf92,i=4096"))
    (should (equal
             (mongo--scram-sha256-client-final
              (concat "I" (string #x00AD) "X")
              "n=user,r=clientnonce" "clientnonce" server-first)
             (mongo--scram-sha256-client-final
              "IX" "n=user,r=clientnonce" "clientnonce" server-first)))))



(ert-deftest mongo-test-scram-sha1-password-does-not-saslprep ()
  "SCRAM-SHA-1 should digest the raw MongoDB password form."
  (let ((password (concat "I" (string #x00AD) "X")))
    (should (equal
             (mongo--scram-sha1-password-bytes "user" password)
             (mongo--utf8-bytes
              (secure-hash
               'md5
               (mongo--utf8-bytes
                (format "user:mongo:%s" password))))))
    (should-not (equal (mongo--scram-sha1-password-bytes "user" password)
                       (mongo--scram-sha1-password-bytes "user" "IX")))))



(ert-deftest mongo-test-scram-rejects-low-iterations ()
  "MongoDB SCRAM conversations should reject downgrade iteration counts."
  (should-error
   (mongo--scram-sha256-client-final
    "pencil" "n=user,r=clientnonce" "clientnonce"
    "r=clientnonceSERVER,s=QSXCR+Q6sek8bf92,i=4095")
   :type 'mongo-error)
  (should-error
   (mongo--scram-sha1-client-final
    "user" "pencil" "n=user,r=clientnonce" "clientnonce"
    "r=clientnonceSERVER,s=QSXCR+Q6sek8bf92,i=4095")
   :type 'mongo-error))



(ert-deftest mongo-test-scram-sha256-conversation ()
  "The native SCRAM implementation should send binary SASL payloads."
  (let* ((credential (make-mongo--credential
                      :username "user"
                      :password "pencil"
                      :source "admin"))
         (server-first
          "r=clientnonceSERVER,s=QSXCR+Q6sek8bf92,i=4096")
         (expected-final
          (mongo--scram-sha256-client-final
           "pencil" "n=user,r=clientnonce" "clientnonce" server-first))
         calls)
    (cl-letf (((symbol-function 'mongo--scram-client-nonce)
               (lambda () "clientnonce"))
              ((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (push (list database command) calls)
                 (cond
                  ((assoc "saslStart" command)
                   (should (equal database "admin"))
                   (should (equal (cdr (assoc "options" command))
                                  '(("skipEmptyExchange" . t))))
                   (should (equal
                            (mongo--scram-payload-string
                             (cdr (assoc "payload" command)))
                            "n,,n=user,r=clientnonce"))
                   `(("conversationId" . 7)
                     ("done" . :false)
                     ("payload" . ,(mongo-binary
                                    0
                                    (mongo--utf8-bytes server-first)))
                     ("ok" . 1)))
                  ((assoc "saslContinue" command)
                   (should (equal database "admin"))
                   (should (= (cdr (assoc "conversationId" command)) 7))
                   (should (string-prefix-p
                            "c=biws,r=clientnonceSERVER,p="
                            (mongo--scram-payload-string
                             (cdr (assoc "payload" command)))))
                   `(("conversationId" . 7)
                     ("done" . t)
                     ("payload" . ,(mongo-binary
                                    0
                                    (mongo--utf8-bytes
                                     (format
                                      "v=%s"
                                      (mongo--base64-encode
                                       (plist-get expected-final
                                                  :server-signature))))))
                     ("ok" . 1)))
                  (t
                   (ert-fail (format "unexpected command: %S" command)))))))
      (mongo--authenticate-scram-sha256 'conn credential)
      (should (= (length calls) 2)))))



(ert-deftest mongo-test-scram-sha256-speculative-conversation ()
  "Speculative SCRAM should continue from the handshake saslStart response."
  (let* ((credential (make-mongo--credential
                      :username "user"
                      :password "pencil"
                      :source "admin"))
         (server-first
          "r=clientnonceSERVER,s=QSXCR+Q6sek8bf92,i=4096")
         (expected-final
          (mongo--scram-sha256-client-final
           "pencil" "n=user,r=clientnonce" "clientnonce" server-first))
         start-data
         calls)
    (cl-letf (((symbol-function 'mongo--scram-client-nonce)
               (lambda () "clientnonce")))
      (setq start-data (mongo--speculative-auth-state credential)))
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (push (list database command) calls)
                 (cond
                  ((assoc "saslStart" command)
                   (ert-fail "speculative auth should not send saslStart"))
                  ((assoc "saslContinue" command)
                   (should (equal database "admin"))
                   (should (= (cdr (assoc "conversationId" command)) 7))
                   (should (string-prefix-p
                            "c=biws,r=clientnonceSERVER,p="
                            (mongo--scram-payload-string
                             (cdr (assoc "payload" command)))))
                   `(("conversationId" . 7)
                     ("done" . t)
                     ("payload" . ,(mongo-binary
                                    0
                                    (mongo--utf8-bytes
                                     (format
                                      "v=%s"
                                      (mongo--base64-encode
                                       (plist-get expected-final
                                                  :server-signature))))))
                     ("ok" . 1)))
                  (t
                   (ert-fail (format "unexpected command: %S" command)))))))
      (mongo--authenticate
       'conn credential
       `(("saslSupportedMechs" . ("SCRAM-SHA-1" "SCRAM-SHA-256"))
         ("speculativeAuthenticate" .
          (("conversationId" . 7)
           ("done" . :false)
           ("payload" . ,(mongo-binary
                          0
                          (mongo--utf8-bytes server-first))))))
       start-data)
      (should (= (length calls) 1)))))



(ert-deftest mongo-test-scram-sha1-conversation ()
  "The native SCRAM implementation should support SCRAM-SHA-1."
  (let* ((credential (make-mongo--credential
                      :username "user"
                      :password "pencil"
                      :source "admin"))
         (server-first
          "r=clientnonceSERVER,s=QSXCR+Q6sek8bf92,i=4096")
         (expected-final
          (mongo--scram-sha1-client-final
           "user" "pencil" "n=user,r=clientnonce"
           "clientnonce" server-first))
         calls)
    (cl-letf (((symbol-function 'mongo--scram-client-nonce)
               (lambda () "clientnonce"))
              ((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (push (list database command) calls)
                 (cond
                  ((assoc "saslStart" command)
                   (should (equal (cdr (assoc "mechanism" command))
                                  "SCRAM-SHA-1"))
                   (should (equal (cdr (assoc "options" command))
                                  '(("skipEmptyExchange" . t))))
                   `(("conversationId" . 7)
                     ("done" . :false)
                     ("payload" . ,(mongo-binary
                                    0
                                    (mongo--utf8-bytes server-first)))
                     ("ok" . 1)))
                  ((assoc "saslContinue" command)
                   (should (string-prefix-p
                            "c=biws,r=clientnonceSERVER,p="
                            (mongo--scram-payload-string
                             (cdr (assoc "payload" command)))))
                   `(("conversationId" . 7)
                     ("done" . t)
                     ("payload" . ,(mongo-binary
                                    0
                                    (mongo--utf8-bytes
                                     (format
                                      "v=%s"
                                      (mongo--base64-encode
                                       (plist-get expected-final
                                                  :server-signature))))))
                     ("ok" . 1)))
                  (t
                   (ert-fail (format "unexpected command: %S" command)))))))
      (mongo--authenticate
       'conn credential
       '(("saslSupportedMechs" . ("SCRAM-SHA-1"))))
      (should (= (length calls) 2)))))



(ert-deftest mongo-test-scram-sha256-final-empty-continue ()
  "SCRAM should continue with an empty payload until the server marks done."
  (let* ((credential (make-mongo--credential
                      :username "user"
                      :password "pencil"
                      :source "admin"))
         (server-first
          "r=clientnonceSERVER,s=QSXCR+Q6sek8bf92,i=4096")
         (expected-final
          (mongo--scram-sha256-client-final
           "pencil" "n=user,r=clientnonce" "clientnonce" server-first))
         (continue-count 0))
    (cl-letf (((symbol-function 'mongo--scram-client-nonce)
               (lambda () "clientnonce"))
              ((symbol-function 'mongo-command)
               (lambda (_conn _database command &optional _timeout)
                 (cond
                  ((assoc "saslStart" command)
                   (should (equal (cdr (assoc "options" command))
                                  '(("skipEmptyExchange" . t))))
                   `(("conversationId" . 7)
                     ("done" . :false)
                     ("payload" . ,(mongo-binary
                                    0
                                    (mongo--utf8-bytes server-first)))
                     ("ok" . 1)))
                  ((assoc "saslContinue" command)
                   (cl-incf continue-count)
                   (if (= continue-count 1)
                       `(("conversationId" . 7)
                         ("done" . :false)
                         ("payload" . ,(mongo-binary
                                        0
                                        (mongo--utf8-bytes
                                         (format
                                          "v=%s"
                                          (mongo--base64-encode
                                           (plist-get expected-final
                                                      :server-signature))))))
                         ("ok" . 1))
                     (should (equal
                              (mongo--scram-payload-string
                               (cdr (assoc "payload" command)))
                              ""))
                     '(("conversationId" . 7)
                       ("done" . t)
                       ("payload" . "")
                       ("ok" . 1))))
                  (t
                   (ert-fail (format "unexpected command: %S" command)))))))
      (mongo--authenticate-scram-sha256 'conn credential)
      (should (= continue-count 2)))))



(ert-deftest mongo-test-params-endpoint-rejects-jdbc-url ()
  "Native mongo.el should not silently treat JDBC URLs as localhost."
  (let ((err (should-error
              (mongo--params-endpoint
               '(:url "jdbc:mongodb://cluster0.a.query.mongodb.net/admin"
                 :database "analytics"))
              :type 'mongo-error)))
    (should (string-match-p "expects mongodb:// URLs"
                            (error-message-string err)))))



(ert-deftest mongo-test-params-endpoint-parses-url-query ()
  "Native mongo.el should parse ordinary mongodb:// URLs with query strings."
  (should (equal (mongo--params-endpoint
                  '(:url "mongodb://127.0.0.1:27018/app?retryWrites=true"))
                 '("127.0.0.1" 27018 "app"))))



(ert-deftest mongo-test-params-endpoint-parses-unix-socket-uri ()
  "Native mongo.el should parse URL-encoded UNIX-domain socket hosts."
  (should (equal (mongo--params-endpoint
                  '(:url "mongodb://%2Ftmp%2Fmongodb-27017.sock/app"))
                 '("/tmp/mongodb-27017.sock" nil "app")))
  (should (equal (mongo--params-endpoint
                  '(:host "/tmp/mongodb-27017.sock"
                    :database "app"))
                 '("/tmp/mongodb-27017.sock" nil "app")))
  (should (equal (mongo--endpoint-key "/tmp/MongoDB-27017.sock" nil)
                 "local:/tmp/MongoDB-27017.sock")))



(ert-deftest mongo-test-params-url-rejects-unsupported-options ()
  "Native mongo.el should not silently ignore unsupported URI options."
  (let ((err (should-error
              (mongo--params-endpoint
               '(:url "mongodb://127.0.0.1/app?unknownOption=10"))
              :type 'mongo-error)))
    (should (string-match-p "unknownoption"
                            (error-message-string err)))))



(ert-deftest mongo-test-params-url-rejects-invalid-boolean-options ()
  "Native mongo.el should validate MongoDB URI boolean option values."
  (let ((err (should-error
              (mongo--params-endpoint
               '(:url "mongodb://127.0.0.1/app?directConnection=maybe"))
              :type 'mongo-error)))
    (should (string-match-p "directconnection"
                            (error-message-string err))))
  (should-not (mongo--params-direct-connection-p
               '(:direct-connection "false")))
  (should-not (mongo--params-load-balanced-p
               '(:load-balanced "false")))
  (should-error (mongo--params-direct-connection-p
                 '(:direct-connection "maybe"))
                :type 'mongo-error))



(ert-deftest mongo-test-params-url-rejects-conflicting-tls-options ()
  "Native mongo.el should reject MongoDB TLS URI option conflicts."
  (should (equal (mongo--params-endpoint
                  '(:url "mongodb://127.0.0.1/app?tls=true&ssl=true"))
                 '("127.0.0.1" 27017 "app")))
  (dolist (case '(("mongodb://127.0.0.1/app?tls=true&ssl=false"
                   . "tls and ssl")
                  ("mongodb://127.0.0.1/app?tlsInsecure=true&tlsAllowInvalidCertificates=true"
                   . "tlsInsecure.*tlsAllowInvalidCertificates")
                  ("mongodb://127.0.0.1/app?tlsInsecure=true&tlsAllowInvalidHostnames=true"
                   . "tlsInsecure.*tlsAllowInvalidHostnames")
                  ("mongodb://127.0.0.1/app?tlsInsecure=true&tlsDisableOCSPEndpointCheck=true"
                   . "tlsInsecure.*tlsDisableOCSPEndpointCheck")
                  ("mongodb://127.0.0.1/app?tlsInsecure=true&tlsDisableCertificateRevocationCheck=true"
                   . "tlsInsecure.*tlsDisableCertificateRevocationCheck")
                  ("mongodb://127.0.0.1/app?tlsAllowInvalidCertificates=true&tlsDisableOCSPEndpointCheck=true"
                   . "tlsAllowInvalidCertificates.*tlsDisableOCSPEndpointCheck")
                  ("mongodb://127.0.0.1/app?tlsAllowInvalidCertificates=true&tlsDisableCertificateRevocationCheck=true"
                   . "tlsAllowInvalidCertificates.*tlsDisableCertificateRevocationCheck")
                  ("mongodb://127.0.0.1/app?tlsDisableOCSPEndpointCheck=true&tlsDisableCertificateRevocationCheck=true"
                   . "tlsDisableOCSPEndpointCheck.*tlsDisableCertificateRevocationCheck")))
    (let ((err (should-error
                (mongo--params-endpoint `(:url ,(car case)))
                :type 'mongo-error)))
      (should (string-match-p (cdr case)
                              (error-message-string err))))))



(ert-deftest mongo-test-params-connect-timeout-from-uri ()
  "Native mongo.el should map connectTimeoutMS to connect timeout seconds."
  (should (= (mongo--params-connect-timeout
              '(:url "mongodb://127.0.0.1/app?connectTimeoutMS=2500"))
             2.5))
  (should (= (mongo--params-connect-timeout
              '(:connect-timeout 7
                :url "mongodb://127.0.0.1/app?connectTimeoutMS=2500"))
             7)))



(ert-deftest mongo-test-params-socket-timeout-from-uri ()
  "Native mongo.el should map socketTimeoutMS to socket timeout seconds."
  (should (= (mongo--params-socket-timeout
              '(:url "mongodb://127.0.0.1/app?socketTimeoutMS=1500"))
             1.5))
  (should (= (mongo--params-socket-timeout
              '(:socket-timeout 7
                :url "mongodb://127.0.0.1/app?socketTimeoutMS=1500"))
             7)))



(ert-deftest mongo-test-params-operation-timeout-from-uri ()
  "Native mongo.el should map timeoutMS to default operation timeout seconds."
  (should (= (mongo--params-operation-timeout
              '(:url "mongodb://127.0.0.1/app?timeoutMS=2500"))
             2.5))
  (should (= (mongo--params-operation-timeout
              '(:timeout-ms 1200
                :url "mongodb://127.0.0.1/app?timeoutMS=2500"))
             1.2))
  (should (= (mongo--params-operation-timeout
              '(:operation-timeout 7
                :url "mongodb://127.0.0.1/app?timeoutMS=2500"))
             7)))



(ert-deftest mongo-test-params-monitoring-options-from-uri ()
  "Native mongo.el should parse MongoDB monitoring URI options."
  (should (= (mongo--params-heartbeat-frequency
              '(:url "mongodb://127.0.0.1/app?heartbeatFrequencyMS=1500"))
             1.5))
  (should (= (mongo--params-heartbeat-frequency
              '(:heartbeat-frequency 2
                :url "mongodb://127.0.0.1/app?heartbeatFrequencyMS=1500"))
             2))
  (should (eq (mongo--params-server-monitoring-mode
               '(:url "mongodb://127.0.0.1/app?serverMonitoringMode=poll"))
              'poll))
  (should (eq (mongo--params-server-monitoring-mode
               '(:server-monitoring-mode stream))
              'stream))
  (should-error
   (mongo--params-heartbeat-frequency
    '(:url "mongodb://127.0.0.1/app?heartbeatFrequencyMS=0"))
   :type 'mongo-error)
  (should-error
   (mongo--params-server-monitoring-mode
    '(:url "mongodb://127.0.0.1/app?serverMonitoringMode=bad"))
   :type 'mongo-error))



(ert-deftest mongo-test-params-pool-options-from-uri ()
  "Native mongo.el should parse MongoDB connection pool URI options."
  (let ((params
         '(:url
           "mongodb://127.0.0.1/app?maxPoolSize=12&minPoolSize=2&maxIdleTimeMS=1500&waitQueueTimeoutMS=250&maxConnecting=3")))
    (should (= (mongo--params-max-pool-size params) 12))
    (should (= (mongo--params-min-pool-size params) 2))
    (should (= (mongo--params-max-idle-time params) 1.5))
    (should (= (mongo--params-wait-queue-timeout params) 0.25))
    (should (= (mongo--params-max-connecting params) 3)))
  (should-not (mongo--params-wait-queue-timeout
               '(:url
                 "mongodb://127.0.0.1/app?waitQueueTimeoutMS=0")))
  (should-not (mongo--params-wait-queue-timeout
               '(:wait-queue-timeout 0))))



(ert-deftest mongo-test-params-pool-options-validate ()
  "Native mongo.el should validate MongoDB connection pool options."
  (should-not (mongo--params-max-pool-size
               '(:url "mongodb://127.0.0.1/app?maxPoolSize=0")))
  (should-error
   (mongo--params-validate-pool-options
    '(:url "mongodb://127.0.0.1/app?maxPoolSize=1&minPoolSize=2"))
   :type 'mongo-error)
  (should-error
   (mongo--params-max-connecting
    '(:url "mongodb://127.0.0.1/app?maxConnecting=0"))
   :type 'mongo-error)
  (should-error
   (mongo--params-wait-queue-timeout
    '(:wait-queue-timeout -1))
   :type 'mongo-error))



(ert-deftest mongo-test-params-proxy-from-uri ()
  "Native mongo.el should parse standard SOCKS5 proxy URI options."
  (should (equal (mongo--params-proxy
                  '(:url
                    "mongodb://127.0.0.1/app?proxyHost=proxy.example&proxyPort=1081&proxyUsername=u&proxyPassword=p"))
                 '(:host "proxy.example"
                   :port 1081
                   :username "u"
                   :password "p")))
  (should (equal (mongo--params-proxy
                  '(:url
                    "mongodb://127.0.0.1/app?proxyHost=proxy.example"))
                 '(:host "proxy.example"
                   :port 1080
                   :username nil
                   :password nil)))
  (should (equal (mongo--params-proxy
                  '(:proxy-host "proxy.local"
                    :proxy-port 1082))
                 '(:host "proxy.local"
                   :port 1082
                   :username nil
                   :password nil)))
  (dolist (params
           '((:url "mongodb://127.0.0.1/app?proxyPort=1081")
             (:url "mongodb://127.0.0.1/app?proxyHost=")
             (:url "mongodb://127.0.0.1/app?proxyHost=proxy.example&proxyPort=0")
             (:url "mongodb://127.0.0.1/app?proxyHost=proxy.example&proxyPort=65536")
             (:url "mongodb://127.0.0.1/app?proxyHost=proxy.example&proxyUsername=u")
             (:url "mongodb://127.0.0.1/app?proxyHost=proxy.example&proxyPassword=p")))
    (should-error (mongo--params-proxy params)
                  :type 'mongo-error)))



(ert-deftest mongo-test-params-retry-reads-defaults-enabled ()
  "Native mongo.el should parse retryReads and default it to enabled."
  (should (mongo--params-retry-reads-p
           '(:url "mongodb://127.0.0.1/app")))
  (should (mongo--params-retry-reads-p
           '(:url "mongodb://127.0.0.1/app?retryReads=true")))
  (should-not (mongo--params-retry-reads-p
               '(:url "mongodb://127.0.0.1/app?retryReads=false")))
  (should-not (mongo--params-retry-reads-p
               '(:retry-reads nil
                 :url "mongodb://127.0.0.1/app?retryReads=true")))
  (should-error (mongo--params-retry-reads-p
                 '(:retry-reads maybe))
                :type 'mongo-error))



(ert-deftest mongo-test-params-retry-writes-defaults-enabled ()
  "Native mongo.el should parse retryWrites and default it to enabled."
  (should (mongo--params-retry-writes-p
           '(:url "mongodb://127.0.0.1/app")))
  (should (mongo--params-retry-writes-p
           '(:url "mongodb://127.0.0.1/app?retryWrites=true")))
  (should-not (mongo--params-retry-writes-p
               '(:url "mongodb://127.0.0.1/app?retryWrites=false")))
  (should-not (mongo--params-retry-writes-p
               '(:retry-writes nil
                 :url "mongodb://127.0.0.1/app?retryWrites=true")))
  (should-error (mongo--params-retry-writes-p
                 '(:retry-writes maybe))
                :type 'mongo-error))



(ert-deftest mongo-test-params-server-selection-timeout-from-uri ()
  "Native mongo.el should map serverSelectionTimeoutMS to seconds."
  (should (= (mongo--params-server-selection-timeout
              '(:url "mongodb://127.0.0.1/app"))
             30))
  (should (= (mongo--params-server-selection-timeout
              '(:url "mongodb://127.0.0.1/app?serverSelectionTimeoutMS=2500"))
             2.5))
  (should (= (mongo--params-server-selection-timeout
              '(:server-selection-timeout 7
                :url "mongodb://127.0.0.1/app?serverSelectionTimeoutMS=2500"))
             7))
  (should-error
   (mongo--params-server-selection-timeout
    '(:url "mongodb://127.0.0.1/app?serverSelectionTimeoutMS=-1"))
   :type 'mongo-error)
  (should-error
  (mongo--params-server-selection-timeout
   '(:server-selection-timeout -1))
  :type 'mongo-error))



(ert-deftest mongo-test-params-server-selection-try-once-from-uri ()
  "Native mongo.el should parse serverSelectionTryOnce."
  (should (mongo--params-server-selection-try-once-p
           '(:url "mongodb://127.0.0.1/app")))
  (should-not (mongo--params-server-selection-try-once-p
               '(:url
                 "mongodb://127.0.0.1/app?serverSelectionTryOnce=false")))
  (should-not (mongo--params-server-selection-try-once-p
               '(:server-selection-try-once nil
                 :url
                 "mongodb://127.0.0.1/app?serverSelectionTryOnce=true")))
  (should (mongo--params-server-selection-try-once-p
           '(:serverSelectionTryOnce t)))
  (should-error
   (mongo--params-server-selection-try-once-p
    '(:url "mongodb://127.0.0.1/app?serverSelectionTryOnce=maybe"))
   :type 'mongo-error)
  (should-error
   (mongo--params-server-selection-try-once-p
    '(:server-selection-try-once maybe))
   :type 'mongo-error))



(ert-deftest mongo-test-params-local-threshold-from-uri ()
  "Native mongo.el should map localThresholdMS to seconds."
  (should (= (mongo--params-local-threshold
              '(:url "mongodb://127.0.0.1/app?localThresholdMS=25"))
             0.025))
  (should (= (mongo--params-local-threshold
              '(:local-threshold 0.2
                :url "mongodb://127.0.0.1/app?localThresholdMS=25"))
             0.2))
  (should (= (mongo--params-local-threshold
              '(:local-threshold-ms 30))
             0.03))
  (should-error
   (mongo--params-local-threshold
    '(:url "mongodb://127.0.0.1/app?localThresholdMS=-1"))
   :type 'mongo-error)
  (should-error
   (mongo--params-local-threshold
    '(:local-threshold -0.1))
   :type 'mongo-error))



(ert-deftest mongo-test-params-endpoints-parse-replica-set-seeds ()
  "Native mongo.el should parse MongoDB replica-set seed lists."
  (let* ((params '(:url "mongodb://mongo-a,mongo-b:27018/app?replicaSet=rs0"))
         (endpoints (mongo--params-endpoints params)))
    (should (equal endpoints
                   '(("mongo-a" 27017 "app")
                     ("mongo-b" 27018 "app"))))
    (should (equal (mongo--params-endpoint params)
                   '("mongo-a" 27017 "app")))
    (should (equal (mongo--params-replica-set-name params) "rs0"))
    (should (mongo--params-replica-discovery-p params endpoints))))



(ert-deftest mongo-test-params-direct-connection-bypasses-discovery ()
  "Native mongo.el should honor directConnection for one explicit host."
  (let* ((params '(:url "mongodb://mongo-a/app?replicaSet=rs0&directConnection=true"))
         (endpoints (mongo--params-endpoints params)))
    (should (mongo--params-direct-connection-p params))
    (should-not (mongo--params-replica-discovery-p params endpoints))))



(ert-deftest mongo-test-params-compressors-parse-supported ()
  "Native mongo.el should parse supported wire compression options."
  (should (equal (mongo--params-compressors
                  '(:url "mongodb://127.0.0.1/app?compressors=snappy"))
                 '("snappy")))
  (should (equal (mongo--params-compressors
                  '(:url "mongodb://127.0.0.1/app?compressors=zlib"))
                 '("zlib")))
  (if (mongo--zstd-available-p)
      (should (equal (mongo--params-compressors
                      '(:url "mongodb://127.0.0.1/app?compressors=zstd"))
                     '("zstd")))
    (let ((err (should-error
                (mongo--params-compressors
                 '(:url "mongodb://127.0.0.1/app?compressors=zstd"))
                :type 'mongo-error)))
      (should (string-match-p "zstd" (error-message-string err)))))
  (should (equal (mongo--params-compressors
                  '(:compressors ("snappy" "zlib" "noop")))
                 '("snappy" "zlib" "noop"))))



(ert-deftest mongo-test-params-zlib-compression-level ()
  "Native mongo.el should validate standard zlibCompressionLevel options."
  (should-not
   (mongo--params-zlib-compression-level
    '(:url "mongodb://127.0.0.1/app")))
  (should (= (mongo--params-zlib-compression-level
              '(:url
                "mongodb://127.0.0.1/app?zlibCompressionLevel=0"))
             0))
  (should (= (mongo--params-zlib-compression-level
              '(:zlib-compression-level 6))
             6))
  (should (equal (mongo--params-compressors
                  '(:url
                    "mongodb://127.0.0.1/app?compressors=zlib&zlibCompressionLevel=0"))
                 '("zlib")))
  (dolist (level '("-2" "10"))
    (let ((err (should-error
                (mongo--params-zlib-compression-level
                 `(:url
                   ,(format
                     "mongodb://127.0.0.1/app?zlibCompressionLevel=%s"
                     level)))
                :type 'mongo-error)))
      (should (string-match-p "zlibCompressionLevel"
                              (error-message-string err)))))
  (let ((err (should-error
              (mongo--params-compressors
               '(:url
                 "mongodb://127.0.0.1/app?compressors=zlib&zlibCompressionLevel=9"))
              :type 'mongo-error)))
    (should (string-match-p "zlibCompressionLevel"
                            (error-message-string err)))))



(ert-deftest mongo-test-negotiated-compressors-preserve-request-order ()
  "Negotiated MongoDB compressors should preserve client preference order."
  (should (equal (mongo--negotiated-compressors
                  '("snappy" "zstd" "zlib" "noop")
                  ["noop" "zlib" "zstd" "snappy"])
                 '("snappy" "zstd" "zlib" "noop")))
  (should (equal (mongo--negotiated-compressors
                  '("zlib" "noop")
                  '("noop"))
                 '("noop")))
  (should-not (mongo--negotiated-compressors
               '("zlib")
               nil)))



(ert-deftest mongo-test-params-compressors-reject-unavailable-zstd ()
  "Native mongo.el should reject zstd compression when zstd is unavailable."
  (let ((mongo-zstd-program nil))
    (let ((err (should-error
                (mongo--params-compressors
                 '(:url "mongodb://127.0.0.1/app?compressors=zstd"))
                :type 'mongo-error)))
      (should (string-match-p "zstd"
                              (error-message-string err))))))



(ert-deftest mongo-test-params-compressors-reject-unknown ()
  "Native mongo.el should reject unknown wire compressors."
  (let ((err (should-error
              (mongo--params-compressors
               '(:url "mongodb://127.0.0.1/app?compressors=brotli"))
              :type 'mongo-error)))
    (should (string-match-p "brotli"
                            (error-message-string err)))))



(ert-deftest mongo-test-params-read-preference-parses-uri ()
  "Native mongo.el should parse URI readPreference options."
  (let ((read-preference
         (mongo--params-read-preference
          '(:url
            "mongodb://mongo-a/app?readPreference=secondaryPreferred&maxStalenessSeconds=120&readPreferenceTags=dc:ny,rack:1&readPreferenceTags="))))
    (should (equal (mongo--read-preference-mode read-preference)
                   "secondaryPreferred"))
    (should (= (mongo--read-preference-max-staleness-seconds
                read-preference)
               120))
    (should (= (length (mongo--read-preference-tags read-preference))
               2))
    (should (equal (aref (mongo--read-preference-tags read-preference) 0)
                   '(("dc" . "ny")
                     ("rack" . "1"))))
    (should (equal (aref (mongo--read-preference-tags read-preference) 1)
                   (mongo-document nil)))))



(ert-deftest mongo-test-params-read-preference-rejects-primary-tags ()
  "Native mongo.el should reject illegal primary read preference tag options."
  (let ((err (should-error
              (mongo--params-read-preference
               '(:read-preference primary
                 :read-preference-tags ((("dc" . "ny")))))
              :type 'mongo-error)))
    (should (string-match-p "readPreference=primary"
                            (error-message-string err)))))



(ert-deftest mongo-test-params-read-preference-max-staleness-rules ()
  "Native mongo.el should follow MongoDB maxStalenessSeconds rules."
  (let ((read-preference
         (mongo--params-read-preference
          '(:url
            "mongodb://mongo-a/app?readPreference=secondary&maxStalenessSeconds=-1"))))
    (should-not
     (mongo--read-preference-max-staleness-seconds read-preference)))
  (dolist (value '("0" "89" "-2"))
    (let ((err (should-error
                (mongo--params-read-preference
                 `(:url
                   ,(format "mongodb://mongo-a/app?readPreference=secondary&maxStalenessSeconds=%s"
                            value)))
                :type 'mongo-error)))
      (should (string-match-p "maxStalenessSeconds"
                              (error-message-string err)))))
  (let ((err (should-error
              (mongo--params-read-preference
               '(:url
                 "mongodb://mongo-a/app?readPreference=secondary&heartbeatFrequencyMS=95000&maxStalenessSeconds=90"))
              :type 'mongo-error)))
    (should (string-match-p "heartbeatFrequencyMS"
                            (error-message-string err)))))



(ert-deftest mongo-test-params-read-write-concern-parse-uri ()
  "Native mongo.el should parse readConcern/writeConcern URI options."
  (let* ((params
          '(:url
            "mongodb://mongo-a/app?readConcernLevel=majority&w=2&wTimeoutMS=5000&journal=true"))
         (read-concern (mongo--params-read-concern params))
         (write-concern (mongo--params-write-concern params)))
    (should (equal (mongo--read-concern-document read-concern)
                   '(("level" . "majority"))))
    (should (equal (mongo--write-concern-document write-concern)
                   '(("w" . 2)
                     ("wtimeout" . 5000)
                     ("j" . t)))))
  (should (equal (mongo--write-concern-document
                  (mongo--params-write-concern '(:journal nil)))
                 '(("j" . :false)))))



(ert-deftest mongo-test-params-write-concern-rejects-negative-timeout ()
  "Native mongo.el should reject negative writeConcern timeouts."
  (let ((err (should-error
              (mongo--params-write-concern '(:w-timeout-ms -1))
              :type 'mongo-error)))
    (should (string-match-p "wTimeoutMS"
                            (error-message-string err)))))



(ert-deftest mongo-test-params-write-concern-rejects-invalid-journal ()
  "Native mongo.el should reject invalid journal booleans."
  (let ((err (should-error
              (mongo--params-write-concern
               '(:url "mongodb://mongo-a/app?journal=maybe"))
              :type 'mongo-error)))
    (should (string-match-p "journal"
                            (error-message-string err)))))



(ert-deftest mongo-test-params-server-api-requires-version ()
  "Stable API strict/deprecation flags should require an API version."
  (let ((err (should-error
              (mongo--params-server-api '(:api-strict t))
              :type 'mongo-error)))
    (should (string-match-p "Stable API requires"
                            (error-message-string err)))))



(ert-deftest mongo-test-params-load-balanced-validated ()
  "Native mongo.el should validate loadBalanced URI constraints."
  (should (mongo--params-load-balanced-p
           '(:url "mongodb://lb.example.test/app?loadBalanced=true")))
  (dolist (case '(("mongodb://a.example.test,b.example.test/app?loadBalanced=true"
                   . "exactly one host")
                  ("mongodb://lb.example.test/app?loadBalanced=true&replicaSet=rs0"
                   . "replicaSet")
                  ("mongodb://lb.example.test/app?loadBalanced=true&directConnection=true"
                   . "directConnection")
                  ("mongodb://lb.example.test/app?loadBalanced=true&srvMaxHosts=1"
                   . "srvMaxHosts")))
    (let ((err (should-error
                (mongo-connect `(:url ,(car case)))
                :type 'mongo-error)))
      (should (string-match-p (cdr case)
                              (error-message-string err))))))



(ert-deftest mongo-test-params-load-balanced-srv-conflict-preflights ()
  "loadBalanced SRV conflicts that need no DNS should fail before DNS lookup."
  (let (dns-called)
    (cl-letf (((symbol-function 'dns-query)
               (lambda (&rest _)
                 (setq dns-called t)
                 (ert-fail "loadBalanced/srvMaxHosts conflict should not query DNS"))))
      (let ((err (should-error
                  (mongo-connect
                   '(:url
                     "mongodb+srv://cluster.example.com/app?loadBalanced=true&srvMaxHosts=1"))
                  :type 'mongo-error)))
        (should (string-match-p "srvMaxHosts"
                                (error-message-string err)))
        (should-not dns-called)))))



(ert-deftest mongo-test-params-endpoints-parse-srv-uri ()
  "Native mongo.el should resolve MongoDB SRV seed lists and TXT options."
  (let ((txt "authSource=admin&replicaSet=rs0")
        (mongo--srv-resolution-cache nil))
    (cl-letf (((symbol-function 'dns-query)
               (lambda (name type &optional full _reverse)
                 (should full)
                 (cond
                  ((and (equal name "_mongodb._tcp.cluster.example.com")
                        (eq type 'SRV))
                   '((response-code no-error)
                     (answers
                      (("_mongodb._tcp.cluster.example.com"
                        (type SRV) (class IN) (ttl 60)
                        (data ((priority 1)
                               (weight 0)
                               (port 27018)
                               (target "db2.example.com."))))
                       ("_mongodb._tcp.cluster.example.com"
                        (type SRV) (class IN) (ttl 60)
                        (data ((priority 0)
                               (weight 0)
                               (port 27017)
                               (target "db1.example.com."))))))))
                  ((and (equal name "cluster.example.com")
                        (eq type 'TXT))
                   `((response-code no-error)
                     (answers
                      (("cluster.example.com"
                        (type TXT) (class IN) (ttl 60)
                        (data ,(concat (string (length txt)) txt)))))))
                  (t
                   '((response-code name-error)
                     (answers nil)))))))
      (let* ((params '(:url "mongodb+srv://user:secret@cluster.example.com/app"))
             (credential (mongo--params-credential params))
             (endpoints (mongo--params-endpoints params)))
        (should (equal endpoints
                       '(("db1.example.com" 27017 "app")
                         ("db2.example.com" 27018 "app"))))
        (should (equal (mongo--credential-source credential) "admin"))
        (should (equal (mongo--params-replica-set-name params) "rs0"))
        (should (mongo--params-tls-enabled-p params))))))



(ert-deftest mongo-test-params-srv-uri-service-and-max-hosts ()
  "Native mongo.el should honor srvServiceName and srvMaxHosts."
  (let ((mongo--srv-resolution-cache nil))
    (cl-letf (((symbol-function 'dns-query)
               (lambda (name type &optional _full _reverse)
                 (cond
                  ((and (equal name "_custom._tcp.cluster.example.com")
                        (eq type 'SRV))
                   '((response-code no-error)
                     (answers
                      (("_custom._tcp.cluster.example.com"
                        (type SRV) (class IN) (ttl 60)
                        (data ((priority 0)
                               (weight 0)
                               (port 27017)
                               (target "db1.example.com."))))
                       ("_custom._tcp.cluster.example.com"
                        (type SRV) (class IN) (ttl 60)
                        (data ((priority 1)
                               (weight 0)
                               (port 27018)
                               (target "db2.example.com."))))))))
                  (t
                   '((response-code no-error)
                     (answers nil)))))))
      (let* ((params
              '(:url
                "mongodb+srv://cluster.example.com/app?srvServiceName=custom&srvMaxHosts=1"))
             (endpoints (mongo--params-endpoints params)))
        (should (equal endpoints
                       '(("db1.example.com" 27017 "app"))))
        (should (equal (mongo--params-srv-service-name params) "custom"))
        (should (= (mongo--params-srv-max-hosts params) 1))))))



(ert-deftest mongo-test-params-srv-uri-validates-service-and-max-hosts ()
  "Native mongo.el should validate SRV-specific connection options."
  (should-not (mongo--params-srv-max-hosts
               '(:url "mongodb+srv://cluster.example.com/app?srvMaxHosts=0")))
  (should-error
   (mongo--params-srv-max-hosts
    '(:url "mongodb+srv://cluster.example.com/app?srvMaxHosts=-1"))
   :type 'mongo-error)
  (should-error
   (mongo--params-srv-service-name
    '(:url "mongodb+srv://cluster.example.com/app?srvServiceName=bad.name"))
   :type 'mongo-error))



(ert-deftest mongo-test-params-srv-max-hosts-rejects-replica-set ()
  "srvMaxHosts should not be used with replicaSet, including SRV TXT records."
  (let (dns-called)
    (cl-letf (((symbol-function 'dns-query)
               (lambda (&rest _)
                 (setq dns-called t)
                 (ert-fail "raw srvMaxHosts/replicaSet conflict should not query DNS"))))
      (let ((err (should-error
                  (mongo-connect
                   '(:url
                     "mongodb+srv://cluster.example.com/app?srvMaxHosts=1&replicaSet=rs0"))
                  :type 'mongo-error)))
        (should (string-match-p "replicaSet"
                                (error-message-string err)))
        (should-not dns-called))))
  (let ((txt "replicaSet=rs0")
        (mongo--srv-resolution-cache nil))
    (cl-letf (((symbol-function 'dns-query)
               (lambda (name type &optional _full _reverse)
                 (cond
                  ((and (equal name "_mongodb._tcp.cluster.example.com")
                        (eq type 'SRV))
                   '((response-code no-error)
                     (answers
                      (("_mongodb._tcp.cluster.example.com"
                        (type SRV) (class IN) (ttl 60)
                        (data ((priority 0)
                               (weight 0)
                               (port 27017)
                               (target "db1.example.com."))))))))
                  ((and (equal name "cluster.example.com")
                        (eq type 'TXT))
                   `((response-code no-error)
                     (answers
                      (("cluster.example.com"
                        (type TXT) (class IN) (ttl 60)
                        (data ,(concat (string (length txt)) txt)))))))
                  (t
                   '((response-code name-error)
                     (answers nil)))))))
      (let ((err (should-error
                  (mongo-connect
                   '(:url
                     "mongodb+srv://cluster.example.com/app?srvMaxHosts=1"))
                  :type 'mongo-error)))
        (should (string-match-p "replicaSet"
                                (error-message-string err)))))))



(ert-deftest mongo-test-params-srv-uri-tls-can-be-disabled ()
  "Native mongo.el should allow mongodb+srv TLS to be disabled explicitly."
  (let ((mongo--srv-resolution-cache nil))
    (cl-letf (((symbol-function 'dns-query)
               (lambda (name type &optional _full _reverse)
                 (cond
                  ((and (equal name "_mongodb._tcp.cluster.example.com")
                        (eq type 'SRV))
                   '((response-code no-error)
                     (answers
                      (("_mongodb._tcp.cluster.example.com"
                        (type SRV) (class IN) (ttl 60)
                        (data ((priority 0)
                               (weight 0)
                               (port 27017)
                               (target "db1.example.com."))))))))
                  (t
                   '((response-code no-error)
                     (answers nil)))))))
      (should-not
       (mongo--params-tls-enabled-p
        '(:url "mongodb+srv://cluster.example.com/app?tls=false"))))))



(ert-deftest mongo-test-params-srv-uri-rejects-invalid-records ()
  "Native mongo.el should reject invalid MongoDB SRV DNS responses."
  (let ((mongo--srv-resolution-cache nil))
    (cl-letf (((symbol-function 'dns-query)
               (lambda (name type &optional _full _reverse)
                 (cond
                  ((and (equal name "_mongodb._tcp.cluster.example.com")
                        (eq type 'SRV))
                   '((response-code no-error)
                     (answers
                      (("_mongodb._tcp.cluster.example.com"
                        (type SRV) (class IN) (ttl 60)
                        (data ((priority 0)
                               (weight 0)
                               (port 27017)
                               (target "db1.bad.example.net."))))))))
                  (t
                   '((response-code no-error)
                     (answers nil)))))))
      (let ((err (should-error
                  (mongo--params-endpoints
                   '(:url "mongodb+srv://cluster.example.com/app"))
                  :type 'mongo-error)))
        (should (string-match-p "outside parent domain"
                                (error-message-string err)))))))



(ert-deftest mongo-test-params-srv-uri-rejects-port ()
  "Native mongo.el should reject mongodb+srv URLs with an explicit port."
  (let ((err (should-error
              (mongo--params-endpoints
               '(:url "mongodb+srv://cluster.example.com:27017/app"))
              :type 'mongo-error)))
    (should (string-match-p "no port"
                            (error-message-string err)))))



(ert-deftest mongo-test-params-tls-from-url ()
  "Native mongo.el should treat MongoDB TLS URI options as TLS settings."
  (let* ((params '(:url "mongodb://db.example.test/app?tls=true&tlsAllowInvalidHostnames=true&tlsCAFile=/tmp/ca.pem"))
         (spec (mongo--params-tls-spec params "db.example.test")))
    (should (mongo--params-tls-enabled-p params))
    (should (equal (plist-get spec :hostname) "db.example.test"))
    (should (equal (plist-get spec :trustfiles) '("/tmp/ca.pem")))
    (should (equal (plist-get spec :verify-error) '(:trustfiles)))
    (should-not (plist-get spec :verify-hostname-error)))
  (let* ((params '(:url "mongodb://db.example.test/app?tls=true&tlsInsecure=true&tlsCAFile=/tmp/ca.pem"))
         (spec (mongo--params-tls-spec params "db.example.test")))
    (should (equal (plist-get spec :trustfiles) '("/tmp/ca.pem")))
    (should-not (plist-get spec :verify-error))
    (should-not (plist-get spec :verify-hostname-error)))
  (should (mongo--params-tls-enabled-p
           '(:url "mongodb://db.example.test/app?ssl=true"))))



(ert-deftest mongo-test-params-tls-verify-can-be-disabled ()
  "Native MongoDB TLS should allow explicit verification opt-out for local certs."
  (let ((spec (mongo--params-tls-spec
               '(:host "127.0.0.1" :tls t :tls-verify nil)
               "127.0.0.1")))
    (should (equal (plist-get spec :hostname) "127.0.0.1"))
    (should-not (plist-get spec :verify-error))
    (should-not (plist-get spec :verify-hostname-error))))



(ert-deftest mongo-test-connect-rejects-direct-multiple-seeds ()
  "Native mongo.el should not silently ignore seeds with directConnection=true."
  (let ((err (should-error
              (mongo-connect
               '(:url "mongodb://mongo-a,mongo-b/app?directConnection=true"))
              :type 'mongo-error)))
    (should (string-match-p "exactly one host"
                            (error-message-string err)))))



(ert-deftest mongo-test-connect-selects-replica-primary ()
  "Native mongo.el should follow replica-set hello data to the writable primary."
  (let (calls disconnected authenticated)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (_params host port database credential authenticate)
                 (push (list host port database
                             (and credential
                                  (mongo--credential-username credential))
                             authenticate)
                       calls)
                 (pcase host
                   ("seed-a"
                    (cons 'conn-a
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("isWritablePrimary" . :false)
                            ("primary" . "seed-b:27018")
                            ("hosts" . ("seed-a:27017"
                                        "seed-b:27018")))))
                   ("seed-b"
                    (cons 'conn-b
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("isWritablePrimary" . t))))
                   (_
                    (error "Unexpected seed %s" host)))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected)))
              ((symbol-function 'mongo--authenticate)
               (lambda (conn credential _hello)
                 (push (list conn
                             (mongo--credential-username credential))
                       authenticated))))
      (should (eq (mongo-connect
                   '(:url "mongodb://user:secret@seed-a/app?replicaSet=rs0"))
                  'conn-b)))
    (should (equal (nreverse calls)
                   '(("seed-a" 27017 "app" "user" nil)
                     ("seed-b" 27018 "app" "user" nil))))
    (should (equal disconnected '(conn-a)))
    (should (equal authenticated '((conn-b "user"))))))



(ert-deftest mongo-test-connect-skips-replica-seed-alias-by-me ()
  "Replica discovery should follow hosts when a seed's me is canonical."
  (let (calls disconnected)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (_params host port database _credential authenticate)
                 (push (list host port database authenticate) calls)
                 (pcase host
                   ("alias"
                    (cons 'conn-alias
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("isWritablePrimary" . t)
                            ("me" . "canonical:27017")
                            ("hosts" . ("canonical:27017")))))
                   ("canonical"
                    (cons 'conn-canonical
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("isWritablePrimary" . t)
                            ("me" . "canonical:27017")
                            ("hosts" . ("canonical:27017")))))
                   (_
                    (error "Unexpected seed %s" host)))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (should (eq (mongo-connect
                   '(:url
                     "mongodb://alias:27021/app?replicaSet=rs0"))
                  'conn-canonical)))
    (should (equal (nreverse calls)
                   '(("alias" 27021 "app" nil)
                     ("canonical" 27017 "app" nil))))
    (should (equal disconnected '(conn-alias)))))



(ert-deftest mongo-test-connect-falls-back-to-reachable-seed-alias ()
  "Replica discovery should retain a reachable seed alias if canonical hosts fail."
  (let (calls disconnected)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (_params host port database _credential authenticate)
                 (push (list host port database authenticate) calls)
                 (pcase host
                   ("alias"
                    (cons 'conn-alias
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("isWritablePrimary" . t)
                            ("me" . "canonical:27017")
                            ("hosts" . ("canonical:27017")))))
                   ("canonical"
                    (signal 'mongo-error (list "Connection refused")))
                   (_
                    (error "Unexpected seed %s" host)))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (should (eq (mongo-connect
                   '(:url
                     "mongodb://alias:27021/app?replicaSet=rs0"))
                  'conn-alias)))
    (should (equal (nreverse calls)
                   '(("alias" 27021 "app" nil)
                     ("canonical" 27017 "app" nil))))
    (should-not disconnected)))



(ert-deftest mongo-test-connect-rejects-replica-seed-alias-without-hosts ()
  "Replica discovery should reject a seed whose me cannot be followed."
  (let (disconnected)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (_params host port database _credential authenticate)
                 (should (equal (list host port database authenticate)
                                '("alias" 27021 "app" nil)))
                 (cons 'conn-alias
                       '(("ok" . 1)
                         ("maxWireVersion" . 17)
                         ("setName" . "rs0")
                         ("isWritablePrimary" . t)
                         ("me" . "canonical:27017")
                         ("hosts" . ("alias:27021"))))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (let ((err (should-error
                  (mongo-connect
                   '(:url
                     "mongodb://alias:27021/app?replicaSet=rs0"))
                  :type 'mongo-error)))
        (should (string-match-p "canonical replica-set member canonical:27017"
                                (error-message-string err)))))
    (should (equal disconnected '(conn-alias)))))



(ert-deftest mongo-test-connect-hidden-seed-discovers-primary ()
  "Replica discovery should use hidden members for hosts, not selection."
  (let (calls disconnected)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (_params host port database _credential authenticate)
                 (push (list host port database authenticate) calls)
                 (pcase host
                   ("hidden"
                    (cons 'conn-hidden
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("secondary" . t)
                            ("hidden" . t)
                            ("hosts" . ("hidden:27018"
                                        "primary:27017")))))
                   ("primary"
                    (cons 'conn-primary
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("isWritablePrimary" . t))))
                   (_
                    (error "Unexpected seed %s" host)))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (should (eq (mongo-connect
                   '(:url "mongodb://hidden:27018/app?replicaSet=rs0"))
                  'conn-primary)))
    (should (equal (nreverse calls)
                   '(("hidden" 27018 "app" nil)
                     ("primary" 27017 "app" nil))))
    (should (equal disconnected '(conn-hidden)))))



(ert-deftest mongo-test-connect-arbiter-can-discover-primary ()
  "Replica discovery should queue arbiters because they can reveal members."
  (let (calls disconnected)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (_params host port database _credential authenticate)
                 (push (list host port database authenticate) calls)
                 (pcase host
                   ("secondary"
                    (cons 'conn-secondary
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("secondary" . t)
                            ("hosts" . ("secondary:27018"))
                            ("arbiters" . ("arbiter:27019")))))
                   ("arbiter"
                    (cons 'conn-arbiter
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("arbiterOnly" . t)
                            ("hosts" . ("secondary:27018"
                                        "primary:27017"))
                            ("arbiters" . ("arbiter:27019")))))
                   ("primary"
                    (cons 'conn-primary
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("isWritablePrimary" . t))))
                   (_
                    (error "Unexpected seed %s" host)))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (should (eq (mongo-connect
                   '(:url "mongodb://secondary:27018/app?replicaSet=rs0"))
                  'conn-primary)))
    (should (equal (nreverse calls)
                   '(("secondary" 27018 "app" nil)
                     ("arbiter" 27019 "app" nil)
                     ("primary" 27017 "app" nil))))
    (should (equal disconnected '(conn-arbiter conn-secondary)))))



(ert-deftest mongo-test-connect-selects-replica-secondary-for-read-preference ()
  "Native mongo.el should prefer a secondary when readPreference allows it."
  (let (calls disconnected authenticated)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (_params host port database credential authenticate)
                 (push (list host port database
                             (and credential
                                  (mongo--credential-username credential))
                             authenticate)
                       calls)
                 (pcase host
                   ("seed-a"
                    (cons 'conn-a
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("isWritablePrimary" . t)
                            ("hosts" . ("seed-a:27017"
                                        "seed-b:27018")))))
                   ("seed-b"
                    (cons 'conn-b
                          '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("secondary" . t))))
                   (_
                    (error "Unexpected seed %s" host)))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected)))
              ((symbol-function 'mongo--authenticate)
               (lambda (conn credential _hello)
                 (push (list conn
                             (mongo--credential-username credential))
                       authenticated))))
      (should (eq (mongo-connect
                   '(:url
                     "mongodb://user:secret@seed-a/app?replicaSet=rs0&readPreference=secondaryPreferred"))
                  'conn-b)))
    (should (equal (nreverse calls)
                   '(("seed-a" 27017 "app" "user" nil)
                     ("seed-b" 27018 "app" "user" nil))))
    (should (equal disconnected '(conn-a)))
    (should (equal authenticated '((conn-b "user"))))))



(ert-deftest mongo-test-connect-server-selection-try-once-default ()
  "Replica discovery should scan once by default when no server matches."
  (let (calls disconnected slept)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (_params host port database _credential _authenticate)
                 (push (list host port database) calls)
                 (cons 'conn-secondary
                       '(("ok" . 1)
                         ("maxWireVersion" . 17)
                         ("setName" . "rs0")
                         ("secondary" . t)
                         ("hosts" . ("seed:27017"))))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected)))
              ((symbol-function 'sleep-for)
               (lambda (&rest _args)
                 (setq slept t))))
      (let ((err (should-error
                  (mongo--connect-replica-server
                   '(:replica-set "rs0"
                     :server-selection-timeout 1)
                   '(("seed" 27017 "app"))
                   nil)
                  :type 'mongo-error)))
        (should (string-match-p "readPreference=primary"
                                (error-message-string err)))))
    (should (equal (nreverse calls)
                   '(("seed" 27017 "app"))))
    (should (equal disconnected '(conn-secondary)))
    (should-not slept)))



(ert-deftest mongo-test-connect-server-selection-try-once-false-rescans ()
  "serverSelectionTryOnce=false should rescan known endpoints before timeout."
  (let ((attempt 0)
        calls disconnected slept)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (_params host port database _credential _authenticate)
                 (cl-incf attempt)
                 (push (list host port database) calls)
                 (if (= attempt 1)
                     (cons 'conn-secondary
                           '(("ok" . 1)
                             ("maxWireVersion" . 17)
                             ("setName" . "rs0")
                             ("secondary" . t)
                             ("hosts" . ("seed:27017"))))
                   (cons 'conn-primary
                         '(("ok" . 1)
                           ("maxWireVersion" . 17)
                           ("setName" . "rs0")
                           ("isWritablePrimary" . t))))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected)))
              ((symbol-function 'sleep-for)
               (lambda (&rest _args)
                 (setq slept t))))
      (should (eq (mongo--connect-replica-server
                   '(:replica-set "rs0"
                     :server-selection-try-once nil
                     :server-selection-timeout 1)
                   '(("seed" 27017 "app"))
                   nil)
                  'conn-primary)))
    (should (equal (nreverse calls)
                   '(("seed" 27017 "app")
                     ("seed" 27017 "app"))))
    (should (equal disconnected '(conn-secondary)))
    (should slept)))



(ert-deftest mongo-test-connect-selects-replica-secondary-by-latency-window ()
  "Replica discovery should apply localThresholdMS to matching secondaries."
  (let (calls disconnected fast-conn)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (_params host port database _credential _authenticate)
                 (push (list host port database) calls)
                 (let* ((conn (make-mongo-conn
                               :host host
                               :port port
                               :database database))
                        (hello '(("ok" . 1)
                                 ("maxWireVersion" . 17)
                                 ("setName" . "rs0")
                                 ("secondary" . t)
                                 ("hosts" . ("slow:27017"
                                             "fast:27018"))))
                        (address (mongo--endpoint-key host port))
                        (rtt (pcase host
                               ("fast" 0.003)
                               ("slow" 0.030)))
                        (server (mongo--server-description-from-hello
                                 address hello nil rtt)))
                   (setf (mongo-conn-topology conn)
                         (make-mongo-topology-description
                          :type 'replica-set-no-primary
                          :set-name "rs0"
                          :servers `((,address . ,server))
                          :compatible t))
                   (when (equal host "fast")
                     (setq fast-conn conn))
                   (cons conn hello))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push (mongo-conn-host conn) disconnected))))
      (should
       (eq (mongo--connect-replica-server
            '(:replica-set "rs0"
              :read-preference secondary
              :local-threshold 0.005
              :server-selection-timeout 3)
            '(("slow" 27017 "app")
              ("fast" 27018 "app"))
            nil)
           fast-conn)))
    (should (equal (nreverse calls)
                   '(("slow" 27017 "app")
                     ("fast" 27018 "app"))))
    (should (equal disconnected '("slow")))))



(ert-deftest mongo-test-topology-description-from-primary-hello ()
  "MongoDB hello data should produce a lightweight SDAM topology description."
  (let* ((conn (make-mongo-conn :host "seed-b"
                                :port 27018
                                :database "app"))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("logicalSessionTimeoutMinutes" . 30)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)
                  ("primary" . "seed-b:27018")
                  ("tags" . (("dc" . "ny")
                             ("rack" . "1")))
                  ("lastWrite" .
                   (("lastWriteDate" . (("$date" . 1704164645000)))))
                  ("hosts" . ("seed-a:27017" "seed-b:27018"))
                  ("passives" . ("seed-c:27017"))
                  ("arbiters" . ("seed-d:27017"))))
         (topology (mongo--topology-description-from-hello conn hello))
         (servers (mongo-topology-description-servers topology))
         (primary (cdr (assoc "seed-b:27018" servers)))
         (seed-a (cdr (assoc "seed-a:27017" servers))))
    (should (eq (mongo-topology-description-type topology)
                'replica-set-with-primary))
    (should (equal (mongo-topology-description-set-name topology) "rs0"))
    (should (equal (mongo-topology-description-primary-address topology)
                   "seed-b:27018"))
    (should (= (mongo-topology-description-logical-session-timeout-minutes
                topology)
               30))
    (should (mongo-topology-description-compatible topology))
    (should (eq (mongo-server-description-type primary) 'rs-primary))
    (should (equal (mongo-server-description-tags primary)
                   '(("dc" . "ny")
                     ("rack" . "1"))))
    (should (= (mongo-server-description-last-write-date primary)
               1704164645.0))
    (should (eq (mongo-server-description-type seed-a) 'unknown))
    (should (assoc "seed-c:27017" servers))
    (should (assoc "seed-d:27017" servers))))


(ert-deftest mongo-test-topology-description-readable-writable-server-p ()
  "Topology availability predicates should follow SDAM readability rules."
  (let* ((primary
          (make-mongo-server-description
           :address "primary:27017"
           :type 'rs-primary
           :tags '(("dc" . "east"))
           :max-wire-version 17
           :last-write-date 1000
           :last-update-time 1000))
         (secondary
          (make-mongo-server-description
           :address "secondary:27017"
           :type 'rs-secondary
           :tags '(("dc" . "west"))
           :max-wire-version 17
           :last-write-date 1000
           :last-update-time 1000))
         (mongos
          (make-mongo-server-description
           :address "mongos:27017"
           :type 'mongos))
         (unknown
          (mongo--unknown-server-description "unknown:27017"))
         (rs-with-primary
          (make-mongo-topology-description
           :type 'replica-set-with-primary
           :primary-address "primary:27017"
           :servers `(("primary:27017" . ,primary)
                      ("secondary:27017" . ,secondary))))
         (rs-no-primary
          (make-mongo-topology-description
           :type 'replica-set-no-primary
           :servers `(("secondary:27017" . ,secondary)
                      ("unknown:27017" . ,unknown))))
         (single-secondary
          (make-mongo-topology-description
           :type 'single
           :servers `(("secondary:27017" . ,secondary))))
         (single-unknown
          (make-mongo-topology-description
           :type 'single
           :servers `(("unknown:27017" . ,unknown))))
         (sharded
          (make-mongo-topology-description
           :type 'sharded
           :servers `(("mongos:27017" . ,mongos))))
         (unknown-topology
          (make-mongo-topology-description
           :type 'unknown
           :servers `(("unknown:27017" . ,unknown))))
         (load-balanced
          (make-mongo-topology-description
           :type 'load-balanced))
         (west-secondary
          (mongo--params-read-preference
           '(:read-preference secondary
             :read-preference-tags ((("dc" . "west"))))))
         (east-secondary
          (mongo--params-read-preference
           '(:read-preference secondary
             :read-preference-tags ((("dc" . "east")))))))
    (should (mongo-topology-description-has-readable-server-p
             rs-with-primary))
    (should (mongo-topology-description-has-writable-server-p
             rs-with-primary))
    (should-not (mongo-topology-description-has-readable-server-p
                 rs-no-primary))
    (should (mongo-topology-description-has-readable-server-p
             rs-no-primary "secondary"))
    (should (mongo-topology-description-has-readable-server-p
             rs-no-primary west-secondary))
    (should-not (mongo-topology-description-has-readable-server-p
                 rs-no-primary east-secondary))
    (should-not (mongo-topology-description-has-writable-server-p
                 rs-no-primary))
    (should (mongo-topology-description-has-readable-server-p
             single-secondary))
    (should (mongo-topology-description-has-writable-server-p
             single-secondary))
    (should-not (mongo-topology-description-has-readable-server-p
                 single-unknown))
    (should-not (mongo-topology-description-has-writable-server-p
                 single-unknown))
    (should (mongo-topology-description-has-readable-server-p
             sharded))
    (should (mongo-topology-description-has-writable-server-p
             sharded))
    (should-not (mongo-topology-description-has-readable-server-p
                 unknown-topology))
    (should-not (mongo-topology-description-has-writable-server-p
                 unknown-topology))
    (should (mongo-topology-description-has-readable-server-p
             load-balanced))
    (should (mongo-topology-description-has-writable-server-p
             load-balanced))))



(ert-deftest mongo-test-topology-hidden-secondary-is-rs-other ()
  "Hidden replica-set members should be discoverable but not readable."
  (let* ((conn (make-mongo-conn
                :host "hidden"
                :port 27018
                :database "app"
                :read-preference
                (mongo--params-read-preference '(:read-preference secondary))))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("secondary" . t)
                  ("hidden" . t)
                  ("hosts" . ("primary:27017"
                              "hidden:27018"))))
         (topology (mongo--topology-description-from-hello conn hello))
         (servers (mongo-topology-description-servers topology))
         (server (cdr (assoc "hidden:27018" servers))))
    (setf (mongo-conn-topology conn) topology)
    (should (eq (mongo-topology-description-type topology)
                'replica-set-no-primary))
    (should (eq (mongo-server-description-type server) 'rs-other))
    (should (assoc "primary:27017" servers))
    (should-not (mongo-select-server conn 'read))))



(ert-deftest mongo-test-topology-rejects-too-old-wire-version ()
  "SDAM compatibility should reject servers older than this OP_MSG client."
  (let* ((conn (make-mongo-conn :host "legacy"
                                :port 27017
                                :database "app"))
         (topology (mongo--topology-description-from-hello
                    conn
                    '(("ok" . 1)
                      ("minWireVersion" . 0)
                      ("maxWireVersion" . 5)
                      ("isWritablePrimary" . t))))
         (error (mongo-topology-description-compatibility-error topology)))
    (should-not (mongo-topology-description-compatible topology))
    (should (string-match-p "reports wire version 5" error))
    (setf (mongo-conn-topology conn) topology)
    (let ((err (should-error (mongo-select-server conn 'write)
                             :type 'mongo-error)))
      (should (string-match-p "requires at least 6"
                              (error-message-string err))))))



(ert-deftest mongo-test-topology-rejects-future-min-wire-version ()
  "SDAM compatibility should reject servers that require a newer client."
  (let* ((future-min (1+ mongo--client-max-wire-version))
         (conn (make-mongo-conn :host "future"
                                :port 27017
                                :database "app"))
         (topology (mongo--topology-description-from-hello
                    conn
                    `(("ok" . 1)
                      ("minWireVersion" . ,future-min)
                      ("maxWireVersion" . ,future-min)
                      ("isWritablePrimary" . t))))
         (error (mongo-topology-description-compatibility-error topology)))
    (should-not (mongo-topology-description-compatible topology))
    (should (string-match-p
             (format "requires wire version %s" future-min)
             error))
    (setf (mongo-conn-topology conn) topology)
    (let ((err (should-error (mongo-select-server conn 'read)
                             :type 'mongo-error)))
      (should (string-match-p "only supports up to"
                              (error-message-string err))))))



(ert-deftest mongo-test-topology-description-tracks-average-rtt ()
  "MongoDB hello refreshes should maintain the SDAM average RTT."
  (let* ((conn (make-mongo-conn :host "seed-b"
                                :port 27018
                                :database "app"))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello 0.100))
    (let ((server (mongo--current-server-description conn)))
      (should (= (mongo-server-description-round-trip-time server)
                 0.100)))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello 0.200))
    (let ((server (mongo--current-server-description conn)))
      (should (< (abs (- (mongo-server-description-round-trip-time server)
                         0.120))
                 0.000001)))))



(ert-deftest mongo-test-topology-secondary-update-preserves-primary ()
  "Secondary SDAM updates should preserve an already known primary."
  (let* ((conn (make-mongo-conn :host "secondary"
                                :port 27018
                                :database "app"))
         (primary (make-mongo-server-description
                   :address "primary:27017"
                   :type 'rs-primary
                   :set-name "rs0"))
         (old-secondary (mongo--unknown-server-description
                         "secondary:27018"))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-with-primary
                        :set-name "rs0"
                        :servers `(("primary:27017" . ,primary)
                                   ("secondary:27018" . ,old-secondary))
                        :primary-address "primary:27017"
                        :compatible t))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("secondary" . t)
                  ("primary" . "primary:27017")
                  ("hosts" . ("primary:27017"
                              "secondary:27018"
                              "new-secondary:27019")))))
    (setf (mongo-conn-topology conn) old-topology)
    (let* ((topology (mongo--topology-description-from-hello conn hello))
           (servers (mongo-topology-description-servers topology))
           (secondary (cdr (assoc "secondary:27018" servers)))
           (new-secondary (cdr (assoc "new-secondary:27019" servers))))
      (should (eq (mongo-topology-description-type topology)
                  'replica-set-with-primary))
      (should (equal (mongo-topology-description-primary-address topology)
                     "primary:27017"))
      (should (eq (cdr (assoc "primary:27017" servers)) primary))
      (should (eq (mongo-server-description-type secondary)
                  'rs-secondary))
      (should (eq (mongo-server-description-type new-secondary)
                  'unknown)))))



(ert-deftest mongo-test-topology-primary-update-prunes-removed-members ()
  "Primary SDAM updates should remove servers absent from the primary host list."
  (let* ((conn (make-mongo-conn :host "primary"
                                :port 27017
                                :database "app"))
         (removed (make-mongo-server-description
                   :address "removed:27019"
                   :type 'rs-secondary
                   :set-name "rs0"))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-with-primary
                        :set-name "rs0"
                        :servers `(("primary:27017" .
                                    ,(mongo--unknown-server-description
                                      "primary:27017"))
                                   ("removed:27019" . ,removed))
                        :primary-address "primary:27017"
                        :compatible t))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)
                  ("hosts" . ("primary:27017"
                              "secondary:27018")))))
    (setf (mongo-conn-topology conn) old-topology)
    (let* ((topology (mongo--topology-description-from-hello conn hello))
           (servers (mongo-topology-description-servers topology))
           (primary (cdr (assoc "primary:27017" servers)))
           (secondary (cdr (assoc "secondary:27018" servers))))
      (should (eq (mongo-topology-description-type topology)
                  'replica-set-with-primary))
      (should (equal (mongo-topology-description-primary-address topology)
                     "primary:27017"))
      (should (eq (mongo-server-description-type primary) 'rs-primary))
      (should (eq (mongo-server-description-type secondary) 'unknown))
      (should-not (assoc "removed:27019" servers)))))



(ert-deftest mongo-test-topology-new-primary-marks-old-primary-unknown ()
  "Primary SDAM updates should mark any previous primary Unknown."
  (let* ((conn (make-mongo-conn :host "new-primary"
                                :port 27018
                                :database "app"))
         (old-primary (make-mongo-server-description
                       :address "old-primary:27017"
                       :type 'rs-primary
                       :set-name "rs0"))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-with-primary
                        :set-name "rs0"
                        :servers `(("old-primary:27017" . ,old-primary)
                                   ("new-primary:27018" .
                                    ,(mongo--unknown-server-description
                                      "new-primary:27018")))
                        :primary-address "old-primary:27017"
                        :compatible t))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)
                  ("hosts" . ("old-primary:27017"
                              "new-primary:27018")))))
    (setf (mongo-conn-topology conn) old-topology)
    (let* ((topology (mongo--topology-description-from-hello conn hello))
           (servers (mongo-topology-description-servers topology))
           (old (cdr (assoc "old-primary:27017" servers)))
           (new (cdr (assoc "new-primary:27018" servers))))
      (should (eq (mongo-topology-description-type topology)
                  'replica-set-with-primary))
      (should (equal (mongo-topology-description-primary-address topology)
                     "new-primary:27018"))
      (should (eq (mongo-server-description-type new) 'rs-primary))
      (should (eq (mongo-server-description-type old) 'unknown))
      (should (string-match-p
               "discovery of newer primary"
               (mongo-server-description-error old))))))



(ert-deftest mongo-test-topology-secondary-primary-address-is-not-known-primary ()
  "A secondary's primary field should not make an unchecked primary selectable."
  (let* ((conn (make-mongo-conn
                :host "secondary"
                :port 27018
                :database "app"
                :read-preference
                (make-mongo--read-preference
                 :mode "primaryPreferred")))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("secondary" . t)
                  ("primary" . "primary:27017")
                  ("hosts" . ("primary:27017"
                              "secondary:27018")))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (should (eq (mongo-topology-description-type
                 (mongo-conn-topology conn))
                'replica-set-no-primary))
    (should-not (mongo-topology-description-primary-address
                 (mongo-conn-topology conn)))
    (should (eq (mongo-select-server conn 'read)
                (mongo--current-server-description conn)))))



(ert-deftest mongo-test-topology-ignores-stale-topology-version ()
  "Older topologyVersion hello data should not replace a newer description."
  (let* ((conn (make-mongo-conn :host "primary"
                                :port 27017
                                :database "app"))
         (old-version `(("processId" .
                         ,(mongo-object-id
                           "64f000000000000000000001"))
                        ("counter" . 8)))
         (new-version `(("processId" .
                         ,(mongo-object-id
                           "64f000000000000000000001"))
                        ("counter" . 7)))
         (server (make-mongo-server-description
                  :address "primary:27017"
                  :type 'rs-primary
                  :set-name "rs0"
                  :tags '(("version" . "old"))
                  :topology-version old-version))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-with-primary
                        :set-name "rs0"
                        :servers `(("primary:27017" . ,server))
                        :primary-address "primary:27017"
                        :compatible t))
         (hello `(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)
                  ("tags" . (("version" . "new")))
                  ("topologyVersion" . ,new-version))))
    (setf (mongo-conn-topology conn) old-topology)
    (should (eq (mongo--topology-description-from-hello conn hello)
                old-topology))
    (should (equal (mongo-server-description-tags
                    (mongo--current-server-description conn))
                   '(("version" . "old"))))))



(ert-deftest mongo-test-topology-rejects-stale-primary-election-id ()
  "Modern SDAM should reject an RSPrimary with an older electionId."
  (let* ((conn (make-mongo-conn :host "old-primary"
                                :port 27017
                                :database "app"))
         (max-election "000000000000000000000002")
         (new-primary (make-mongo-server-description
                       :address "new-primary:27018"
                       :type 'rs-primary
                       :set-name "rs0"
                       :election-id (mongo-object-id max-election)
                       :set-version 4))
         (old-primary (mongo--unknown-server-description
                       "old-primary:27017"))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-with-primary
                        :set-name "rs0"
                        :servers `(("new-primary:27018" . ,new-primary)
                                   ("old-primary:27017" . ,old-primary))
                        :primary-address "new-primary:27018"
                        :max-election-id max-election
                        :max-set-version 4
                        :compatible t))
         (hello `(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)
                  ("electionId" .
                   ,(mongo-object-id "000000000000000000000001"))
                  ("setVersion" . 4)
                  ("hosts" . ("new-primary:27018"
                              "old-primary:27017")))))
    (setf (mongo-conn-topology conn) old-topology)
    (let* ((topology (mongo--topology-description-from-hello conn hello))
           (servers (mongo-topology-description-servers topology))
           (old (cdr (assoc "old-primary:27017" servers))))
      (should (eq (mongo-topology-description-type topology)
                  'replica-set-with-primary))
      (should (equal (mongo-topology-description-primary-address topology)
                     "new-primary:27018"))
      (should (equal (mongo-topology-description-max-election-id topology)
                     max-election))
      (should (= (mongo-topology-description-max-set-version topology) 4))
      (should (eq (mongo-server-description-type old) 'unknown))
      (should (string-match-p
               "Stale primary"
               (mongo-server-description-error old))))))



(ert-deftest mongo-test-topology-updates-primary-version-max ()
  "A newer RSPrimary should update the remembered electionId/setVersion tuple."
  (let* ((conn (make-mongo-conn :host "new-primary"
                                :port 27018
                                :database "app"))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-with-primary
                        :set-name "rs0"
                        :servers nil
                        :primary-address nil
                        :max-election-id
                        "000000000000000000000001"
                        :max-set-version 10
                        :compatible t))
         (hello `(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)
                  ("electionId" .
                   ,(mongo-object-id "000000000000000000000002"))
                  ("setVersion" . 1)
                  ("hosts" . ("new-primary:27018")))))
    (setf (mongo-conn-topology conn) old-topology)
    (let ((topology (mongo--topology-description-from-hello conn hello)))
      (should (equal (mongo-topology-description-primary-address topology)
                     "new-primary:27018"))
      (should (equal (mongo-topology-description-max-election-id topology)
                     "000000000000000000000002"))
      (should (= (mongo-topology-description-max-set-version topology) 1)))))



(ert-deftest mongo-test-topology-legacy-stale-primary-order ()
  "Pre-6.0 SDAM compatibility should compare setVersion before electionId."
  (let* ((conn (make-mongo-conn :host "legacy-primary"
                                :port 27017
                                :database "app"))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-with-primary
                        :set-name "rs0"
                        :servers nil
                        :primary-address nil
                        :max-election-id
                        "000000000000000000000001"
                        :max-set-version 5
                        :compatible t))
         (hello `(("ok" . 1)
                  ("maxWireVersion" . 16)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)
                  ("electionId" .
                   ,(mongo-object-id "000000000000000000000002"))
                  ("setVersion" . 4)
                  ("hosts" . ("legacy-primary:27017")))))
    (setf (mongo-conn-topology conn) old-topology)
    (let* ((topology (mongo--topology-description-from-hello conn hello))
           (server (cdr (assoc "legacy-primary:27017"
                               (mongo-topology-description-servers
                                topology)))))
      (should (eq (mongo-topology-description-type topology)
                  'replica-set-no-primary))
      (should-not (mongo-topology-description-primary-address topology))
      (should (eq (mongo-server-description-type server) 'unknown))
      (should (equal (mongo-topology-description-max-election-id topology)
                     "000000000000000000000001"))
      (should (= (mongo-topology-description-max-set-version topology) 5)))))



(ert-deftest mongo-test-topology-ignores-secondary-set-version ()
  "SDAM should not update max election/set version from non-primary hello."
  (let* ((conn (make-mongo-conn :host "secondary"
                                :port 27018
                                :database "app"))
         (hello `(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("secondary" . t)
                  ("electionId" .
                   ,(mongo-object-id "0000000000000000000000ff"))
                  ("setVersion" . 99)
                  ("hosts" . ("primary:27017"
                              "secondary:27018")))))
    (let ((topology (mongo--topology-description-from-hello conn hello)))
      (should (eq (mongo-topology-description-type topology)
                  'replica-set-no-primary))
      (should-not (mongo-topology-description-max-election-id topology))
      (should-not (mongo-topology-description-max-set-version topology)))))



(ert-deftest mongo-test-topology-rsghost-initial-remains-unknown ()
  "Initial SDAM Unknown topology should remain Unknown for RSGhost servers."
  (let* ((conn (make-mongo-conn :host "ghost"
                                :port 27017
                                :database "app"))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("isreplicaset" . t)))
         (topology (mongo--topology-description-from-hello conn hello))
         (server (cdr (assoc "ghost:27017"
                             (mongo-topology-description-servers topology)))))
    (should (eq (mongo-topology-description-type topology) 'unknown))
    (should-not (mongo-topology-description-set-name topology))
    (should-not (mongo-topology-description-primary-address topology))
    (should (eq (mongo-server-description-type server) 'rs-ghost))))



(ert-deftest mongo-test-topology-rsghost-keeps-replica-set-state ()
  "RSGhost updates should not collapse an existing replica-set topology."
  (let* ((conn (make-mongo-conn :host "ghost"
                                :port 27017
                                :database "app"))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-no-primary
                        :set-name "rs0"
                        :servers `(("ghost:27017" .
                                    ,(mongo--unknown-server-description
                                      "ghost:27017"))
                                   ("secondary:27018" .
                                    ,(make-mongo-server-description
                                      :address "secondary:27018"
                                      :type 'rs-secondary
                                      :set-name "rs0")))
                        :compatible t))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("isreplicaset" . t))))
    (setf (mongo-conn-topology conn) old-topology)
    (let* ((topology (mongo--topology-description-from-hello conn hello))
           (server (cdr (assoc "ghost:27017"
                               (mongo-topology-description-servers
                                topology)))))
      (should (eq (mongo-topology-description-type topology)
                  'replica-set-no-primary))
      (should (equal (mongo-topology-description-set-name topology) "rs0"))
      (should (eq (mongo-server-description-type server) 'rs-ghost))
      (should (assoc "secondary:27018"
                     (mongo-topology-description-servers topology))))))



(ert-deftest mongo-test-topology-direct-rsghost-is-single ()
  "directConnection=true should use Single topology for an RSGhost server."
  (let* ((conn (make-mongo-conn
                :host "ghost"
                :port 27017
                :database "app"
                :params '(:url
                          "mongodb://ghost:27017/app?directConnection=true")))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("isreplicaset" . t)))
         (topology (mongo--topology-description-from-hello conn hello))
         (server (cdr (assoc "ghost:27017"
                             (mongo-topology-description-servers
                              topology)))))
    (setf (mongo-conn-topology conn) topology)
    (should (eq (mongo-topology-description-type topology) 'single))
    (should (eq (mongo-server-description-type server) 'rs-ghost))
    (should (eq (mongo-select-server conn 'read) server))
    (should (eq (mongo-select-server conn 'write) server))))



(ert-deftest mongo-test-topology-direct-secondary-is-single ()
  "directConnection=true should use Single topology for a replica-set member."
  (let* ((conn (make-mongo-conn
                :host "seed-a"
                :port 27018
                :database "app"
                :params '(:url
                          "mongodb://seed-a:27018/app?directConnection=true")))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("secondary" . t)))
         (topology (mongo--topology-description-from-hello conn hello))
         (server (cdr (assoc "seed-a:27018"
                             (mongo-topology-description-servers
                              topology)))))
    (setf (mongo-conn-topology conn) topology)
    (should (eq (mongo-topology-description-type topology) 'single))
    (should (eq (mongo-server-description-type server) 'rs-secondary))
    (should (eq (mongo-select-server conn 'read) server))
    (should (eq (mongo-select-server conn 'write) server))))



(ert-deftest mongo-test-topology-direct-replica-set-name-matches ()
  "Single topology should keep direct replica-set members with matching setName."
  (let* ((conn (make-mongo-conn
                :host "seed-a"
                :port 27018
                :database "app"
                :params '(:url
                          "mongodb://seed-a:27018/app?replicaSet=rs0&directConnection=true")))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("secondary" . t)))
         (topology (mongo--topology-description-from-hello conn hello))
         (server (cdr (assoc "seed-a:27018"
                             (mongo-topology-description-servers
                              topology)))))
    (setf (mongo-conn-topology conn) topology)
    (should (eq (mongo-topology-description-type topology) 'single))
    (should (eq (mongo-server-description-type server) 'rs-secondary))
    (should (eq (mongo-select-server conn 'read) server))))



(ert-deftest mongo-test-topology-direct-replica-set-name-missing ()
  "Single topology should reject direct servers missing requested setName."
  (let* ((conn (make-mongo-conn
                :host "seed-a"
                :port 27017
                :database "app"
                :params '(:url
                          "mongodb://seed-a:27017/app?replicaSet=rs0&directConnection=true")))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("isWritablePrimary" . t)))
         (topology (mongo--topology-description-from-hello conn hello))
         (server (cdr (assoc "seed-a:27017"
                             (mongo-topology-description-servers
                              topology)))))
    (setf (mongo-conn-topology conn) topology)
    (should (eq (mongo-topology-description-type topology) 'single))
    (should (eq (mongo-server-description-type server) 'unknown))
    (should (string-match-p
             "did not report replica set rs0"
             (mongo-server-description-error server)))
    (should-not (mongo-select-server conn 'read))))



(ert-deftest mongo-test-topology-direct-replica-set-name-mismatch ()
  "Single topology should reject direct servers with the wrong setName."
  (let* ((conn (make-mongo-conn
                :host "seed-a"
                :port 27017
                :database "app"
                :process 'proc
                :closed nil
                :params '(:url
                          "mongodb://seed-a:27017/app?replicaSet=rs0&directConnection=true")))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "other")
                  ("isWritablePrimary" . t)))
         (topology (mongo--topology-description-from-hello conn hello))
         (server (cdr (assoc "seed-a:27017"
                             (mongo-topology-description-servers
                              topology)))))
    (setf (mongo-conn-topology conn) topology)
    (should (eq (mongo-topology-description-type topology) 'single))
    (should (eq (mongo-server-description-type server) 'unknown))
    (should (string-match-p
             "belongs to replica set other, not rs0"
             (mongo-server-description-error server)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-hello)
               (lambda (&rest _args) nil))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "setName mismatch should fail before send"))))
      (let ((err (should-error
                  (mongo-command conn "app" '(("find" . "users")))
                  :type 'mongo-error)))
        (should (string-match-p
                 "belongs to replica set other, not rs0"
                 (error-message-string err)))))))



(ert-deftest mongo-test-topology-replica-primary-set-name-mismatch-removes ()
  "Replica-set topology should remove a primary with a wrong setName."
  (let* ((conn (make-mongo-conn :host "primary"
                                :port 27017
                                :database "app"))
         (old-primary (make-mongo-server-description
                       :address "primary:27017"
                       :type 'rs-primary
                       :set-name "rs0"))
         (secondary (make-mongo-server-description
                     :address "secondary:27018"
                     :type 'rs-secondary
                     :set-name "rs0"))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-with-primary
                        :set-name "rs0"
                        :servers `(("primary:27017" . ,old-primary)
                                   ("secondary:27018" . ,secondary))
                        :primary-address "primary:27017"
                        :compatible t))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "other")
                  ("isWritablePrimary" . t)
                  ("hosts" . ("primary:27017"
                              "secondary:27018")))))
    (setf (mongo-conn-topology conn) old-topology)
    (let* ((topology (mongo--topology-description-from-hello conn hello))
           (servers (mongo-topology-description-servers topology)))
      (should (eq (mongo-topology-description-type topology)
                  'replica-set-no-primary))
      (should (equal (mongo-topology-description-set-name topology) "rs0"))
      (should-not (mongo-topology-description-primary-address topology))
      (should-not (assoc "primary:27017" servers))
      (should (eq (cdr (assoc "secondary:27018" servers))
                  secondary)))))



(ert-deftest mongo-test-topology-replica-secondary-set-name-mismatch-removes ()
  "Replica-set topology should remove a non-primary with a wrong setName."
  (let* ((conn (make-mongo-conn :host "secondary"
                                :port 27018
                                :database "app"))
         (primary (make-mongo-server-description
                   :address "primary:27017"
                   :type 'rs-primary
                   :set-name "rs0"))
         (old-secondary (make-mongo-server-description
                         :address "secondary:27018"
                         :type 'rs-secondary
                         :set-name "rs0"))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-with-primary
                        :set-name "rs0"
                        :servers `(("primary:27017" . ,primary)
                                   ("secondary:27018" . ,old-secondary))
                        :primary-address "primary:27017"
                        :compatible t))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "other")
                  ("secondary" . t)
                  ("hosts" . ("primary:27017"
                              "secondary:27018")))))
    (setf (mongo-conn-topology conn) old-topology)
    (let* ((topology (mongo--topology-description-from-hello conn hello))
           (servers (mongo-topology-description-servers topology)))
      (should (eq (mongo-topology-description-type topology)
                  'replica-set-with-primary))
      (should (equal (mongo-topology-description-set-name topology) "rs0"))
      (should (equal (mongo-topology-description-primary-address topology)
                     "primary:27017"))
      (should (eq (cdr (assoc "primary:27017" servers))
                  primary))
      (should-not (assoc "secondary:27018" servers)))))



(ert-deftest mongo-test-topology-replica-set-name-param-mismatch-removes ()
  "Requested replicaSet should be enforced before a topology name is known."
  (let* ((conn (make-mongo-conn
                :host "seed-a"
                :port 27017
                :database "app"
                :params '(:url "mongodb://seed-a:27017/app?replicaSet=rs0")))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "other")
                  ("secondary" . t)
                  ("hosts" . ("seed-a:27017"))))
         (topology (mongo--topology-description-from-hello conn hello)))
    (should (eq (mongo-topology-description-type topology)
                'replica-set-no-primary))
    (should (equal (mongo-topology-description-set-name topology) "rs0"))
    (should-not (mongo-topology-description-servers topology))
    (setf (mongo-conn-topology conn) topology)
    (should-not (mongo-select-server conn 'read))))



(ert-deftest mongo-test-topology-replica-secondary-me-mismatch-removes ()
  "Replica-set topology should remove non-primary members with wrong me."
  (let* ((conn (make-mongo-conn :host "alias-secondary"
                                :port 27018
                                :database "app"))
         (primary (make-mongo-server-description
                   :address "primary:27017"
                   :type 'rs-primary
                   :set-name "rs0"))
         (old-secondary (make-mongo-server-description
                         :address "alias-secondary:27018"
                         :type 'rs-secondary
                         :set-name "rs0"))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-with-primary
                        :set-name "rs0"
                        :servers `(("primary:27017" . ,primary)
                                   ("alias-secondary:27018" . ,old-secondary))
                        :primary-address "primary:27017"
                        :compatible t))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("secondary" . t)
                  ("me" . "secondary:27018")
                  ("hosts" . ("primary:27017"
                              "secondary:27018")))))
    (setf (mongo-conn-topology conn) old-topology)
    (let* ((topology (mongo--topology-description-from-hello conn hello))
           (servers (mongo-topology-description-servers topology)))
      (should (eq (mongo-topology-description-type topology)
                  'replica-set-with-primary))
      (should (equal (mongo-topology-description-set-name topology) "rs0"))
      (should (equal (mongo-topology-description-primary-address topology)
                     "primary:27017"))
      (should (eq (cdr (assoc "primary:27017" servers))
                  primary))
      (should-not (assoc "alias-secondary:27018" servers))
      (should-not (assoc "secondary:27018" servers)))))



(ert-deftest mongo-test-topology-direct-secondary-me-mismatch-is-kept ()
  "Single topology should not remove direct members when me is canonical."
  (let* ((conn (make-mongo-conn
                :host "alias-secondary"
                :port 27018
                :database "app"
                :params '(:url
                          "mongodb://alias-secondary:27018/app?directConnection=true")))
         (old-secondary (make-mongo-server-description
                         :address "alias-secondary:27018"
                         :type 'rs-secondary
                         :set-name "rs0"))
         (old-topology (make-mongo-topology-description
                        :type 'single
                        :servers `(("alias-secondary:27018" . ,old-secondary))
                        :compatible t))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("secondary" . t)
                  ("me" . "secondary:27018")
                  ("hosts" . ("primary:27017"
                              "secondary:27018")))))
    (setf (mongo-conn-topology conn) old-topology)
    (let* ((topology (mongo--topology-description-from-hello conn hello))
           (servers (mongo-topology-description-servers topology))
           (server (cdr (assoc "alias-secondary:27018" servers))))
      (should (eq (mongo-topology-description-type topology) 'single))
      (should (eq (mongo-server-description-type server) 'rs-secondary))
      (should (equal (mongo-server-description-me server)
                     "secondary:27018"))
      (should-not (assoc "secondary:27018" servers)))))



(ert-deftest mongo-test-topology-replica-primary-me-alias-is-kept-for-fallback ()
  "Primary aliases should remain for local port-forward fallback."
  (let* ((conn (make-mongo-conn :host "alias-primary"
                                :port 27021
                                :database "app"))
         (old-primary (make-mongo-server-description
                       :address "alias-primary:27021"
                       :type 'rs-primary
                       :set-name "rs0"))
         (old-secondary (make-mongo-server-description
                         :address "secondary:27018"
                         :type 'rs-secondary
                         :set-name "rs0"))
         (old-topology (make-mongo-topology-description
                        :type 'replica-set-with-primary
                        :set-name "rs0"
                        :servers `(("alias-primary:27021" . ,old-primary)
                                   ("secondary:27018" . ,old-secondary))
                        :primary-address "alias-primary:27021"
                        :compatible t))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)
                  ("me" . "primary:27017")
                  ("hosts" . ("primary:27017"
                              "secondary:27018")))))
    (setf (mongo-conn-topology conn) old-topology)
    (let* ((topology (mongo--topology-description-from-hello conn hello))
           (servers (mongo-topology-description-servers topology))
           (server (cdr (assoc "alias-primary:27021" servers))))
      (should (eq (mongo-topology-description-type topology)
                  'replica-set-with-primary))
      (should (equal (mongo-topology-description-primary-address topology)
                     "alias-primary:27021"))
      (should (eq (mongo-server-description-type server) 'rs-primary))
      (should (equal (mongo-server-description-me server)
                     "primary:27017"))
      (should (assoc "primary:27017" servers))
      (should (assoc "secondary:27018" servers)))))



(ert-deftest mongo-test-hello-refreshes-topology-description ()
  "mongo-hello should refresh cached hello and topology descriptions."
  (let ((conn (make-mongo-conn :host "db"
                               :port 27017
                               :database "app"
                               :hello-command "hello"))
        captured)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (setq captured (list database command))
                 '(("ok" . 1)
                   ("maxWireVersion" . 17)
                   ("msg" . "isdbgrid")))))
      (mongo-hello conn))
    (should (equal captured
                   '("admin" (("hello" . 1)))))
    (should (equal (mongo-conn-last-hello conn)
                   '(("ok" . 1)
                     ("maxWireVersion" . 17)
                     ("msg" . "isdbgrid"))))
    (should (eq (mongo-topology-description-type
                 (mongo-conn-topology conn))
                'sharded))
    (let ((server (cdar (mongo-topology-description-servers
                         (mongo-conn-topology conn)))))
      (should (eq (mongo-server-description-type server) 'mongos)))))



(ert-deftest mongo-test-awaitable-hello-includes-topology-version ()
  "mongo-awaitable-hello should send topologyVersion and maxAwaitTimeMS."
  (let* ((conn (make-mongo-conn :host "db"
                                :port 27017
                                :database "app"
                                :hello-command "hello"))
         (topology-version '(("processId" . (("$oid" . "64f000000000000000000001")))
                             ("counter" . 7)))
         (command-topology-version
          (mongo-document
           `(("processId" .
              ,(mongo-object-id "64f000000000000000000001"))
             ("counter" . ,(mongo-int64 7)))))
         (next-topology-version '(("processId" . (("$oid" . "64f000000000000000000001")))
                                  ("counter" . 8)))
         captured)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello
           conn
           `(("ok" . 1)
             ("maxWireVersion" . 17)
             ("topologyVersion" . ,topology-version))))
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (setq captured (list database command))
                 `(("ok" . 1)
                   ("maxWireVersion" . 17)
                   ("topologyVersion" . ,next-topology-version)))))
      (mongo-awaitable-hello conn 250))
    (should (equal captured
                   `("admin"
                     (("hello" . 1)
                      ("topologyVersion" . ,command-topology-version)
                      ("maxAwaitTimeMS" . 250)))))
    (should (equal (mongo-server-description-topology-version
                    (mongo--current-server-description conn))
                   next-topology-version))))



(ert-deftest mongo-test-awaitable-hello-falls-back-without-topology-version ()
  "mongo-awaitable-hello should use ordinary hello when no topologyVersion is known."
  (let ((conn (make-mongo-conn :host "db"
                               :port 27017
                               :database "app"
                               :hello-command "hello"))
        captured)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout)
                 (setq captured (list database command))
                 '(("ok" . 1)
                   ("maxWireVersion" . 17)))))
      (mongo-awaitable-hello conn 250))
    (should (equal captured
                   '("admin" (("hello" . 1)))))))



(ert-deftest mongo-test-monitor-once-clears-error ()
  "MongoDB monitor heartbeat should clear old monitor errors on success."
  (let ((conn (make-mongo-conn :host "db"
                               :port 27017
                               :database "app"))
        captured)
    (setf (mongo-conn-monitor-error conn) '(mongo-error "old"))
    (cl-letf (((symbol-function 'mongo-awaitable-hello)
               (lambda (_conn max-await timeout)
                 (setq captured (list max-await timeout))
                 '(("ok" . 1)
                   ("maxWireVersion" . 17)))))
      (should (equal (mongo-monitor-once conn 250 3)
                     '(("ok" . 1)
                       ("maxWireVersion" . 17)))))
    (should (equal captured '(250 3)))
    (should-not (mongo-conn-monitor-error conn))))


(ert-deftest mongo-test-monitor-heartbeat-emits-sdam-success-events ()
  "Monitor heartbeats should emit paired SDAM started/succeeded events."
  (let* ((topology-version
          '(("processId" . (("$oid" . "64f000000000000000000001")))
            ("counter" . 7)))
         (reply `(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("connectionId" . 42)
                  ("topologyVersion" . ,topology-version)))
         (conn (make-mongo-conn :host "db"
                                :port 27017
                                :database "app"))
         events)
    (setf (mongo-conn-last-hello conn)
          '(("ok" . 1)
            ("connectionId" . 41)))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello
           conn
           `(("ok" . 1)
             ("maxWireVersion" . 17)
             ("topologyVersion" . ,topology-version))))
    (cl-letf (((symbol-function 'mongo-awaitable-hello)
               (lambda (_conn max-await timeout)
                 (should (= max-await 250))
                 (should (= timeout 3))
                 (setf (mongo-conn-last-hello conn) reply)
                 reply)))
      (let ((mongo-sdam-event-hook
             (list (lambda (event)
                     (push event events)))))
        (should (equal (mongo-monitor-once conn 250 3) reply))))
    (let ((ordered (nreverse events)))
      (should (equal (mapcar (lambda (event)
                               (alist-get 'type event))
                             ordered)
                     '(server-heartbeat-started
                       server-heartbeat-succeeded)))
      (should (eq (alist-get 'awaited (nth 0 ordered)) t))
      (should (eq (alist-get 'awaited (nth 1 ordered)) t))
      (should (equal (alist-get 'connection-id (nth 0 ordered))
                     "db:27017"))
      (should (equal (alist-get 'server-connection-id (nth 0 ordered))
                     41))
      (should (equal (alist-get 'server-connection-id (nth 1 ordered))
                     42))
      (should (numberp (alist-get 'duration-ms (nth 1 ordered))))
      (should (equal (alist-get 'reply (nth 1 ordered)) reply)))))


(ert-deftest mongo-test-monitor-heartbeat-emits-sdam-failure-events ()
  "Monitor heartbeat failures should emit paired SDAM started/failed events."
  (let ((conn (make-mongo-conn :host "db"
                               :port 27017
                               :database "app"))
        events)
    (cl-letf (((symbol-function 'mongo-awaitable-hello)
               (lambda (&rest _args)
                 (signal 'mongo-error (list "heartbeat failed")))))
      (let ((mongo-sdam-event-hook
             (list (lambda (event)
                     (push event events)))))
        (should-error (mongo-monitor-once conn 250 3)
                      :type 'mongo-error)))
    (let ((ordered (nreverse events)))
      (should (equal (mapcar (lambda (event)
                               (alist-get 'type event))
                             ordered)
                     '(server-heartbeat-started
                       server-heartbeat-failed)))
      (should-not (alist-get 'awaited (nth 0 ordered)))
      (should-not (alist-get 'awaited (nth 1 ordered)))
      (should (equal (alist-get 'connection-id (nth 0 ordered))
                     "db:27017"))
      (should (numberp (alist-get 'duration-ms (nth 1 ordered))))
      (should (equal (alist-get 'failure (nth 1 ordered))
                     '(mongo-error "heartbeat failed"))))))


(ert-deftest mongo-test-sdam-description-change-events-from-hello ()
  "Post-handshake hello should emit SDAM description change events."
  (let* ((primary-hello
          '(("ok" . 1)
            ("maxWireVersion" . 17)
            ("setName" . "rs0")
            ("isWritablePrimary" . t)
            ("hosts" . ("db:27017"))))
         (secondary-hello
          '(("ok" . 1)
            ("maxWireVersion" . 17)
            ("setName" . "rs0")
            ("secondary" . t)
            ("hosts" . ("db:27017"))))
         (conn (make-mongo-conn :host "db"
                                :port 27017
                                :database "app"))
         events)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn _database command &optional _timeout)
                 (should (equal command '(("hello" . 1))))
                 secondary-hello)))
      (let ((mongo-sdam-event-hook
             (list (lambda (event)
                     (push event events)))))
        (should (equal (mongo-hello conn) secondary-hello))))
    (let ((ordered (nreverse events)))
      (should (equal (mapcar (lambda (event)
                               (alist-get 'type event))
                             ordered)
                     '(server-description-changed
                       topology-description-changed)))
      (should (numberp (alist-get 'topology-id (nth 0 ordered))))
      (should (equal (alist-get 'topology-id (nth 0 ordered))
                     (alist-get 'topology-id (nth 1 ordered))))
      (should (equal (alist-get 'address (nth 0 ordered))
                     "db:27017"))
      (should (eq (mongo-server-description-type
                   (alist-get 'previous-description (nth 0 ordered)))
                  'rs-primary))
      (should (eq (mongo-server-description-type
                   (alist-get 'new-description (nth 0 ordered)))
                  'rs-secondary))
      (should (eq (mongo-topology-description-type
                   (alist-get 'previous-description (nth 1 ordered)))
                  'replica-set-with-primary))
      (should (eq (mongo-topology-description-type
                   (alist-get 'new-description (nth 1 ordered)))
                  'replica-set-no-primary)))))


(ert-deftest mongo-test-sdam-description-change-ignores-rtt-only ()
  "SDAM description change events should ignore RTT-only refreshes."
  (let* ((hello
          '(("ok" . 1)
            ("maxWireVersion" . 17)
            ("setName" . "rs0")
            ("secondary" . t)
            ("hosts" . ("db:27017"))))
         (conn (make-mongo-conn :host "db"
                                :port 27017
                                :database "app"))
         events)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello 0.100))
    (cl-letf (((symbol-function 'float-time)
               (let ((times '(1000.0 1000.2)))
                 (lambda ()
                   (prog1 (or (pop times) 1000.2)))))
              ((symbol-function 'mongo-command)
               (lambda (&rest _args)
                 hello)))
      (let ((mongo-sdam-event-hook
             (list (lambda (event)
                     (push event events)))))
        (should (equal (mongo-hello conn) hello))))
    (should-not events)))


(ert-deftest mongo-test-sdam-description-change-events-from-monitor-error ()
  "Monitor errors should emit SDAM description changes to Unknown."
  (let* ((hello
          '(("ok" . 1)
            ("maxWireVersion" . 17)
            ("setName" . "rs0")
            ("isWritablePrimary" . t)
            ("hosts" . ("db:27017"))))
         (conn (make-mongo-conn :host "db"
                                :port 27017
                                :database "app"))
         events)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'mongo-awaitable-hello)
               (lambda (&rest _args)
                 (signal 'mongo-error (list "heartbeat failed")))))
      (let ((mongo-sdam-event-hook
             (list (lambda (event)
                     (push event events)))))
        (should-error (mongo-monitor-once conn 250 3)
                      :type 'mongo-error)))
    (let ((ordered (nreverse events)))
      (should (equal (mapcar (lambda (event)
                               (alist-get 'type event))
                             ordered)
                     '(server-heartbeat-started
                       server-description-changed
                       topology-description-changed
                       server-heartbeat-failed)))
      (should (eq (mongo-server-description-type
                   (alist-get 'new-description (nth 1 ordered)))
                  'unknown))
      (should (eq (mongo-topology-description-type
                   (alist-get 'new-description (nth 2 ordered)))
                  'replica-set-no-primary)))))


(ert-deftest mongo-test-sdam-lifecycle-events-connect-disconnect ()
  "Connect/disconnect should emit SDAM opening and closed lifecycle events."
  (let (events conn)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest _args) 'proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'mongo--send-handshake)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-handshake-message)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("maxWireVersion" . 17))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (let ((mongo-sdam-event-hook
             (list (lambda (event)
                     (push event events)))))
        (unwind-protect
            (setq conn (mongo-connect '(:host "db"
                                        :port 27017
                                        :database "app")))
          (when conn
            (mongo-disconnect conn)
            (mongo-disconnect conn)))))
    (let* ((ordered (nreverse events))
           (types (mapcar (lambda (event)
                            (alist-get 'type event))
                          ordered))
           (topology-ids (delq nil
                               (mapcar (lambda (event)
                                         (alist-get 'topology-id event))
                                       ordered))))
      (should (equal types
                     '(topology-opening
                       server-opening
                       server-description-changed
                       topology-description-changed
                       server-description-changed
                       topology-description-changed
                       server-closed
                       topology-closed)))
      (should (seq-every-p (lambda (id)
                             (equal id (car topology-ids)))
                           topology-ids))
      (should (equal (alist-get 'address (nth 1 ordered)) "db:27017"))
      (should (eq (mongo-server-description-type
                   (alist-get 'previous-description (nth 2 ordered)))
                  'unknown))
      (should (eq (mongo-server-description-type
                   (alist-get 'new-description (nth 2 ordered)))
                  'standalone))
      (should (eq (mongo-topology-description-type
                   (alist-get 'previous-description (nth 3 ordered)))
                  'unknown))
      (should (eq (mongo-topology-description-type
                   (alist-get 'new-description (nth 3 ordered)))
                  'single))
      (should (eq (mongo-server-description-type
                   (alist-get 'new-description (nth 4 ordered)))
                  'unknown))
      (should (eq (mongo-topology-description-type
                   (alist-get 'new-description (nth 5 ordered)))
                  'unknown))
      (should (eq (car (last types)) 'topology-closed)))))



(ert-deftest mongo-test-monitor-once-can-use-poll-mode ()
  "serverMonitoringMode=poll should use ordinary hello for monitoring."
  (let ((conn (make-mongo-conn :host "db"
                               :port 27017
                               :database "app"
                               :server-monitoring-mode 'poll))
        captured)
    (cl-letf (((symbol-function 'mongo-hello)
               (lambda (_conn timeout)
                 (setq captured (list 'hello timeout))
                 '(("ok" . 1)
                   ("maxWireVersion" . 17))))
              ((symbol-function 'mongo-awaitable-hello)
               (lambda (&rest _args)
                 (ert-fail "poll mode should not use awaitable hello"))))
      (should (equal (mongo-monitor-once conn 250 3)
                     '(("ok" . 1)
                       ("maxWireVersion" . 17)))))
    (should (equal captured '(hello 3)))))



(ert-deftest mongo-test-monitor-once-load-balanced-is-noop ()
  "Load-balanced connections should not run monitoring hello commands."
  (let* ((last-hello '(("ok" . 1)
                       ("maxWireVersion" . 17)
                       ("serviceId" . "service-1")))
         (conn (make-mongo-conn :host "lb"
                                :port 27017
                                :database "app"
                                :load-balanced t
                                :last-hello last-hello)))
    (setf (mongo-conn-monitor-error conn) '(mongo-error "old"))
    (cl-letf (((symbol-function 'mongo-hello)
               (lambda (&rest _args)
                 (ert-fail "load-balanced monitor should not call hello")))
              ((symbol-function 'mongo-awaitable-hello)
               (lambda (&rest _args)
                 (ert-fail
                  "load-balanced monitor should not call awaitable hello"))))
      (should (equal (mongo-monitor-once conn 250 3)
                     last-hello)))
    (should-not (mongo-conn-monitor-error conn))))



(ert-deftest mongo-test-monitor-once-marks-server-unknown-on-error ()
  "Monitor errors should mark current server Unknown while preserving topology."
  (let* ((conn (make-mongo-conn :host "db"
                                :port 27017
                                :database "app"))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'mongo-awaitable-hello)
               (lambda (&rest _args)
                 (signal 'mongo-error (list "heartbeat failed")))))
      (should-error (mongo-monitor-once conn 250 3) :type 'mongo-error))
    (should (mongo-conn-monitor-error conn))
    (should (eq (mongo-topology-description-type
                 (mongo-conn-topology conn))
                'replica-set-no-primary))
    (let ((server (mongo--current-server-description conn)))
      (should (eq (mongo-server-description-type server) 'unknown))
      (should (string-match-p
               "heartbeat failed"
               (mongo-server-description-error server))))))



(ert-deftest mongo-test-start-stop-monitor-schedules-tick ()
  "Explicit MongoDB monitor timers should schedule ticks and stop cleanly."
  (let ((conn (make-mongo-conn :host "db"
                               :port 27017
                               :database "app"
                               :process 'proc
                               :closed nil))
        scheduled
        cancelled
        ticked)
    (cl-letf (((symbol-function 'run-at-time)
               (lambda (secs repeat fn &rest args)
                 (setq scheduled (list secs repeat fn args))
                 'fake-monitor-timer))
              ((symbol-function 'cancel-timer)
               (lambda (timer)
                 (push timer cancelled)))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-monitor-once)
               (lambda (_conn max-await timeout)
                 (setq ticked (list max-await timeout))
                 '(("ok" . 1)))))
      (should (eq (mongo-start-monitor conn 2 250 4) conn))
      (should (eq (mongo-conn-monitor-timer conn) 'fake-monitor-timer))
      (should (equal (list (nth 0 scheduled) (nth 1 scheduled))
                     '(0 2)))
      (apply (nth 2 scheduled) (nth 3 scheduled))
      (should (equal ticked '(250 4)))
      (should (eq (mongo-stop-monitor conn) conn))
      (should-not (mongo-conn-monitor-timer conn))
      (should (equal cancelled '(fake-monitor-timer))))))



(ert-deftest mongo-test-start-monitor-load-balanced-is-noop ()
  "Load-balanced connections should not schedule monitor timers."
  (let ((conn (make-mongo-conn :host "lb"
                               :port 27017
                               :database "app"
                               :load-balanced t
                               :monitor-timer 'old-monitor-timer))
        cancelled)
    (cl-letf (((symbol-function 'cancel-timer)
               (lambda (timer)
                 (push timer cancelled)))
              ((symbol-function 'run-at-time)
               (lambda (&rest _args)
                 (ert-fail
                  "load-balanced monitor should not schedule a timer"))))
      (should (eq (mongo-start-monitor conn 2 250 4) conn)))
    (should-not (mongo-conn-monitor-timer conn))
    (should (equal cancelled '(old-monitor-timer)))))



(ert-deftest mongo-test-start-monitor-uses-connection-heartbeat ()
  "heartbeatFrequencyMS should configure explicit monitor scheduling."
  (let ((conn (make-mongo-conn :host "db"
                               :port 27017
                               :database "app"
                               :process 'proc
                               :closed nil
                               :heartbeat-frequency 1.5))
        scheduled
        ticked)
    (cl-letf (((symbol-function 'run-at-time)
               (lambda (secs repeat fn &rest args)
                 (setq scheduled (list secs repeat fn args))
                 'fake-monitor-timer))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-monitor-once)
               (lambda (_conn max-await timeout)
                 (setq ticked (list max-await timeout))
                 '(("ok" . 1)))))
      (mongo-start-monitor conn)
      (should (equal (list (nth 0 scheduled) (nth 1 scheduled))
                     '(0 1.5)))
      (apply (nth 2 scheduled) (nth 3 scheduled))
      (should (equal ticked '(1500 2.5))))))



(ert-deftest mongo-test-select-server-uses-current-topology ()
  "mongo-select-server should classify the current topology server."
  (let* ((primary-conn (make-mongo-conn :host "seed-b"
                                        :port 27018
                                        :database "app"))
         (secondary-read-preference
          (mongo--params-read-preference
           '(:read-preference secondary)))
         (primary-hello '(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t)))
         (secondary-conn (make-mongo-conn :host "seed-a"
                                          :port 27017
                                          :database "app"))
         (secondary-hello '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("secondary" . t))))
    (setf (mongo-conn-topology primary-conn)
          (mongo--topology-description-from-hello
           primary-conn primary-hello))
    (setf (mongo-conn-topology secondary-conn)
          (mongo--topology-description-from-hello
           secondary-conn secondary-hello))
    (setf (mongo-conn-read-preference secondary-conn)
          secondary-read-preference)
    (should (eq (mongo-server-description-type
                 (mongo-select-server primary-conn 'write))
                'rs-primary))
    (should (eq (mongo-server-description-type
                 (mongo-select-server secondary-conn 'read))
                'rs-secondary))
    (should-not (mongo-select-server secondary-conn 'write))))



(ert-deftest mongo-test-select-server-filters-read-preference-tags ()
  "mongo-select-server should enforce readPreferenceTags on replica reads."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("secondary" . t)
                  ("tags" . (("dc" . "ny")
                             ("rack" . "1")))))
         (topology (mongo--topology-description-from-hello conn hello)))
    (setf (mongo-conn-topology conn) topology)
    (setf (mongo-conn-read-preference conn)
          (mongo--params-read-preference
           '(:read-preference secondary
             :read-preference-tags ((("dc" . "ny"))))))
    (should (mongo-select-server conn 'read))
    (setf (mongo-conn-read-preference conn)
          (mongo--params-read-preference
           '(:read-preference secondary
             :read-preference-tags ((("dc" . "sf"))))))
    (should-not (mongo-select-server conn 'read))
    (let ((empty-tag-set (mongo-document nil)))
      (setf (mongo-conn-read-preference conn)
            (mongo--params-read-preference
             (list :read-preference 'secondary
                   :read-preference-tags
                   (list '(("dc" . "sf")) empty-tag-set)))))
    (should (mongo-select-server conn 'read))))



(ert-deftest mongo-test-select-server-filters-max-staleness ()
  "mongo-select-server should reject stale secondaries for maxStalenessSeconds."
  (let* ((conn (make-mongo-conn :host "seed-s"
                                :port 27018
                                :database "app"
                                :heartbeat-frequency 10))
         (read-preference
          (mongo--params-read-preference
           '(:read-preference secondary
             :max-staleness-seconds 120)))
         (primary
          (make-mongo-server-description
           :address "seed-p:27017"
           :type 'rs-primary
           :max-wire-version 17
           :last-update-time 1000.0
           :last-write-date 1000.0))
         (secondary
          (make-mongo-server-description
           :address "seed-s:27018"
           :type 'rs-secondary
           :max-wire-version 17
           :last-update-time 1000.0
           :last-write-date 880.0))
         (topology
          (make-mongo-topology-description
           :type 'replica-set-with-primary
           :primary-address "seed-p:27017"
           :servers `(("seed-p:27017" . ,primary)
                      ("seed-s:27018" . ,secondary)))))
    (setf (mongo-conn-read-preference conn) read-preference)
    (setf (mongo-conn-topology conn) topology)
    (should-not (mongo-select-server conn 'read))
    (setf (mongo-server-description-last-write-date secondary) 890.0)
    (should (mongo-select-server conn 'read))))



(ert-deftest mongo-test-pool-opens-min-pool-size ()
  "MongoDB pools should pre-open minPoolSize native connections."
  (let ((created 0)
        disconnected
        pool)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn :process (intern (format "proc-%d" created)))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (setq pool (mongo-pool-open '(:min-pool-size 2
                                    :max-pool-size 3)))
      (should (= created 2))
      (should (= (length (mongo-pool-available pool)) 2))
      (should-not (mongo-pool-in-use pool))
      (mongo-pool-disconnect pool)
      (should (= (length disconnected) 2))
      (should (mongo-pool-closed pool)))))


(ert-deftest mongo-test-pool-ready-maintains-min-pool-size ()
  "mongo-pool-ready should repopulate minPoolSize after a clear."
  (let ((created 0)
        disconnected
        pool)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn
                  :process (intern (format "proc-%d" created)))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (setq pool (mongo-pool-open '(:min-pool-size 2
                                    :max-pool-size 4)))
      (should (= created 2))
      (mongo-pool-clear pool)
      (should (mongo-pool-paused pool))
      (should-not (mongo-pool-available pool))
      (should (= (length disconnected) 2))
      (mongo-pool-ready pool)
      (should-not (mongo-pool-paused pool))
      (should (= created 4))
      (should (= (length (mongo-pool-available pool)) 2)))))


(ert-deftest mongo-test-pool-checkout-maintains-min-size-after-prune ()
  "Checkout should refill minPoolSize after pruning dead idle connections."
  (let ((created 0)
        disconnected
        pool conn)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn
                  :process (intern (format "proc-%d" created)))))
              ((symbol-function 'process-live-p)
               (lambda (proc)
                 (not (eq proc 'proc-1))))
              ((symbol-function 'mongo-disconnect)
               (lambda (wire)
                 (push wire disconnected))))
      (setq pool (mongo-pool-open '(:min-pool-size 2
                                    :max-pool-size 3)))
      (should (= created 2))
      (setq conn (mongo-pool-checkout pool))
      (should (eq (mongo-conn-process conn) 'proc-2))
      (should (= created 3))
      (should (= (length (mongo-pool-in-use pool)) 1))
      (should (= (length (mongo-pool-available pool)) 1))
      (should (equal (mapcar #'mongo-conn-process disconnected)
                     '(proc-1))))))



(ert-deftest mongo-test-pool-reuses-released-connection ()
  "MongoDB pools should reuse released live connections."
  (let ((created 0)
        pool first second)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn :process (intern (format "proc-%d" created)))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t)))
      (setq pool (mongo-pool-open '(:max-pool-size 2)))
      (setq first (mongo-pool-checkout pool))
      (mongo-pool-release pool first)
      (setq second (mongo-pool-checkout pool))
      (should (eq first second))
      (should (= created 1))
      (should (= (length (mongo-pool-in-use pool)) 1))
      (should-not (mongo-pool-available pool)))))


(ert-deftest mongo-test-pool-checkout-tracks-purpose ()
  "MongoDB pools should track checked-out connection purposes."
  (let ((conn (make-mongo-conn :process 'proc))
        pool)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params) conn))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t)))
      (setq pool (mongo-pool-open '(:max-pool-size 1)))
      (should (eq (mongo-pool-checkout pool nil 'cursor) conn))
      (should (eq (mongo--pool-connection-purpose pool conn) 'cursor))
      (should (= (mongo--pool-purpose-count pool 'cursor) 1))
      (should (= (mongo--pool-purpose-count pool 'transaction) 0))
      (should (= (mongo--pool-purpose-count pool 'other) 0))
      (mongo-pool-release pool conn)
      (should-not (mongo-pool-conn-purposes pool))
      (mongo-with-pool-connection (checked-out pool nil 'transaction)
        (should (eq checked-out conn))
        (should (eq (mongo--pool-connection-purpose pool conn)
                    'transaction)))
      (should-not (mongo-pool-conn-purposes pool))
      (should (eq (mongo-pool-checkout pool) conn))
      (should (eq (mongo--pool-connection-purpose pool conn) 'other)))))


(ert-deftest mongo-test-pool-load-balanced-timeout-reports-purpose-counts ()
  "Load-balanced wait queue timeouts should report checked-out purpose counts."
  (let* ((cursor-conn (make-mongo-conn :process 'cursor-proc))
         (txn-conn (make-mongo-conn :process 'txn-proc))
         (other-conn (make-mongo-conn :process 'other-proc))
         (pool (make-mongo-pool
                :params '(:load-balanced t)
                :max-size 3
                :max-connecting 2
                :in-use (list cursor-conn txn-conn other-conn)
                :conn-purposes `((,cursor-conn . cursor)
                                 (,txn-conn . transaction)
                                 (,other-conn . other)))))
    (let ((err (should-error (mongo-pool-checkout pool 0)
                             :type 'mongo-error)))
      (should (string-match-p
               (regexp-quote
                "Timeout waiting for connection from the connection pool. maxPoolSize: 3, connections in use by cursors: 1, connections in use by transactions: 1, connections in use by other operations: 1")
               (error-message-string err))))))


(ert-deftest mongo-test-pool-emits-lifecycle-and-checkout-events ()
  "MongoDB pools should expose basic CMAP-style lifecycle events."
  (let ((created 0)
        events pool conn)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn :process (intern (format "proc-%d" created)))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-disconnect)
               (lambda (_conn) nil)))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (setq pool (mongo-pool-open '(:host "db.example.test"
                                      :port 27018
                                      :min-pool-size 1)))
        (let ((ordered (nreverse events)))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 ordered)
                         '(connection-pool-created
                           connection-pool-ready
                           connection-created
                           connection-ready)))
          (should (equal (alist-get 'address (car ordered))
                         "db.example.test:27018"))
          (should (= (alist-get 'connection-id (nth 2 ordered)) 1))
          (should (= (alist-get 'connection-id (nth 3 ordered)) 1))
          (should (numberp (alist-get 'duration-ms (nth 3 ordered)))))
        (setq events nil)
        (setq conn (mongo-pool-checkout pool))
        (mongo-pool-release pool conn)
        (let ((ordered (nreverse events)))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 ordered)
                         '(connection-check-out-started
                           connection-checked-out
                           connection-checked-in)))
          (should (= (alist-get 'connection-id (nth 1 ordered)) 1))
          (should (numberp (alist-get 'duration-ms (nth 1 ordered))))
          (should (= (alist-get 'connection-id (nth 2 ordered)) 1)))
        (setq events nil)
        (mongo-pool-disconnect pool)
        (let ((ordered (nreverse events)))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 ordered)
                         '(connection-closed
                           connection-pool-closed)))
          (should (= (alist-get 'connection-id (car ordered)) 1))
          (should (eq (alist-get 'reason (car ordered)) 'pool-closed)))))))


(ert-deftest mongo-test-pool-created-event-includes-options ()
  "MongoDB pool-created events should expose non-default pool options."
  (let (events)
    (let ((mongo-pool-event-hook
           (list (lambda (event)
                   (push event events)))))
      (mongo-pool-open
       '(:url
         "mongodb://user:secret@db.example.test:27018/app?maxPoolSize=0&maxIdleTimeMS=1500&waitQueueTimeoutMS=250&maxConnecting=3"))
      (let ((created (car (nreverse events))))
        (should (eq (alist-get 'type created)
                    'connection-pool-created))
        (should (equal (alist-get 'address created)
                       "db.example.test:27018"))
        (should (equal (alist-get 'options created)
                       '((max-pool-size . 0)
                         (max-idle-time-ms . 1500)
                         (wait-queue-timeout-ms . 250)
                         (max-connecting . 3))))))))


(ert-deftest mongo-test-pool-emits-checkout-failed-event ()
  "MongoDB pool checkout failures should expose a CMAP-style event."
  (let (events pool conn)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (make-mongo-conn :process 'proc)))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t)))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (setq pool (mongo-pool-open '(:max-pool-size 1)))
        (setq conn (mongo-pool-checkout pool))
        (setq events nil)
        (should-error (mongo-pool-checkout pool 0) :type 'mongo-error)
        (setq events (nreverse events))
        (should (equal (mapcar (lambda (event)
                                 (alist-get 'type event))
                               events)
                       '(connection-check-out-started
                         connection-check-out-failed)))
        (should (eq (alist-get 'reason (cadr events)) 'timeout))
        (should (numberp (alist-get 'duration-ms (cadr events))))
        (mongo-pool-release pool conn)))))


(ert-deftest mongo-test-pool-wait-queue-timeout-zero-has-no-deadline ()
  "MongoDB waitQueueTimeoutMS=0 should not cause immediate checkout timeout."
  (let ((conn (make-mongo-conn :process 'proc))
        events pool first second released)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params) conn))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'accept-process-output)
               (lambda (&rest _args)
                 (unless released
                   (setq released t)
                   (mongo-pool-release pool first))
                 nil))
              ((symbol-function 'sit-for)
               (lambda (&rest _args) nil)))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (setq pool
              (mongo-pool-open
               '(:max-pool-size 1
                 :wait-queue-timeout-ms 0)))
        (setq first (mongo-pool-checkout pool))
        (setq events nil)
        (setq second (mongo-pool-checkout pool))
        (should (eq second first))
        (should released)
        (let ((ordered (nreverse events)))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 ordered)
                         '(connection-check-out-started
                           connection-checked-in
                           connection-checked-out)))
          (should-not (seq-some (lambda (event)
                                  (eq (alist-get 'type event)
                                      'connection-check-out-failed))
                                ordered))
          (should (= (alist-get 'connection-id (cadr ordered)) 1))
          (should (= (alist-get 'connection-id (caddr ordered)) 1)))))))


(ert-deftest mongo-test-pool-emits-checkout-connection-error-event ()
  "MongoDB pool connection setup failures should emit checkout failure events."
  (let (events)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (signal 'mongo-error
                         (list "open failed")))))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (let ((pool (mongo-pool-open '(:max-pool-size 1))))
          (setq events nil)
          (should-error (mongo-pool-checkout pool) :type 'mongo-error)
          (setq events (nreverse events))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 events)
                         '(connection-check-out-started
                           connection-created
                           connection-closed
                           connection-check-out-failed)))
          (should (= (alist-get 'connection-id (nth 1 events)) 1))
          (should (= (alist-get 'connection-id (nth 2 events)) 1))
          (should (eq (alist-get 'reason (nth 2 events)) 'error))
          (should (eq (alist-get 'reason (nth 3 events))
                      'connection-error))
          (should (numberp (alist-get 'duration-ms (nth 3 events))))
          (should (alist-get 'error (nth 3 events))))))))


(ert-deftest mongo-test-pool-labels-hello-network-errors-with-backpressure ()
  "Connection setup hello network errors should receive CMAP backpressure labels."
  (let (events)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest _args) 'mongo-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'process-send-string) #'ignore)
              ((symbol-function 'mongo--recv-handshake-message)
               (lambda (&rest _args)
                 (signal 'mongo-error
                         (list "Timed out waiting for MongoDB response"))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (let* ((pool (mongo-pool-open '(:host "db.example.test"
                                        :port 27017
                                        :database "app"
                                        :max-pool-size 1)))
               (err (should-error (mongo-pool-checkout pool)
                                  :type 'mongo-error)))
          (should (mongo-error-has-label-p
                   err mongo--system-overloaded-error-label))
          (should (mongo-error-has-label-p
                   err mongo--retryable-error-label))
          (let ((failure (car events)))
            (should (eq (alist-get 'type failure)
                        'connection-check-out-failed))
            (should (mongo-error-has-label-p
                     (alist-get 'error failure)
                     mongo--system-overloaded-error-label))
            (should (mongo-error-has-label-p
                     (alist-get 'error failure)
                     mongo--retryable-error-label))))))))


(ert-deftest mongo-test-pool-does-not-label-socks5-errors-as-backpressure ()
  "SOCKS5 proxy errors should not receive CMAP backpressure labels."
  (cl-letf (((symbol-function 'make-network-process)
             (lambda (&rest _args) 'mongo-proc))
            ((symbol-function 'set-process-coding-system) #'ignore)
            ((symbol-function 'mongo--socks5-connect)
             (lambda (&rest _args)
               (signal 'mongo-error
                       (list "MongoDB SOCKS5 CONNECT failed: connection refused"))))
            ((symbol-function 'process-live-p)
             (lambda (_proc) t))
            ((symbol-function 'delete-process) #'ignore))
    (let* ((pool (mongo-pool-open '(:host "db.example.test"
                                    :port 27017
                                    :database "app"
                                    :proxy-host "proxy.example"
                                    :proxy-port 1080
                                    :max-pool-size 1)))
           (err (should-error (mongo-pool-checkout pool)
                              :type 'mongo-error)))
      (should-not (mongo-error-has-label-p
                   err mongo--system-overloaded-error-label))
      (should-not (mongo-error-has-label-p
                   err mongo--retryable-error-label)))))


(ert-deftest mongo-test-pool-checkout-fails-when-cleared-while-waiting ()
  "Pool clear should evict an in-flight checkout from the wait queue."
  (let ((created 0)
        events pool conn cleared disconnected)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn :process
                                  (intern (format "proc-%d" created)))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-disconnect)
               (lambda (wire)
                 (push wire disconnected)))
              ((symbol-function 'accept-process-output)
               (lambda (&rest _args)
                 (unless cleared
                   (setq cleared t)
                   (mongo-pool-clear pool))
                 nil))
              ((symbol-function 'sit-for)
               (lambda (&rest _args) nil)))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (setq pool (mongo-pool-open '(:max-pool-size 1)))
        (setq conn (mongo-pool-checkout pool))
        (setq events nil)
        (let ((err (should-error (mongo-pool-checkout pool 5)
                                 :type 'mongo-error)))
          (should (string-match-p
                   "connection pool was cleared"
                   (error-message-string err)))
          (should (mongo-error-has-label-p
                   err mongo--retryable-error-label)))
        (should cleared)
        (let ((ordered (nreverse events)))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 ordered)
                         '(connection-check-out-started
                           connection-pool-cleared
                           connection-check-out-failed)))
          (should (eq (alist-get 'reason (caddr ordered))
                      'connection-error))
          (should (numberp (alist-get 'duration-ms (caddr ordered))))
          (should (mongo-error-has-label-p
                   (alist-get 'error (caddr ordered))
                   mongo--retryable-error-label)))
        (mongo-pool-release pool conn)
        (should (equal disconnected (list conn)))))))


(ert-deftest mongo-test-pool-emits-stale-connection-closed-event ()
  "MongoDB pools should emit connection-closed when stale connections return."
  (let ((created 0)
        events pool conn)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn :process (intern (format "proc-%d" created)))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-disconnect)
               (lambda (_conn) nil)))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (setq pool (mongo-pool-open '(:max-pool-size 1)))
        (setq conn (mongo-pool-checkout pool))
        (setq events nil)
        (mongo-pool-clear pool)
        (mongo-pool-release pool conn)
        (setq events (nreverse events))
        (should (equal (mapcar (lambda (event)
                                 (alist-get 'type event))
                               events)
                       '(connection-pool-cleared
                         connection-checked-in
                         connection-closed)))
        (should (= (alist-get 'connection-id (caddr events)) 1))
        (should (eq (alist-get 'reason (caddr events)) 'stale))))))


(ert-deftest mongo-test-pool-clear-interrupts-in-use-connections ()
  "mongo-pool-clear should optionally close checked-out connections."
  (let ((created 0)
        disconnected closed-procs events pool conn)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn
                  :process (intern (format "proc-%d" created)))))
              ((symbol-function 'process-live-p)
               (lambda (proc)
                 (not (memq proc closed-procs))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected)
                 (push (mongo-conn-process conn) closed-procs))))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (setq pool (mongo-pool-open '(:max-pool-size 1)))
        (setq conn (mongo-pool-checkout pool))
        (setq events nil)
        (mongo-pool-clear pool nil t)
        (should (mongo-pool-paused pool))
        (should (equal disconnected (list conn)))
        (should-not (mongo--pool-connection-generation pool conn))
        (let ((ordered (nreverse events)))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 ordered)
                         '(connection-pool-cleared
                           connection-closed)))
          (should (eq (alist-get 'interrupt-in-use-connections
                                 (car ordered))
                      t))
          (should (= (alist-get 'connection-id (cadr ordered)) 1))
          (should (eq (alist-get 'reason (cadr ordered)) 'stale)))
        (setq events nil)
        (mongo-pool-release pool conn)
        (let ((ordered (nreverse events)))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 ordered)
                         '(connection-checked-in)))
          (should (= (alist-get 'connection-id (car ordered)) 1)))
        (should-not (mongo-pool-in-use pool))
        (should (equal disconnected (list conn)))))))



(ert-deftest mongo-test-pool-enforces-max-pool-size ()
  "MongoDB pools should wait and then fail when maxPoolSize is exhausted."
  (let ((created 0)
        pool conn)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn :process (intern (format "proc-%d" created)))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t)))
      (setq pool (mongo-pool-open '(:max-pool-size 1)))
      (setq conn (mongo-pool-checkout pool))
      (should-error (mongo-pool-checkout pool 0)
                    :type 'mongo-error)
      (should (= created 1))
      (mongo-pool-release pool conn)
      (should (= (length (mongo-pool-available pool)) 1)))))



(ert-deftest mongo-test-pool-tracks-connecting-during-open ()
  "MongoDB pools should count connections while they are being established."
  (let* ((pool (make-mongo-pool
                :params '(:host "127.0.0.1")
                :max-connecting 2))
         observed)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (setq observed (mongo-pool-connecting pool))
                 'conn)))
      (should (eq (mongo--pool-open-connection pool) 'conn))
      (should (= observed 1))
      (should (= (mongo-pool-connecting pool) 0)))))



(ert-deftest mongo-test-pool-decrements-connecting-on-open-error ()
  "MongoDB pools should clear connecting count when opening fails."
  (let ((pool (make-mongo-pool
               :params '(:host "127.0.0.1")
               :max-connecting 2)))
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (signal 'mongo-error
                         (list "open failed")))))
      (should-error (mongo--pool-open-connection pool)
                    :type 'mongo-error)
      (should (= (mongo-pool-connecting pool) 0)))))



(ert-deftest mongo-test-pool-honors-max-connecting ()
  "MongoDB pools should not open above maxConnecting."
  (let ((pool (make-mongo-pool
               :params '(:host "127.0.0.1")
               :max-size 5
               :min-size 0
               :max-connecting 1
               :connecting 1))
        opened)
    (cl-letf (((symbol-function 'mongo--pool-open-connection)
               (lambda (_pool)
                 (setq opened t)
                 'conn)))
      (should-error (mongo-pool-checkout pool 0)
                    :type 'mongo-error)
      (should-not opened))))



(ert-deftest mongo-test-pool-counts-connecting-against-max-pool-size ()
  "MongoDB pools should count connecting sockets against maxPoolSize."
  (let ((pool (make-mongo-pool
               :params '(:host "127.0.0.1")
               :max-size 1
               :min-size 0
               :max-connecting 2
               :connecting 1))
        opened)
    (cl-letf (((symbol-function 'mongo--pool-open-connection)
               (lambda (_pool)
                 (setq opened t)
                 'conn)))
      (should-error (mongo-pool-checkout pool 0)
                    :type 'mongo-error)
      (should-not opened))))



(ert-deftest mongo-test-pool-clear-closes-available-connections ()
  "mongo-pool-clear should close idle connections and advance generation."
  (let ((created 0)
        disconnected
        pool)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn :process (intern (format "proc-%d" created)))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (setq pool (mongo-pool-open '(:min-pool-size 2
                                    :max-pool-size 4)))
      (should (= (length (mongo-pool-available pool)) 2))
      (should (= (mongo--pool-generation pool) 0))
      (should (eq (mongo-pool-clear pool) pool))
      (should (= (mongo--pool-generation pool) 1))
      (should (mongo-pool-paused pool))
      (should-not (mongo-pool-available pool))
      (should-not (mongo-pool-conn-generations pool))
      (should (= (length disconnected) 2)))))


(ert-deftest mongo-test-pool-clear-paused-does-not-emit-duplicate-event ()
  "Clearing an already paused pool should advance generation without events."
  (let (events)
    (let ((mongo-pool-event-hook
           (list (lambda (event)
                   (push event events)))))
      (let ((pool (mongo-pool-open '(:max-pool-size 1))))
        (setq events nil)
        (mongo-pool-clear pool)
        (should (= (mongo--pool-generation pool) 1))
        (should (mongo-pool-paused pool))
        (mongo-pool-clear pool)
        (should (= (mongo--pool-generation pool) 2))
        (let ((ordered (nreverse events)))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 ordered)
                         '(connection-pool-cleared))))))))



(ert-deftest mongo-test-pool-clear-pauses-checkout-until-ready ()
  "mongo-pool-clear should pause checkout until the pool is marked ready."
  (let ((created 0)
        pool opened)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn :process (intern (format "proc-%d" created)))))
              ((symbol-function 'mongo--pool-open-connection)
               (lambda (_pool)
                 (setq opened t)
                 (make-mongo-conn :process 'new-proc))))
      (setq pool (mongo-pool-open '(:max-pool-size 2)))
      (mongo-pool-clear pool)
      (let ((err (should-error (mongo-pool-checkout pool)
                               :type 'mongo-error)))
        (should (string-match-p "connection pool was cleared"
                                (error-message-string err)))
        (should (mongo-error-has-label-p
                 err mongo--retryable-error-label)))
      (should-not opened)
      (should (eq (mongo-pool-ready pool) pool))
      (should-not (mongo-pool-paused pool))
      (should (mongo-pool-checkout pool))
      (should opened))))


(ert-deftest mongo-test-pool-monitor-success-readies-cleared-pool ()
  "Pool monitor heartbeats should mark a cleared pool ready."
  (let (events pool monitor-args)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (make-mongo-conn :process 'monitor-proc)))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-monitor-once)
               (lambda (conn max-await timeout)
                 (setq monitor-args (list conn max-await timeout))
                 '(("ok" . 1)
                   ("maxWireVersion" . 17)))))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (setq pool (mongo-pool-open '(:max-pool-size 2)))
        (setq events nil)
        (mongo-pool-clear pool)
        (should (mongo-pool-paused pool))
        (should (equal (mongo-pool-monitor-once pool 250 3)
                       '(("ok" . 1)
                         ("maxWireVersion" . 17))))
        (should-not (mongo-pool-paused pool))
        (should (eq (car monitor-args)
                    (mongo-pool-monitor-conn pool)))
        (should (equal (cdr monitor-args) '(250 3)))
        (should (equal (mapcar (lambda (event)
                                 (alist-get 'type event))
                               (nreverse events))
                       '(connection-pool-cleared
                         connection-pool-ready)))))))


(ert-deftest mongo-test-pool-monitor-error-clears-pool ()
  "Pool monitor heartbeat failures should clear and pause the pool."
  (let ((created 0)
        disconnected events pool conn monitor-conn)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn :process
                                  (intern (format "proc-%d" created)))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-disconnect)
               (lambda (wire)
                 (push wire disconnected)))
              ((symbol-function 'mongo-monitor-once)
               (lambda (conn _max-await _timeout)
                 (setq monitor-conn conn)
                 (signal 'mongo-error
                         (list "heartbeat failed")))))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (setq pool (mongo-pool-open '(:max-pool-size 2)))
        (setq conn (mongo-pool-checkout pool))
        (mongo-pool-release pool conn)
        (setq events nil)
        (should-error (mongo-pool-monitor-once pool 250 3)
                      :type 'mongo-error)
        (should (mongo-pool-paused pool))
        (should (mongo-pool-monitor-error pool))
        (should-not (mongo-pool-monitor-conn pool))
        (should-not (mongo-pool-available pool))
        (should (memq conn disconnected))
        (should (memq monitor-conn disconnected))
        (let ((ordered (nreverse events)))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 ordered)
                         '(connection-pool-cleared
                           connection-closed)))
          (should (eq (alist-get 'reason (cadr ordered)) 'stale)))))))


(ert-deftest mongo-test-pool-monitor-load-balanced-is-noop ()
  "Load-balanced pools should not open dedicated monitor connections."
  (let* ((monitor (make-mongo-conn :process 'old-monitor-proc))
         (pool (make-mongo-pool
                :params '(:load-balanced t)
                :monitor-conn monitor
                :monitor-error '(mongo-error "old")))
         disconnected)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (&rest _args)
                 (ert-fail
                  "load-balanced pool monitor should not open a connection")))
              ((symbol-function 'mongo-monitor-once)
               (lambda (&rest _args)
                 (ert-fail
                  "load-balanced pool monitor should not heartbeat")))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (should-not (mongo-pool-monitor-once pool 250 3)))
    (should-not (mongo-pool-monitor-error pool))
    (should-not (mongo-pool-monitor-conn pool))
    (should (equal disconnected (list monitor)))))


(ert-deftest mongo-test-pool-start-stop-monitor-schedules-tick ()
  "Pool monitors should schedule SDAM heartbeat ticks and stop cleanly."
  (let ((pool (make-mongo-pool
               :params '(:heartbeat-frequency-ms 1500)))
        scheduled cancelled ticked)
    (cl-letf (((symbol-function 'run-at-time)
               (lambda (secs repeat fn &rest args)
                 (setq scheduled (list secs repeat fn args))
                 'fake-pool-monitor-timer))
              ((symbol-function 'cancel-timer)
               (lambda (timer)
                 (push timer cancelled)))
              ((symbol-function 'mongo-pool-monitor-once)
               (lambda (_pool max-await timeout)
                 (setq ticked (list max-await timeout))
                 '(("ok" . 1)))))
      (should (eq (mongo-pool-start-monitor pool) pool))
      (should (eq (mongo-pool-monitor-timer pool)
                  'fake-pool-monitor-timer))
      (should (equal (list (nth 0 scheduled) (nth 1 scheduled))
                     '(0 1.5)))
      (apply (nth 2 scheduled) (nth 3 scheduled))
      (should (equal ticked '(1500 2.5)))
      (should (eq (mongo-pool-stop-monitor pool) pool))
      (should-not (mongo-pool-monitor-timer pool))
      (should (equal cancelled '(fake-pool-monitor-timer))))))


(ert-deftest mongo-test-pool-start-monitor-load-balanced-is-noop ()
  "Load-balanced pools should not schedule SDAM monitor timers."
  (let* ((monitor (make-mongo-conn :process 'old-monitor-proc))
         (pool (make-mongo-pool
                :params '(:load-balanced t)
                :monitor-conn monitor
                :monitor-timer 'old-pool-monitor-timer))
         cancelled disconnected)
    (cl-letf (((symbol-function 'cancel-timer)
               (lambda (timer)
                 (push timer cancelled)))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected)))
              ((symbol-function 'run-at-time)
               (lambda (&rest _args)
                 (ert-fail
                  "load-balanced pool monitor should not schedule a timer"))))
      (should (eq (mongo-pool-start-monitor pool) pool)))
    (should-not (mongo-pool-monitor-timer pool))
    (should-not (mongo-pool-monitor-conn pool))
    (should (equal cancelled '(old-pool-monitor-timer)))
    (should (equal disconnected (list monitor)))))


(ert-deftest mongo-test-pool-disconnect-stops-monitor ()
  "Disconnecting a pool should stop its monitor timer and connection."
  (let* ((monitor (make-mongo-conn :process 'monitor-proc))
         (pool (make-mongo-pool
                :monitor-conn monitor
                :monitor-timer 'fake-pool-monitor-timer))
         cancelled disconnected)
    (cl-letf (((symbol-function 'cancel-timer)
               (lambda (timer)
                 (push timer cancelled)))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (should (eq (mongo-pool-disconnect pool) pool))
      (should-not (mongo-pool-monitor-timer pool))
      (should-not (mongo-pool-monitor-conn pool))
      (should (equal cancelled '(fake-pool-monitor-timer)))
      (should (equal disconnected (list monitor))))))



(ert-deftest mongo-test-pool-release-after-clear-disconnects-stale-connection ()
  "Checked-out connections from old pool generations should not return to idle."
  (let ((created 0)
        disconnected
        pool conn)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn :process (intern (format "proc-%d" created)))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-disconnect)
               (lambda (wire)
                 (push wire disconnected))))
      (setq pool (mongo-pool-open '(:max-pool-size 2)))
      (setq conn (mongo-pool-checkout pool))
      (should (= (length (mongo-pool-in-use pool)) 1))
      (mongo-pool-clear pool)
      (should-not disconnected)
      (mongo-pool-release pool conn)
      (should (equal disconnected (list conn)))
      (should-not (mongo-pool-in-use pool))
      (should-not (mongo-pool-available pool))
      (should-not (mongo-pool-conn-generations pool)))))



(ert-deftest mongo-test-pool-checkout-after-clear-opens-new-generation ()
  "MongoDB pools should open new-generation connections after clear."
  (let ((created 0)
        disconnected
        pool first second)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn :process (intern (format "proc-%d" created)))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (setq pool (mongo-pool-open '(:max-pool-size 2)))
      (setq first (mongo-pool-checkout pool))
      (mongo-pool-release pool first)
      (mongo-pool-clear pool)
      (should-error (mongo-pool-checkout pool)
                    :type 'mongo-error)
      (mongo-pool-ready pool)
      (setq second (mongo-pool-checkout pool))
      (should-not (eq first second))
      (should (= created 2))
      (should (equal disconnected (list first)))
      (should (equal (mongo--pool-connection-generation pool second)
                     (mongo--pool-generation-state pool second))))))



(ert-deftest mongo-test-pool-clear-service-id-closes-only-matching-available ()
  "mongo-pool-clear with serviceId should only clear matching idle connections."
  (let* ((service-a '(("$oid" . "64f0000000000000000000aa")))
         (service-b '(("$oid" . "64f0000000000000000000bb")))
         (conn-a (make-mongo-conn :process 'proc-a :service-id service-a))
         (conn-b (make-mongo-conn :process 'proc-b :service-id service-b))
         (pool (make-mongo-pool :max-size 4
                                :max-connecting 2))
         disconnected)
    (mongo--pool-track-connection pool conn-a)
    (mongo--pool-track-connection pool conn-b)
    (setf (mongo-pool-available pool)
          (list (make-mongo--pool-entry
                 :conn conn-a
                 :idle-since (float-time)
                 :generation
                 (mongo--pool-connection-generation pool conn-a))
                (make-mongo--pool-entry
                 :conn conn-b
                 :idle-since (float-time)
                 :generation
                 (mongo--pool-connection-generation pool conn-b))))
    (cl-letf (((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (should (eq (mongo-pool-clear pool service-a) pool))
      (should-not (mongo-pool-paused pool))
      (should (= (mongo--pool-service-count pool service-a) 0))
      (should-not (assoc service-a (mongo-pool-service-generations pool)))
      (should (= (mongo--pool-service-generation pool service-b) 0))
      (should (= (mongo--pool-service-count pool service-b) 1))
      (should (equal disconnected (list conn-a)))
      (should (equal (mapcar #'mongo--pool-entry-conn
                             (mongo-pool-available pool))
                     (list conn-b)))
      (should (mongo--pool-current-generation-connection-p pool conn-b))
      (should-not (mongo--pool-current-generation-connection-p pool conn-a)))))



(ert-deftest mongo-test-pool-tracks-service-id-connection-counts ()
  "MongoDB load-balanced pools should account connections per serviceId."
  (let* ((service-a '(("$oid" . "64f0000000000000000000aa")))
         (service-b '(("$oid" . "64f0000000000000000000bb")))
         (conn-a1 (make-mongo-conn :process 'proc-a1 :service-id service-a))
         (conn-a2 (make-mongo-conn :process 'proc-a2 :service-id service-a))
         (conn-b (make-mongo-conn :process 'proc-b :service-id service-b))
         (pool (make-mongo-pool)))
    (mongo--pool-track-connection pool conn-a1)
    (mongo--pool-track-connection pool conn-a2)
    (mongo--pool-track-connection pool conn-b)
    (should (= (mongo--pool-service-count pool service-a) 2))
    (should (= (mongo--pool-service-count pool service-b) 1))
    (mongo--pool-set-service-generation pool service-a 3)
    (mongo--pool-untrack-connection pool conn-a1)
    (should (= (mongo--pool-service-count pool service-a) 1))
    (should (= (mongo--pool-service-generation pool service-a) 3))
    (mongo--pool-untrack-connection pool conn-a2)
    (should (= (mongo--pool-service-count pool service-a) 0))
    (should-not (assoc service-a (mongo-pool-service-generations pool)))
    (should (= (mongo--pool-service-count pool service-b) 1))))


(ert-deftest mongo-test-pool-retrack-uses-original-service-id-accounting ()
  "Retracking a connection should decrement the previously recorded serviceId."
  (let* ((service-a '(("$oid" . "64f0000000000000000000aa")))
         (service-b '(("$oid" . "64f0000000000000000000bb")))
         (conn (make-mongo-conn :process 'proc-a :service-id service-a))
         (pool (make-mongo-pool)))
    (mongo--pool-track-connection pool conn)
    (setf (mongo-conn-service-id conn) service-b)
    (mongo--pool-track-connection pool conn)
    (should (= (mongo--pool-service-count pool service-a) 0))
    (should (= (mongo--pool-service-count pool service-b) 1))
    (mongo--pool-untrack-connection pool conn)
    (should (= (mongo--pool-service-count pool service-b) 0))))



(ert-deftest mongo-test-pool-clear-service-id-stales-only-matching-in-use ()
  "mongo-pool-clear with serviceId should stale only matching checked-out connections."
  (let* ((service-a '(("$oid" . "64f0000000000000000000aa")))
         (service-b '(("$oid" . "64f0000000000000000000bb")))
         (conn-a (make-mongo-conn :process 'proc-a :service-id service-a))
         (conn-b (make-mongo-conn :process 'proc-b :service-id service-b))
         (pool (make-mongo-pool :max-size 4
                                :max-connecting 2
                                :in-use (list conn-a conn-b)))
         disconnected)
    (mongo--pool-track-connection pool conn-a)
    (mongo--pool-track-connection pool conn-b)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected))))
      (mongo-pool-clear pool service-a)
      (should (= (mongo--pool-service-count pool service-a) 1))
      (should (= (mongo--pool-service-generation pool service-a) 1))
      (mongo-pool-release pool conn-a)
      (mongo-pool-release pool conn-b)
      (should (equal disconnected (list conn-a)))
      (should-not (mongo-pool-in-use pool))
      (should (equal (mapcar #'mongo--pool-entry-conn
                             (mongo-pool-available pool))
                     (list conn-b)))
      (should-not (mongo--pool-connection-generation pool conn-a))
      (should (= (mongo--pool-service-count pool service-a) 0))
      (should-not (assoc service-a (mongo-pool-service-generations pool)))
      (should (= (mongo--pool-service-count pool service-b) 1))
      (should (mongo--pool-current-generation-connection-p pool conn-b)))))


(ert-deftest mongo-test-pool-clear-service-id-interrupts-only-matching-in-use ()
  "serviceId pool clear should interrupt only matching checked-out connections."
  (let* ((service-a '(("$oid" . "64f0000000000000000000aa")))
         (service-b '(("$oid" . "64f0000000000000000000bb")))
         (conn-a (make-mongo-conn :process 'proc-a :service-id service-a))
         (conn-b (make-mongo-conn :process 'proc-b :service-id service-b))
         (pool (make-mongo-pool :max-size 4
                                :max-connecting 2
                                :in-use (list conn-a conn-b)))
         disconnected closed-procs events)
    (mongo--pool-record-connection-id pool conn-a 1)
    (mongo--pool-record-connection-id pool conn-b 2)
    (mongo--pool-track-connection pool conn-a)
    (mongo--pool-track-connection pool conn-b)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (proc)
                 (not (memq proc closed-procs))))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected)
                 (push (mongo-conn-process conn) closed-procs))))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (mongo-pool-clear pool service-a t)
        (should-not (mongo-pool-paused pool))
        (should (equal disconnected (list conn-a)))
        (should-not (mongo--pool-connection-generation pool conn-a))
        (should (mongo--pool-current-generation-connection-p pool conn-b))
        (should (= (mongo--pool-service-count pool service-a) 0))
        (should (= (mongo--pool-service-count pool service-b) 1))
        (let ((ordered (nreverse events)))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 ordered)
                         '(connection-pool-cleared
                           connection-closed)))
          (should (equal (alist-get 'service-id (car ordered))
                         service-a))
          (should (eq (alist-get 'interrupt-in-use-connections
                                 (car ordered))
                      t))
          (should (= (alist-get 'connection-id (cadr ordered)) 1)))
        (setq events nil)
        (mongo-pool-release pool conn-a)
        (mongo-pool-release pool conn-b)
        (let ((ordered (nreverse events)))
          (should (equal (mapcar (lambda (event)
                                   (alist-get 'type event))
                                 ordered)
                         '(connection-checked-in
                           connection-checked-in)))
          (should (= (alist-get 'connection-id (car ordered)) 1))
          (should (= (alist-get 'connection-id (cadr ordered)) 2)))
        (should (equal disconnected (list conn-a)))
        (should (equal (mapcar #'mongo--pool-entry-conn
                               (mongo-pool-available pool))
                       (list conn-b)))))))



(ert-deftest mongo-test-pool-command-releases-connection ()
  "mongo-pool-command should release its checked-out connection."
  (let ((conn (make-mongo-conn :process 'proc))
        pool command-conn)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params) conn))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-command)
               (lambda (wire database command &optional timeout sequences)
                 (setq command-conn wire)
                 (list (cons "database" database)
                       (cons "command" command)
                       (cons "timeout" timeout)
                       (cons "sequences" sequences)))))
      (setq pool (mongo-pool-open '(:max-pool-size 1)))
      (should (equal (mongo-pool-command
                      pool "app" '(("ping" . 1)) 2
                      '(("documents" . [])))
                     `(("database" . "app")
                       ("command" . (("ping" . 1)))
                       ("timeout" . 2)
                       ("sequences" . (("documents" . []))))))
      (should (eq command-conn conn))
      (should-not (mongo-pool-in-use pool))
      (should (= (length (mongo-pool-available pool)) 1)))))


(ert-deftest mongo-test-pool-command-clears-pool-on-network-error ()
  "mongo-pool-command should clear the pool after command network errors."
  (let ((created 0)
        disconnected events pool)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params)
                 (cl-incf created)
                 (make-mongo-conn
                  :process (intern (format "proc-%d" created)))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected)))
              ((symbol-function 'mongo-command)
               (lambda (&rest _args)
                 (signal 'mongo-error
                         (list "connection closed while reading MongoDB response")))))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (setq pool (mongo-pool-open '(:min-pool-size 2
                                      :max-pool-size 2)))
        (should (= (length (mongo-pool-available pool)) 2))
        (should-error
         (mongo-pool-command pool "app" '(("ping" . 1)))
         :type 'mongo-error)
        (should (mongo-pool-paused pool))
        (should-not (mongo-pool-available pool))
        (should-not (mongo-pool-in-use pool))
        (should-not (mongo-pool-conn-generations pool))
        (should (= (mongo--pool-generation pool) 1))
        (should (= (length disconnected) 2))
        (should (seq-some (lambda (event)
                            (eq (alist-get 'type event)
                                'connection-pool-cleared))
                          events))))))


(ert-deftest mongo-test-pool-command-timeout-does-not-clear-pool ()
  "mongo-pool-command should not clear the pool after command timeouts."
  (let ((conn (make-mongo-conn :process 'proc))
        disconnected events pool)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params) conn))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected)))
              ((symbol-function 'mongo-command)
               (lambda (&rest _args)
                 (signal 'mongo-error
                         (list "Timed out waiting for MongoDB response")))))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (setq pool (mongo-pool-open '(:max-pool-size 1)))
        (should-error
         (mongo-pool-command pool "app" '(("ping" . 1)))
         :type 'mongo-error)
        (should-not (mongo-pool-paused pool))
        (should (= (mongo--pool-generation pool) 0))
        (should-not disconnected)
        (should-not (mongo-pool-in-use pool))
        (should (equal (mapcar #'mongo--pool-entry-conn
                               (mongo-pool-available pool))
                       (list conn)))
        (should-not (seq-some (lambda (event)
                                (eq (alist-get 'type event)
                                    'connection-pool-cleared))
                              events))))))


(ert-deftest mongo-test-pool-command-load-balanced-clears-service-id ()
  "mongo-pool-command should clear only the checked-out load-balanced serviceId."
  (let* ((service-a '(("$oid" . "64f0000000000000000000aa")))
         (service-b '(("$oid" . "64f0000000000000000000bb")))
         (conn-a (make-mongo-conn :process 'proc-a :service-id service-a))
         (conn-b (make-mongo-conn :process 'proc-b :service-id service-b))
         (pool (make-mongo-pool :max-size 4
                                :max-connecting 2))
         disconnected events)
    (mongo--pool-track-connection pool conn-a)
    (mongo--pool-track-connection pool conn-b)
    (setf (mongo-pool-available pool)
          (list (make-mongo--pool-entry
                 :conn conn-a
                 :idle-since (float-time)
                 :generation
                 (mongo--pool-connection-generation pool conn-a))
                (make-mongo--pool-entry
                 :conn conn-b
                 :idle-since (float-time)
                 :generation
                 (mongo--pool-connection-generation pool conn-b))))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-disconnect)
               (lambda (conn)
                 (push conn disconnected)))
              ((symbol-function 'mongo-command)
               (lambda (&rest _args)
                 (signal 'mongo-error
                         (list "connection closed while reading MongoDB response")))))
      (let ((mongo-pool-event-hook
             (list (lambda (event)
                     (push event events)))))
        (should-error
         (mongo-pool-command pool "app" '(("ping" . 1)))
         :type 'mongo-error)
        (should-not (mongo-pool-paused pool))
        (should-not (mongo-pool-in-use pool))
        (should (equal disconnected (list conn-a)))
        (should (equal (mapcar #'mongo--pool-entry-conn
                               (mongo-pool-available pool))
                       (list conn-b)))
        (should-not (assoc service-a (mongo-pool-service-generations pool)))
        (should (= (mongo--pool-service-count pool service-a) 0))
        (should (= (mongo--pool-service-count pool service-b) 1))
        (should (mongo--pool-current-generation-connection-p pool conn-b))
        (should
         (seq-some (lambda (event)
	                     (and (eq (alist-get 'type event)
	                              'connection-pool-cleared)
                          (equal (alist-get 'service-id event)
                                 service-a)))
                   events))))))



(ert-deftest mongo-test-pool-cursor-results-pins-connection-until-drained ()
  "Pooled cursor helpers should keep one connection checked out for getMore."
  (let ((conn (make-mongo-conn :process 'proc))
        pool commands in-use-states purposes)
    (cl-letf (((symbol-function 'mongo-connect)
               (lambda (_params) conn))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-command)
               (lambda (wire database command &optional _timeout _sequences)
                 (push (list wire database command) commands)
                 (push (memq conn (mongo-pool-in-use pool)) in-use-states)
                 (push (mongo--pool-connection-purpose pool conn) purposes)
                 (cond
                  ((assoc "find" command)
                   '(("cursor" . (("id" . 42)
                                  ("ns" . "app.users")
                                  ("firstBatch" . ((("n" . 1))))))))
                  ((assoc "getMore" command)
                   '(("cursor" . (("id" . 0)
                                  ("ns" . "app.users")
                                  ("nextBatch" . ((("n" . 2))))))))
                  (t
                   (ert-fail
                    (format "unexpected command: %S" command)))))))
      (setq pool (mongo-pool-open '(:max-pool-size 1)))
      (should (equal
               (mongo-pool-cursor-results
                pool "app" "users"
                '(("find" . "users")
                  ("filter" . (("active" . t))))
                "firstBatch")
               '((("n" . 1))
                 (("n" . 2)))))
      (should (equal (mapcar (lambda (entry)
                               (list (eq (nth 0 entry) conn)
                                     (nth 1 entry)
                                     (caar (nth 2 entry))))
                             (nreverse commands))
                     '((t "app" "find")
                       (t "app" "getMore"))))
      (should (equal (nreverse in-use-states)
                     (list (list conn) (list conn))))
      (should (equal (nreverse purposes)
                     '(cursor cursor)))
      (should-not (mongo-pool-in-use pool))
      (should-not (mongo-pool-conn-purposes pool))
      (should (equal (mapcar #'mongo--pool-entry-conn
                             (mongo-pool-available pool))
                     (list conn))))))


(ert-deftest mongo-test-pool-cursor-load-balanced-getmore-error-skips-kill ()
  "Load-balanced pooled cursors should not killCursors after getMore network errors."
  (let* ((service-id '(("$oid" . "64f0000000000000000000aa")))
         (conn (make-mongo-conn :process 'proc
                                :load-balanced t
                                :service-id service-id))
         (pool (make-mongo-pool :params '(:load-balanced t)
                                :max-size 1
                                :max-connecting 2))
         disconnected commands)
    (mongo--pool-record-connection-id pool conn 1)
    (mongo--pool-track-connection pool conn)
    (setf (mongo-pool-available pool)
          (list (make-mongo--pool-entry
                 :conn conn
                 :idle-since (float-time)
                 :generation
                 (mongo--pool-connection-generation pool conn))))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-disconnect)
               (lambda (wire)
                 (push wire disconnected)))
              ((symbol-function 'mongo-command)
               (lambda (_wire _database command &optional _timeout _sequences)
                 (push command commands)
                 (cond
                  ((assoc "find" command)
                   '(("cursor" . (("id" . 42)
                                  ("ns" . "app.users")
                                  ("firstBatch" . ((("n" . 1))))))))
                  ((assoc "getMore" command)
                   (signal 'mongo-error
                           (list "connection closed while reading MongoDB response")))
                  ((assoc "killCursors" command)
                   (ert-fail
                    "load-balanced getMore network errors should not killCursors"))
                  (t
                   (ert-fail
                    (format "unexpected command: %S" command)))))))
      (should-error
       (mongo-pool-cursor-results
        pool "app" "users"
        '(("find" . "users")) "firstBatch")
       :type 'mongo-error)
      (should-not (mongo-pool-paused pool))
      (should-not (mongo-pool-in-use pool))
      (should-not (mongo-pool-available pool))
      (should (equal disconnected (list conn)))
      (should (= (mongo--pool-service-count pool service-id) 0))
      (should (equal (mapcar #'caar (nreverse commands))
                     '("find" "getMore"))))))


(ert-deftest mongo-test-pool-find-uses-pool-cursor-results ()
  "mongo-pool-find should build a find command for pooled cursor draining."
  (let (captured)
    (cl-letf (((symbol-function 'mongo-pool-cursor-results)
               (lambda (&rest args)
                 (setq captured args)
                 '((("name" . "Ann"))))))
      (should (equal
               (mongo-pool-find
                'pool "app" "users"
                '(("active" . t)) '(("name" . 1)) 5 2
                '(("batchSize" . 3)))
               '((("name" . "Ann"))))))
    (should (equal captured
                   '(pool "app" "users"
                          (("find" . "users")
                           ("filter" . (("active" . t)))
                           ("batchSize" . 3)
                           ("projection" . (("name" . 1)))
                           ("limit" . 5)
                           ("skip" . 2))
                          "firstBatch" nil
                          (("batchSize" . 3)))))))



(ert-deftest mongo-test-bulk-write-command-builds-sequences ()
  "MongoDB bulkWrite should build command and OP_MSG sequences."
  (let* ((command-and-sequences
          (mongo-bulk-write-command
           '((("insert" . "app.users")
              ("document" . (("name" . "Ann"))))
             (("update" . "app.users")
              ("filter" . (("name" . "Ann")))
              ("updateMods" . (("$set" . (("score" . 2)))))
              ("multi" . :false))
             (("delete" . "app.audit")
              ("filter" . (("level" . "debug")))
              ("multi" . t)))
           '(("ordered" . :false)
             ("verboseResults" . t)
             ("comment" . "bulk-test"))))
         (command (car command-and-sequences))
         (sequences (cdr command-and-sequences))
         (ops (cdr (assoc "ops" sequences)))
         (ns-info (cdr (assoc "nsInfo" sequences))))
    (should (equal command
                   '(("bulkWrite" . 1)
                     ("ordered" . :false)
                     ("errorsOnly" . :false)
                     ("comment" . "bulk-test"))))
    (should (= (length ops) 3))
    (should (= (length ns-info) 2))
    (should (equal (aref ns-info 0) '(("ns" . "app.users"))))
    (should (equal (aref ns-info 1) '(("ns" . "app.audit"))))
    (should (equal (cdr (assoc "insert" (aref ops 0))) 0))
    (should (mongo--document-has-field-p
             (cdr (assoc "document" (aref ops 0)))
             "_id"))
    (should (equal (cdr (assoc "update" (aref ops 1))) 0))
    (should (equal (cdr (assoc "delete" (aref ops 2))) 1))))



(ert-deftest mongo-test-bulk-write-validates-inputs ()
  "MongoDB bulkWrite should reject invalid native helper inputs."
  (should-error (mongo-bulk-write-command nil)
                :type 'mongo-error)
  (should-error
   (mongo-bulk-write-command
    '((("insert" . "app.users")
       ("update" . "app.users")
       ("document" . (("name" . "Ann"))))))
   :type 'mongo-error)
  (should-error
   (mongo-bulk-write-command
    '((("insert" . "app.users"))))
   :type 'mongo-error)
  (let ((conn (make-mongo-conn
               :write-concern
               (make-mongo--write-concern :pairs '(("w" . 0))))))
    (should-error
     (mongo-bulk-write
      conn
      '((("insert" . "app.users")
         ("document" . (("name" . "Ann"))))))
     :type 'mongo-error)
    (should-error
     (mongo-bulk-write
      conn
      '((("insert" . "app.users")
         ("document" . (("name" . "Ann")))))
      '(("ordered" . :false)
        ("verboseResults" . t)))
     :type 'mongo-error)))



(ert-deftest mongo-test-bulk-write-sends-admin-command ()
  "mongo-bulk-write should send admin bulkWrite and collect cursor results."
  (let ((conn (make-mongo-conn :process 'proc))
        captured-database captured-command captured-sequences)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout sequences)
                 (setq captured-database database
                       captured-command command
                       captured-sequences sequences)
                 '(("ok" . 1)
                   ("cursor" .
                    (("id" . 0)
                     ("ns" . "admin.$cmd.bulkWrite")
                     ("firstBatch" .
                      [(("ok" . 1)
                        ("idx" . 0))])))))))
      (let ((response
             (mongo-bulk-write
              conn
              '((("insert" . "app.users")
                 ("document" . (("name" . "Ann")))))
              '(("ordered" . :false)))))
        (should (equal captured-database "admin"))
        (should (equal (cdr (assoc "bulkWrite" captured-command)) 1))
        (should (equal (cdr (assoc "ordered" captured-command)) :false))
        (should (equal (cdr (assoc "errorsOnly" captured-command)) t))
        (should (assoc "ops" captured-sequences))
        (should (assoc "nsInfo" captured-sequences))
        (should (equal (cdr (assoc "results" response))
                       [(("ok" . 1)
                         ("idx" . 0))]))))))


(ert-deftest mongo-test-bulk-write-splits-at-max-write-batch-size ()
  "mongo-bulk-write should split batches and merge result indexes."
  (let ((conn (make-mongo-conn :process 'proc
                               :max-write-batch-size 2))
        calls)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout sequences)
                 (let* ((ops (cdr (assoc "ops" sequences)))
                        (batch-results
                         (cl-loop for index below (length ops)
                                  collect `(("ok" . 1)
                                            ("idx" . ,index)))))
                   (push (list database command sequences) calls)
                   `(("ok" . 1)
                     ("nInserted" . ,(length ops))
                     ("cursor" .
                      (("id" . 0)
                       ("ns" . "admin.$cmd.bulkWrite")
                       ("firstBatch" . ,(vconcat batch-results)))))))))
      (let ((response
             (mongo-bulk-write
              conn
              '((("insert" . "app.users")
                 ("document" . (("name" . "Ann"))))
                (("insert" . "app.users")
                 ("document" . (("name" . "Bob"))))
                (("insert" . "app.users")
                 ("document" . (("name" . "Cal")))))
              '(("ordered" . :false)
                ("verboseResults" . t)))))
        (setq calls (nreverse calls))
        (should (= (length calls) 2))
        (should (equal (mapcar (lambda (call)
                                 (length (cdr (assoc "ops" (nth 2 call)))))
                               calls)
                       '(2 1)))
        (should (equal (cdr (assoc "nInserted" response)) 3))
        (should (equal (cdr (assoc "results" response))
                       [(("ok" . 1) ("idx" . 0))
                        (("ok" . 1) ("idx" . 1))
                        (("ok" . 1) ("idx" . 2))]))))))


(ert-deftest mongo-test-bulk-write-ordered-stops-after-batch-error ()
  "Ordered mongo-bulk-write should not send later batches after errors."
  (let ((conn (make-mongo-conn :process 'proc
                               :max-write-batch-size 1))
        calls)
    (cl-letf (((symbol-function 'mongo-command)
               (lambda (_conn database command &optional _timeout sequences)
                 (push (list database command sequences) calls)
                 '(("ok" . 1)
                   ("nErrors" . 1)
                   ("cursor" .
                    (("id" . 0)
                     ("ns" . "admin.$cmd.bulkWrite")
                     ("firstBatch" .
                      [(("ok" . :false)
                        ("idx" . 0)
                        ("code" . 11000))])))))))
      (let ((response
             (mongo-bulk-write
              conn
              '((("insert" . "app.users")
                 ("document" . (("name" . "Ann"))))
                (("insert" . "app.users")
                 ("document" . (("name" . "Bob"))))))))
        (should (= (length calls) 1))
        (should (equal (cdr (assoc "nErrors" response)) 1))
        (should (equal (cdr (assoc "results" response))
                       [(("ok" . :false)
                         ("idx" . 0)
                         ("code" . 11000))]))))))



(ert-deftest mongo-test-command-refreshes-before-write-when-not-writable ()
  "Write commands should refresh topology before sending if no writable server is known."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil))
         (secondary-hello '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("secondary" . t)))
         (primary-hello '(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t)))
         events)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn secondary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-hello)
               (lambda (refresh-conn &optional _timeout)
                 (push :hello events)
                 (setf (mongo-conn-topology refresh-conn)
                       (mongo--topology-description-from-hello
                        refresh-conn primary-hello))
                 primary-hello))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document)
                 (push (list :send document) events)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (should (equal (mongo-command
                      conn
                      "app"
                      '(("insert" . "users")
                        ("documents" . [])))
                     '(("ok" . 1)))))
    (should (equal (car (last events))
                   :hello))
    (should (equal (caar events) :send))
    (should (mongo-select-server conn 'write))))



(ert-deftest mongo-test-command-rejects-write-when-refresh-finds-no-primary ()
  "Write commands should not be sent when refresh still finds no writable server."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil))
         (secondary-hello '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("secondary" . t)))
         refreshed)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn secondary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-hello)
               (lambda (_conn &optional _timeout)
                 (setq refreshed t)
                 secondary-hello))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "write command should not be sent"))))
      (let ((err (should-error
                  (mongo-command
                   conn
                   "app"
                   '(("insert" . "users")
                     ("documents" . [])))
                  :type 'mongo-error)))
        (should refreshed)
        (should (string-match-p "No writable MongoDB server"
                                (error-message-string err)))))))



(ert-deftest mongo-test-command-refreshes-after-not-writable-error ()
  "NotWritablePrimary errors should refresh cached topology before surfacing."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil))
         (primary-hello '(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t)))
         refreshed)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 0)
                   ("codeName" . "NotWritablePrimary")
                   ("errmsg" . "not writable primary"))))
              ((symbol-function 'mongo-hello)
               (lambda (_conn &optional _timeout)
                 (setq refreshed t)
                 primary-hello)))
      (let ((err (should-error
                  (mongo-command
                   conn
                   "app"
                   '(("insert" . "users")
                     ("documents" . [])))
                  :type 'mongo-error)))
        (should refreshed)
        (should (string-match-p "not writable primary"
                                (error-message-string err)))))))



(ert-deftest mongo-test-command-state-change-error-marks-unknown ()
  "Fresh state-change errors should mark the current server Unknown."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :retry-reads nil))
         (old-version '(("processId" .
                         (("$oid" . "64f000000000000000000001")))
                        ("counter" . 1)))
         (new-version '(("processId" .
                         (("$oid" . "64f000000000000000000001")))
                        ("counter" . 2)))
         (primary-hello `(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t)
                          ("topologyVersion" . ,old-version))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 `(("ok" . 0)
                   ("codeName" . "NotPrimaryOrSecondary")
                   ("errmsg" . "node is recovering")
                   ("topologyVersion" . ,new-version)))))
      (let ((err (should-error
                  (mongo-command conn "app" '(("find" . "users")))
                  :type 'mongo-error)))
        (should (string-match-p "node is recovering"
                                (error-message-string err)))))
    (let ((server (mongo--current-server-description conn)))
      (should (eq (mongo-topology-description-type
                   (mongo-conn-topology conn))
                  'replica-set-no-primary))
      (should (eq (mongo-server-description-type server) 'unknown))
      (should (equal (mongo-server-description-topology-version server)
                     new-version))
      (should (string-match-p
               "node is recovering"
               (mongo-server-description-error server))))))



(ert-deftest mongo-test-command-stale-state-change-error-is-ignored ()
  "Stale state-change errors should not overwrite a newer server description."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :retry-writes nil))
         (topology-version '(("processId" .
                              (("$oid" . "64f000000000000000000002")))
                             ("counter" . 5)))
         (primary-hello `(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t)
                          ("topologyVersion" . ,topology-version)))
         refreshed)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 `(("ok" . 0)
                   ("codeName" . "NotWritablePrimary")
                   ("errmsg" . "not writable primary")
                   ("topologyVersion" . ,topology-version))))
              ((symbol-function 'mongo-hello)
               (lambda (&rest _args)
                 (setq refreshed t)
                 primary-hello)))
      (let ((err (should-error
                  (mongo-command
                   conn "app"
                   '(("insert" . "users")
                     ("documents" . [])))
                  :type 'mongo-error)))
        (should (string-match-p "not writable primary"
                                (error-message-string err)))))
    (should-not refreshed)
    (let ((server (mongo--current-server-description conn)))
      (should (eq (mongo-topology-description-type
                   (mongo-conn-topology conn))
                  'replica-set-with-primary))
      (should (eq (mongo-server-description-type server) 'rs-primary))
      (should (equal (mongo-server-description-topology-version server)
                     topology-version)))))



(ert-deftest mongo-test-command-state-change-without-version-marks ()
  "State-change errors without topologyVersion should still mark Unknown."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :retry-writes nil))
         (primary-hello '(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 0)
                   ("codeName" . "NotWritablePrimary")
                   ("errmsg" . "not writable primary"))))
              ((symbol-function 'mongo-hello)
               (lambda (refresh-conn &rest _args)
                 (let ((hello '(("ok" . 1)
                                ("maxWireVersion" . 17)
                                ("setName" . "rs0")
                                ("secondary" . t))))
                   (setf (mongo-conn-topology refresh-conn)
                         (mongo--topology-description-from-hello
                          refresh-conn hello))
                   hello))))
      (should-error
       (mongo-command
        conn "app"
        '(("insert" . "users")
          ("documents" . [])))
       :type 'mongo-error))
    (let ((server (mongo--current-server-description conn)))
      (should (eq (mongo-server-description-type server) 'rs-secondary)))))



(ert-deftest mongo-test-command-retries-read-network-error ()
  "Retryable read commands should retry once after a network read error."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :retry-reads t))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)))
         sends
         (recv-count 0)
         reconnected)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (push document sends)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (cl-incf recv-count)
                 (if (= recv-count 1)
                     (signal 'mongo-error
                             (list "Timed out waiting for MongoDB response"))
                   '(("ok" . 1)
                     ("cursor" .
                      (("id" . 0)
                       ("firstBatch" . [])))))))
              ((symbol-function 'mongo--reconnect-current-server)
               (lambda (retry-conn)
                 (setq reconnected t)
                 (setf (mongo-conn-topology retry-conn)
                       (mongo--topology-description-from-hello
                        retry-conn hello))
                 retry-conn)))
      (should (equal (mongo-command conn "app" '(("find" . "users")))
                     '(("ok" . 1)
                       ("cursor" .
                        (("id" . 0)
                         ("firstBatch" . [])))))))
    (should reconnected)
    (should (= recv-count 2))
    (should (= (length sends) 2))))



(ert-deftest mongo-test-command-retries-read-server-error ()
  "Retryable read commands should retry once after retryable server errors."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :retry-reads t))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)))
         (recv-count 0)
         reconnected)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (cl-incf recv-count)
                 (if (= recv-count 1)
                     '(("ok" . 0)
                       ("code" . 91)
                       ("codeName" . "ShutdownInProgress")
                       ("errmsg" . "shutting down"))
                   '(("ok" . 1)
                     ("cursor" .
                      (("id" . 0)
                       ("firstBatch" . [])))))))
              ((symbol-function 'mongo--reconnect-current-server)
               (lambda (retry-conn)
                 (setq reconnected t)
                 (setf (mongo-conn-topology retry-conn)
                       (mongo--topology-description-from-hello
                        retry-conn hello))
                 retry-conn)))
      (should (equal (mongo-command conn "app" '(("find" . "users")))
                     '(("ok" . 1)
                       ("cursor" .
                        (("id" . 0)
                         ("firstBatch" . [])))))))
    (should reconnected)
    (should (= recv-count 2))))



(ert-deftest mongo-test-command-honors-retry-reads-false ()
  "retryReads=false should leave read commands as a single attempt."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :retry-reads nil))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)))
         (recv-count 0))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (cl-incf recv-count)
                 (signal 'mongo-error
                         (list "Timed out waiting for MongoDB response"))))
              ((symbol-function 'mongo--reconnect-current-server)
               (lambda (&rest _args)
                 (ert-fail "retryReads=false should not reconnect"))))
      (should-error (mongo-command conn "app" '(("find" . "users")))
                    :type 'mongo-error))
    (should (= recv-count 1))))



(ert-deftest mongo-test-command-does-not-retry-getmore ()
  "Cursor getMore should not be retried by retryable reads."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :retry-reads t))
         (recv-count 0))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (cl-incf recv-count)
                 (signal 'mongo-error
                         (list "Timed out waiting for MongoDB response"))))
              ((symbol-function 'mongo--reconnect-current-server)
               (lambda (&rest _args)
                 (ert-fail "getMore should not retry"))))
      (should-error
       (mongo-command conn
                      "app"
                      '(("getMore" . 123)
                        ("collection" . "users")))
       :type 'mongo-error))
    (should (= recv-count 1))))



(ert-deftest mongo-test-transaction-first-and-next-command-fields ()
  "Transaction commands should add startTransaction only once."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "mongos-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         sends)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (push document sends)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-start-transaction
       conn
       '(("readConcern" . (("level" . "snapshot")))))
      (should (eq (mongo-conn-transaction-state conn) 'starting))
      (mongo-command conn "app" '(("ping" . 1)))
      (should (eq (mongo-conn-transaction-state conn) 'in-progress))
      (mongo-command conn "app" '(("ping" . 1))))
    (setq sends (nreverse sends))
    (should (equal (cdr (assoc "lsid" (nth 0 sends))) session-id))
    (should (equal (cdr (assoc "txnNumber" (nth 0 sends)))
                   (mongo-int64 1)))
    (should (eq (cdr (assoc "autocommit" (nth 0 sends))) :false))
    (should (eq (cdr (assoc "startTransaction" (nth 0 sends))) t))
    (should (equal (cdr (assoc "readConcern" (nth 0 sends)))
                   '(("level" . "snapshot"))))
    (should (equal (cdr (assoc "txnNumber" (nth 1 sends)))
                   (mongo-int64 1)))
    (should (eq (cdr (assoc "autocommit" (nth 1 sends))) :false))
	    (should-not (assoc "startTransaction" (nth 1 sends)))
	    (should-not (assoc "readConcern" (nth 1 sends)))))



(ert-deftest mongo-test-transaction-recovery-token-commit ()
  "commitTransaction should include the latest transaction recoveryToken."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (token-a '(("shard" . "a")))
         (token-b '(("shard" . "b")))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         sends
         (recv-count 0))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (push document sends)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (cl-incf recv-count)
                 (cond
                  ((= recv-count 1)
                   `(("ok" . 1)
                     ("recoveryToken" . ,token-a)))
                  ((= recv-count 2)
                   `(("ok" . 1)
                     ("recoveryToken" . ,token-b)))
                  (t
                   '(("ok" . 1)))))))
      (mongo-start-transaction conn)
      (mongo-command conn "app" '(("ping" . 1)))
      (should (equal (mongo-conn-transaction-recovery-token conn)
                     token-a))
      (mongo-command conn "app" '(("ping" . 1)))
      (should (equal (mongo-conn-transaction-recovery-token conn)
                     token-b))
      (mongo-commit-transaction conn))
    (setq sends (nreverse sends))
    (should (= (length sends) 3))
    (should-not (assoc "recoveryToken" (nth 0 sends)))
    (should-not (assoc "recoveryToken" (nth 1 sends)))
    (should (equal (cdr (assoc "recoveryToken" (nth 2 sends)))
                   token-b))
    (should (eq (mongo-conn-transaction-state conn) 'committed))
    (should (equal (mongo-conn-transaction-recovery-token conn)
                   token-b))
    (should-not (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-recovery-token-abort ()
  "abortTransaction should include cached transaction recoveryToken."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (token '(("shard" . "a") ("txn" . 1)))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("msg" . "isdbgrid")))
         captured)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-start-transaction
       conn
       '(("writeConcern" . (("w" . "majority")))))
      (setf (mongo-conn-transaction-state conn) 'in-progress)
      (setf (mongo-conn-transaction-recovery-token conn) token)
      (setf (mongo-conn-transaction-pinned-address conn) "seed-a:27017")
      (mongo-abort-transaction conn))
    (should (equal captured
                   `(("abortTransaction" . 1)
                     ("writeConcern" . (("w" . "majority")))
                     ("recoveryToken" . ,token)
                     ("$db" . "admin")
                     ("lsid" . ,session-id)
                     ("txnNumber" . ,(mongo-int64 1))
                     ("autocommit" . :false))))
    (should (eq (mongo-conn-transaction-state conn) 'aborted))
    (should (equal (mongo-conn-transaction-recovery-token conn)
                   token))
    (should-not (mongo-conn-transaction-pinned-address conn))
    (should-not (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-recovery-token-retry-preserves ()
  "Transaction control retries should preserve cached recoveryToken."
  (let* ((token '(("shard" . "a")))
         (read-preference
          (mongo--params-read-preference '(:read-preference primary)))
         (service-id '(("$oid" . "64f000000000000000000001")))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :transaction-state 'in-progress
                                :transaction-number (mongo-int64 4)
                                :transaction-read-preference read-preference
                                :transaction-read-concern
                                '(("level" . "snapshot"))
                                :transaction-write-concern
                                '(("w" . "majority"))
                                :transaction-max-commit-time-ms 2500
                                :transaction-recovery-token token
                                :transaction-pinned-address
                                "seed-a:27017"
                                :transaction-pinned-service-id service-id
                                :transaction-commit-sent t)))
    (cl-letf (((symbol-function 'mongo--retry-write-once)
               (lambda (retry-conn _err)
                 (should-not
                  (mongo-conn-transaction-pinned-address retry-conn))
                 (should-not
                  (mongo-conn-transaction-pinned-service-id retry-conn))
                 (setf (mongo-conn-transaction-state retry-conn) nil)
                 (setf (mongo-conn-transaction-number retry-conn) nil)
                 (setf (mongo-conn-transaction-read-preference retry-conn)
                       nil)
                 (setf (mongo-conn-transaction-read-concern retry-conn) nil)
                 (setf (mongo-conn-transaction-write-concern retry-conn) nil)
                 (setf (mongo-conn-transaction-max-commit-time-ms retry-conn)
                       nil)
                 (setf (mongo-conn-transaction-recovery-token retry-conn) nil)
                 (setf (mongo-conn-transaction-commit-sent retry-conn) nil)
                 retry-conn)))
      (mongo--retry-transaction-control-once
       conn
       (list 'mongo-error "network failure")))
    (should (eq (mongo-conn-transaction-state conn) 'in-progress))
    (should (equal (mongo-conn-transaction-number conn) (mongo-int64 4)))
    (should (equal (mongo-conn-transaction-read-preference conn)
                   read-preference))
    (should (equal (mongo-conn-transaction-read-concern conn)
                   '(("level" . "snapshot"))))
    (should (equal (mongo-conn-transaction-write-concern conn)
                   '(("w" . "majority"))))
    (should (= (mongo-conn-transaction-max-commit-time-ms conn) 2500))
    (should (equal (mongo-conn-transaction-recovery-token conn) token))
    (should-not (mongo-conn-transaction-pinned-address conn))
    (should-not (mongo-conn-transaction-pinned-service-id conn))
    (should (eq (mongo-conn-transaction-commit-sent conn) t))))



(ert-deftest mongo-test-transaction-pins-mongos-after-first-command ()
  "Sharded transactions should pin to the selected mongos."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "mongos-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("msg" . "isdbgrid"))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-start-transaction conn)
      (mongo-command conn "app" '(("insert" . "users")))
      (should (equal (mongo-conn-transaction-pinned-address conn)
                     "mongos-a:27017"))
      (should-not (mongo-conn-transaction-pinned-service-id conn))
      (mongo-commit-transaction conn))
    (should (eq (mongo-conn-transaction-state conn) 'committed))
    (should (equal (mongo-conn-transaction-pinned-address conn)
                   "mongos-a:27017"))))



(ert-deftest mongo-test-transaction-load-balanced-pins-service-id ()
  "Load-balanced transactions should pin to the selected serviceId."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (service-id '(("$oid" . "64f000000000000000000001")))
         (conn (make-mongo-conn :host "lb"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id
                                :load-balanced t
                                :service-id service-id))
         (hello `(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("serviceId" . ,service-id))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-start-transaction conn)
      (mongo-command conn "app" '(("insert" . "users"))))
    (should (equal (mongo-conn-transaction-pinned-address conn)
                   "lb:27017"))
    (should (equal (mongo-conn-transaction-pinned-service-id conn)
                   service-id))))



(ert-deftest mongo-test-transaction-rejects-pinned-server-change ()
  "Commands in a transaction should stay on the pinned mongos."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "mongos-b"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :session-id session-id
                                :transaction-state 'in-progress
                                :transaction-number (mongo-int64 1)
                                :transaction-pinned-address
                                "mongos-a:27017"))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("msg" . "isdbgrid"))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "pinned server mismatch should fail before send"))))
      (let ((err (should-error
                  (mongo-command conn "app" '(("insert" . "users")))
                  :type 'mongo-error)))
        (should (string-match-p "transaction is pinned"
                                (error-message-string err)))))))



(ert-deftest mongo-test-transaction-rejects-explicit-unacknowledged-write-concern ()
  "Transactions should reject explicit unacknowledged writeConcern."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t)))
      (let ((err (should-error
                  (mongo-start-transaction
                   conn
                   '(("writeConcern" . (("w" . 0)))))
                  :type 'mongo-error)))
        (should (string-match-p
                 "transactions do not support unacknowledged write concerns"
                 (error-message-string err)))))
    (should-not (mongo-conn-transaction-state conn))
    (should (= (mongo-conn-txn-number conn) 0))))



(ert-deftest mongo-test-transaction-rejects-inherited-unacknowledged-write-concern ()
  "Transactions should reject inherited unacknowledged writeConcern."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id
                                :write-concern
                                (mongo--params-write-concern '(:w 0)))))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t)))
      (let ((err (should-error
                  (mongo-start-transaction conn)
                  :type 'mongo-error)))
        (should (string-match-p
                 "transactions do not support unacknowledged write concerns"
                 (error-message-string err)))))
    (should-not (mongo-conn-transaction-state conn))
    (should (= (mongo-conn-txn-number conn) 0))))



(ert-deftest mongo-test-transaction-requires-logical-session-support ()
  "Transactions should not create sessions when the server lacks support."
  (let ((conn (make-mongo-conn :host "seed-a"
                               :port 27017
                               :database "app"
                               :process 'proc
                               :closed nil
                               :max-wire-version 17
                               :txn-number 0)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t)))
      (let ((err (should-error
                  (mongo-start-transaction conn)
                  :type 'mongo-error)))
        (should (string-match-p
                 "logical session support"
                 (error-message-string err)))))
    (should-not (mongo-conn-session-id conn))
    (should-not (mongo-conn-transaction-state conn))
    (should (= (mongo-conn-txn-number conn) 0))))



(ert-deftest mongo-test-transaction-creates-session-from-hello-support ()
  "Transactions may create an lsid after hello reports session support."
  (let ((conn (make-mongo-conn :host "seed-a"
                               :port 27017
                               :database "app"
                               :process 'proc
                               :closed nil
                               :max-wire-version 17
                               :txn-number 0
                               :last-hello
                               '(("ok" . 1)
                                 ("logicalSessionTimeoutMinutes" . 30)))))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t)))
      (mongo-start-transaction conn))
    (should (mongo-conn-session-id conn))
    (should (eq (mongo-conn-transaction-state conn) 'starting))
    (should (equal (mongo-conn-transaction-number conn)
                   (mongo-int64 1)))))


(ert-deftest mongo-test-transaction-load-balanced-creates-session ()
  "Load-balanced transactions should not require logicalSessionTimeoutMinutes."
  (let ((conn (make-mongo-conn :host "lb"
                               :port 27017
                               :database "app"
                               :process 'proc
                               :closed nil
                               :max-wire-version 17
                               :txn-number 0
                               :load-balanced t
                               :service-id
                               '(("$oid" . "64f0000000000000000000aa"))
                               :last-hello
                               '(("ok" . 1)
                                 ("serviceId" .
                                  (("$oid" . "64f0000000000000000000aa")))))))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t)))
      (mongo-start-transaction conn))
    (should (mongo-conn-session-id conn))
    (should (eq (mongo-conn-transaction-state conn) 'starting))
    (should (equal (mongo-conn-transaction-number conn)
                   (mongo-int64 1)))))



(ert-deftest mongo-test-transaction-inherits-connection-write-concern ()
  "Transactions should use connection writeConcern when no option overrides it."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id
                                :write-concern
                                (mongo--params-write-concern
                                 '(:w majority :w-timeout-ms 2500))))
         captured)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-start-transaction conn)
      (setf (mongo-conn-transaction-state conn) 'in-progress)
      (mongo-commit-transaction conn))
    (should (equal (cdr (assoc "writeConcern" captured))
                   '(("w" . "majority")
                     ("wtimeout" . 2500))))
    (should (eq (mongo-conn-transaction-state conn) 'committed))
    (should-not (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-commit-uses-max-commit-time-ms ()
  "commitTransaction should include transaction option maxCommitTimeMS as maxTimeMS."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         captured)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-start-transaction
       conn
       '(("maxCommitTimeMS" . 2500)))
      (setf (mongo-conn-transaction-state conn) 'in-progress)
      (mongo-commit-transaction conn))
    (should (= (cdr (assoc "maxTimeMS" captured)) 2500))
    (should (eq (mongo-conn-transaction-state conn) 'committed))))



(ert-deftest mongo-test-transaction-commit-argument-overrides-max-commit-time-ms ()
  "Explicit mongo-commit-transaction maxTimeMS should override maxCommitTimeMS."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         captured)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-start-transaction
       conn
       '(("maxCommitTimeMS" . 2500)))
      (setf (mongo-conn-transaction-state conn) 'in-progress)
      (mongo-commit-transaction conn 5000))
    (should (= (cdr (assoc "maxTimeMS" captured)) 5000))
    (should (eq (mongo-conn-transaction-state conn) 'committed))))



(ert-deftest mongo-test-transaction-rejects-negative-max-commit-time-ms ()
  "startTransaction should reject negative maxCommitTimeMS without changing state."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t)))
      (let ((err (should-error
                  (mongo-start-transaction
                   conn
                   '(("maxCommitTimeMS" . -1)))
                  :type 'mongo-error)))
        (should (string-match-p "maxCommitTimeMS"
                                (error-message-string err)))))
    (should-not (mongo-conn-transaction-state conn))
    (should (= (mongo-conn-txn-number conn) 0))))



(ert-deftest mongo-test-transaction-rejects-negative-commit-max-time-ms ()
  "mongo-commit-transaction should reject negative maxTimeMS without changing state."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "invalid maxTimeMS should fail before send"))))
      (mongo-start-transaction conn)
      (setf (mongo-conn-transaction-state conn) 'in-progress)
      (let ((err (should-error
                  (mongo-commit-transaction conn -1)
                  :type 'mongo-error)))
        (should (string-match-p "maxTimeMS"
                                (error-message-string err)))))
    (should (eq (mongo-conn-transaction-state conn) 'in-progress))
    (should (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-read-requires-primary-read-preference ()
  "Transaction read operations should reject non-primary readPreference."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn
                :host "seed-a"
                :port 27017
                :database "app"
                :process 'proc
                :closed nil
                :max-wire-version 17
                :txn-number 0
                :session-id session-id
                :read-preference
                (mongo--params-read-preference
                 '(:read-preference secondary)))))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "transaction read should fail before send"))))
      (mongo-start-transaction conn)
      (let ((err (should-error
                  (mongo-command conn "app" '(("find" . "users")))
                  :type 'mongo-error)))
        (should (string-match-p "read preference in a transaction must be primary"
                                (error-message-string err))))
      (should (eq (mongo-conn-transaction-state conn) 'starting)))))



(ert-deftest mongo-test-transaction-read-preference-option-overrides-connection ()
  "Transaction readPreference should override connection readPreference."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn
                :host "seed-a"
                :port 27017
                :database "app"
                :process 'proc
                :closed nil
                :max-wire-version 17
                :txn-number 0
                :session-id session-id
                :read-preference
                (mongo--params-read-preference
                 '(:read-preference secondary))))
         (primary-hello '(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t)))
         captured)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-start-transaction
       conn
       '(("readPreference" . "primary")))
      (mongo-command conn "app" '(("find" . "users"))))
    (should (eq (mongo-conn-transaction-state conn) 'in-progress))
    (should (equal (mongo--read-preference-mode
                    (mongo-conn-transaction-read-preference conn))
                   "primary"))
    (should (eq (cdr (assoc "startTransaction" captured)) t))
    (should (eq (cdr (assoc "autocommit" captured)) :false))
    (should-not (assoc "$readPreference" captured))))



(ert-deftest mongo-test-transaction-read-preference-option-rejects-non-primary-read ()
  "Transaction readPreference=secondary should reject read operations."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "non-primary transaction readPreference should fail before send"))))
      (mongo-start-transaction
       conn
       '(("readPreference" . (("mode" . "secondary")))))
      (let ((err (should-error
                  (mongo-command conn "app" '(("find" . "users")))
                  :type 'mongo-error)))
        (should (string-match-p "read preference in a transaction must be primary"
                                (error-message-string err)))))
    (should (eq (mongo-conn-transaction-state conn) 'starting))))



(ert-deftest mongo-test-transaction-write-does-not-validate-read-preference ()
  "Transaction write operations should not validate readPreference."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn
                :host "seed-a"
                :port 27017
                :database "app"
                :process 'proc
                :closed nil
                :max-wire-version 17
                :txn-number 0
                :session-id session-id
                :read-preference
                (mongo--params-read-preference
                 '(:read-preference secondary))))
         (primary-hello '(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t)))
         captured)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-start-transaction conn)
      (mongo-command conn "app" '(("insert" . "users"))))
    (should (eq (cdr (assoc "startTransaction" captured)) t))
    (should (eq (cdr (assoc "autocommit" captured)) :false))))



(ert-deftest mongo-test-transaction-network-error-labels-transient ()
  "Network errors inside a transaction should be labeled transient."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         (mongos-hello '(("ok" . 1)
                         ("maxWireVersion" . 17)
                         ("msg" . "isdbgrid"))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn mongos-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (signal 'mongo-error
                         (list "Timed out waiting for MongoDB response")))))
      (mongo-start-transaction conn)
      (let ((err (should-error
                  (mongo-command conn "app" '(("insert" . "users")))
                  :type 'mongo-error)))
        (should
         (mongo-error-has-label-p
          err "TransientTransactionError"))
        (should (string-match-p "Timed out waiting"
                                (error-message-string err)))))
    (should (eq (mongo-conn-transaction-state conn) 'in-progress))
    (should-not (mongo-conn-transaction-pinned-address conn))))



(ert-deftest mongo-test-transaction-server-transient-label-unpins ()
  "Server TransientTransactionError labels should unpin the transaction."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "mongos-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("msg" . "isdbgrid"))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 0)
                   ("errmsg" . "write conflict")
                   ("errorLabels" . ["TransientTransactionError"])))))
      (mongo-start-transaction conn)
      (let ((err (should-error
                  (mongo-command conn "app" '(("insert" . "users")))
                  :type 'mongo-error)))
        (should
         (mongo-error-has-label-p
          err "TransientTransactionError"))))
    (should (eq (mongo-conn-transaction-state conn) 'in-progress))
    (should-not (mongo-conn-transaction-pinned-address conn))))



(ert-deftest mongo-test-transaction-selection-error-labels-transient ()
  "Server-selection errors inside a transaction should be labeled transient."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         (secondary-hello '(("ok" . 1)
                            ("maxWireVersion" . 17)
                            ("setName" . "rs0")
                            ("secondary" . t))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn secondary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo-hello)
               (lambda (_conn &optional _timeout)
                 secondary-hello))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "server-selection error should fail before send"))))
      (mongo-start-transaction conn)
      (setf (mongo-conn-transaction-state conn) 'in-progress)
      (let ((err (should-error
                  (mongo-command conn "app" '(("insert" . "users")))
                  :type 'mongo-error)))
        (should
         (mongo-error-has-label-p
          err "TransientTransactionError"))
        (should (string-match-p "No writable MongoDB server"
                                (error-message-string err)))))
    (should (eq (mongo-conn-transaction-state conn) 'in-progress))))



(ert-deftest mongo-test-transaction-rejects-operation-concerns ()
  "Operations inside transactions should reject explicit concerns."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "operation concerns should fail before send"))))
      (mongo-start-transaction conn)
      (let ((err (should-error
                  (mongo-command
                   conn "app"
                   '(("distinct" . "users")
                     ("key" . "email")
                     ("readConcern" . (("level" . "snapshot")))))
                  :type 'mongo-error)))
        (should (string-match-p "Cannot set read concern"
                                (error-message-string err))))
      (let ((err (should-error
                  (mongo-command
                   conn "app"
                   '(("insert" . "users")
                     ("writeConcern" . (("w" . 1)))))
                  :type 'mongo-error)))
        (should (string-match-p "Cannot set write concern"
                                (error-message-string err)))))))



(ert-deftest mongo-test-transaction-commit-enters-committed-state ()
  "commitTransaction should use transaction metadata and enter committed state."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         captured)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-start-transaction
       conn
       '(("writeConcern" . (("w" . "majority")))))
      (setf (mongo-conn-transaction-state conn) 'in-progress)
      (mongo-commit-transaction conn 5000))
    (should (equal captured
                   `(("commitTransaction" . 1)
                     ("writeConcern" . (("w" . "majority")))
                     ("maxTimeMS" . 5000)
                     ("$db" . "admin")
                     ("lsid" . ,session-id)
                     ("txnNumber" . ,(mongo-int64 1))
                     ("autocommit" . :false))))
    (should (eq (mongo-conn-transaction-state conn) 'committed))
    (should (equal (mongo-conn-transaction-number conn)
                   (mongo-int64 1)))
    (should-not (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-commit-empty-sends-no-command ()
  "commitTransaction should not send a command for an empty transaction."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "empty transaction commit should not send"))))
      (mongo-start-transaction conn)
      (should (equal (mongo-commit-transaction conn)
                     '(("ok" . 1)))))
    (should (eq (mongo-conn-transaction-state conn) 'committed))
    (should (equal (mongo-conn-transaction-number conn)
                   (mongo-int64 1)))
    (should-not (mongo-conn-transaction-commit-sent conn))
    (should-not (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-commit-retries-network-error ()
  "commitTransaction should retry once with majority writeConcern."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         sends
         retried
         (recv-count 0))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (push document sends)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (cl-incf recv-count)
                 (if (= recv-count 1)
                     (signal 'mongo-error
                             (list "Timed out waiting for MongoDB response"))
                   '(("ok" . 1)))))
              ((symbol-function 'mongo--retry-transaction-control-once)
               (lambda (retry-conn _err)
                 (setq retried t)
                 retry-conn)))
      (mongo-start-transaction
       conn
       '(("writeConcern" . (("w" . 1)))
         ("maxCommitTimeMS" . 750)))
      (setf (mongo-conn-transaction-state conn) 'in-progress)
      (should (equal (mongo-commit-transaction conn)
                     '(("ok" . 1)))))
    (setq sends (nreverse sends))
    (should retried)
    (should (= recv-count 2))
    (should (= (length sends) 2))
    (should (equal (cdr (assoc "writeConcern" (nth 0 sends)))
                   '(("w" . 1))))
    (should (equal (cdr (assoc "writeConcern" (nth 1 sends)))
                   '(("w" . "majority")
                     ("wtimeout" . 10000))))
    (should (= (cdr (assoc "maxTimeMS" (nth 0 sends))) 750))
    (should (= (cdr (assoc "maxTimeMS" (nth 1 sends))) 750))
    (should (equal (cdr (assoc "txnNumber" (nth 0 sends)))
                   (mongo-int64 1)))
    (should (equal (cdr (assoc "txnNumber" (nth 1 sends)))
                   (mongo-int64 1)))
    (should (eq (mongo-conn-transaction-state conn) 'committed))
    (should (equal (mongo-conn-transaction-number conn)
                   (mongo-int64 1)))
    (should (eq (mongo-conn-transaction-commit-sent conn) t))
    (should-not (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-commit-labels-unknown-result ()
  "commitTransaction write concern timeouts should be labeled unknown."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         (mongos-hello '(("ok" . 1)
                         ("maxWireVersion" . 17)
                         ("msg" . "isdbgrid"))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn mongos-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("writeConcernError" .
                    (("code" . 64)
                     ("codeName" . "WriteConcernFailed")
                     ("errmsg" . "waiting for replication timed out")))))))
      (mongo-start-transaction conn)
      (setf (mongo-conn-transaction-state conn) 'in-progress)
      (let ((err (should-error
                  (mongo-commit-transaction conn)
                  :type 'mongo-error)))
        (should
         (mongo-error-has-label-p
          err "UnknownTransactionCommitResult"))
        (should (string-match-p "write concern"
                                (error-message-string err)))))
    (should (eq (mongo-conn-transaction-state conn) 'committed))
    (should (equal (mongo-conn-transaction-number conn)
                   (mongo-int64 1)))
    (should (eq (mongo-conn-transaction-commit-sent conn) t))
    (should-not (mongo-conn-transaction-pinned-address conn))
    (should-not (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-abort-empty-sends-no-command ()
  "abortTransaction should not send a command for an empty transaction."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "empty transaction abort should not send"))))
      (mongo-start-transaction conn)
      (should (equal (mongo-abort-transaction conn)
                     '(("ok" . 1)))))
    (should (eq (mongo-conn-transaction-state conn) 'aborted))
    (should (equal (mongo-conn-transaction-number conn)
                   (mongo-int64 1)))
    (should-not (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-abort-retries-network-error ()
  "abortTransaction should retry once and ignore final command errors."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         sends
         retried
         (recv-count 0))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (push document sends)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (cl-incf recv-count)
                 (if (= recv-count 1)
                     (signal 'mongo-error
                             (list "Timed out waiting for MongoDB response"))
                   '(("ok" . 0)
                     ("code" . 11000)
                     ("codeName" . "DuplicateKey")
                     ("errmsg" . "non-retryable abort error")))))
              ((symbol-function 'mongo--retry-transaction-control-once)
               (lambda (retry-conn _err)
                 (setq retried t)
                 retry-conn)))
      (mongo-start-transaction
       conn
       '(("writeConcern" . (("w" . "majority")))))
      (setf (mongo-conn-transaction-state conn) 'in-progress)
      (should (equal (mongo-abort-transaction conn)
                     '(("ok" . 0)
                       ("code" . 11000)
                       ("codeName" . "DuplicateKey")
                       ("errmsg" . "non-retryable abort error")))))
    (setq sends (nreverse sends))
    (should retried)
    (should (= recv-count 2))
    (should (= (length sends) 2))
    (should (equal (cdr (assoc "writeConcern" (nth 0 sends)))
                   '(("w" . "majority"))))
    (should (equal (cdr (assoc "writeConcern" (nth 1 sends)))
                   '(("w" . "majority"))))
    (should (equal (cdr (assoc "txnNumber" (nth 0 sends)))
                   (mongo-int64 1)))
    (should (equal (cdr (assoc "txnNumber" (nth 1 sends)))
                   (mongo-int64 1)))
    (should (eq (mongo-conn-transaction-state conn) 'aborted))
    (should-not (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-repeat-commit-reruns-with-majority ()
  "Calling commitTransaction again after committed should rerun with majority."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id))
         sends)
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (push document sends)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-start-transaction
       conn
       '(("writeConcern" . (("w" . 1)))))
      (setf (mongo-conn-transaction-state conn) 'in-progress)
      (mongo-commit-transaction conn)
      (should (eq (mongo-conn-transaction-state conn) 'committed))
      (mongo-commit-transaction conn))
    (setq sends (nreverse sends))
    (should (= (length sends) 2))
    (should (equal (cdr (assoc "writeConcern" (nth 0 sends)))
                   '(("w" . 1))))
    (should (equal (cdr (assoc "writeConcern" (nth 1 sends)))
                   '(("w" . "majority")
                     ("wtimeout" . 10000))))
    (should (equal (cdr (assoc "txnNumber" (nth 1 sends)))
                   (mongo-int64 1)))
    (should (eq (mongo-conn-transaction-state conn) 'committed))
    (should-not (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-repeat-empty-commit-does-not-send ()
  "Repeating commitTransaction for an empty committed transaction should not send."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "empty committed transaction should not send"))))
      (mongo-start-transaction conn)
      (should (equal (mongo-commit-transaction conn)
                     '(("ok" . 1))))
      (should (equal (mongo-commit-transaction conn)
                     '(("ok" . 1)))))
    (should (eq (mongo-conn-transaction-state conn) 'committed))
    (should-not (mongo-in-transaction-p conn))))



(ert-deftest mongo-test-transaction-abort-state-errors ()
  "Invalid commit/abort calls should preserve committed/aborted state."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "invalid state transition should fail before send"))))
      (mongo-start-transaction conn)
      (mongo-abort-transaction conn)
      (let ((err (should-error
                  (mongo-abort-transaction conn)
                  :type 'mongo-error)))
        (should (string-match-p "Cannot call abortTransaction twice"
                                (error-message-string err))))
      (let ((err (should-error
                  (mongo-commit-transaction conn)
                  :type 'mongo-error)))
        (should (string-match-p
                 "Cannot call commitTransaction after calling abortTransaction"
                 (error-message-string err)))))
    (should (eq (mongo-conn-transaction-state conn) 'aborted))))



(ert-deftest mongo-test-transaction-committed-state-rejects-abort ()
  "abortTransaction should fail after commitTransaction."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :txn-number 0
                                :session-id session-id)))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args)
                 (ert-fail "empty commit and invalid abort should not send"))))
      (mongo-start-transaction conn)
      (mongo-commit-transaction conn)
      (let ((err (should-error
                  (mongo-abort-transaction conn)
                  :type 'mongo-error)))
        (should (string-match-p
                 "Cannot call abortTransaction after calling commitTransaction"
                 (error-message-string err)))))
    (should (eq (mongo-conn-transaction-state conn) 'committed))))



(ert-deftest mongo-test-transaction-ended-state-clears-on-next-command ()
  "The next non-control command after committed/aborted should clear transaction state."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (token '(("shard" . "a")))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :retry-reads t
                                :txn-number 4
                                :session-id session-id
                                :transaction-state 'committed
                                :transaction-number (mongo-int64 4)
                                :transaction-recovery-token token
                                :transaction-pinned-address "seed-a:27017"
                                :transaction-commit-sent t))
         captured)
    (setf (mongo-conn-topology conn)
          (make-mongo-topology-description
           :type 'replica-set-with-primary
           :primary-address "seed-a:27017"
           :compatible t
           :servers
           `(("seed-a:27017" .
              ,(make-mongo-server-description
                :address "seed-a:27017"
                :type 'rs-primary
                :max-wire-version 17)))))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--retryable-reads-supported-p)
               (lambda (_conn) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-command conn "app" '(("find" . "users"))))
    (should-not (mongo-conn-transaction-state conn))
    (should-not (mongo-conn-transaction-number conn))
    (should-not (mongo-conn-transaction-recovery-token conn))
    (should-not (mongo-conn-transaction-pinned-address conn))
    (should-not (assoc "txnNumber" captured))
    (should-not (assoc "autocommit" captured))
    (should (equal (cdr (assoc "lsid" captured)) session-id))))



(ert-deftest mongo-test-transaction-disables-retryable-writes ()
  "Writes inside transactions should not use retryable-write retry logic."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :retry-writes t
                                :txn-number 0
                                :session-id session-id))
         captured
         (recv-count 0))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (cl-incf recv-count)
                 (signal 'mongo-error
                         (list "Timed out waiting for MongoDB response"))))
              ((symbol-function 'mongo--reconnect-current-server)
               (lambda (&rest _args)
                 (ert-fail "transaction writes should not use retryWrites"))))
      (mongo-start-transaction conn)
      (let ((mongo--retryable-write-context t))
        (should-error
         (mongo-command
          conn
          "app"
          '(("insert" . "users"))
          nil
          `(("documents" . [,(mongo-document '(("_id" . "a")))])))
         :type 'mongo-error)))
    (should (= recv-count 1))
    (should (eq (cdr (assoc "startTransaction" captured)) t))
    (should (eq (cdr (assoc "autocommit" captured)) :false))
    (should (equal (cdr (assoc "txnNumber" captured))
                   (mongo-int64 1)))))



(ert-deftest mongo-test-command-adds-txn-number-for-retryable-write ()
  "Retryable write helper context should add lsid and txnNumber."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :retry-writes t
                                :txn-number 0
                                :session-id session-id))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)))
         captured)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (let ((mongo--retryable-write-context t))
        (mongo-command
         conn
         "app"
         '(("insert" . "users"))
         nil
         `(("documents" . [,(mongo-document '(("_id" . "a")))])))))
    (should (equal (cdr (assoc "lsid" captured)) session-id))
    (should (equal (cdr (assoc "txnNumber" captured))
                   (mongo-int64 1)))
    (should (= (mongo-conn-txn-number conn) 1))))



(ert-deftest mongo-test-command-retries-write-network-error ()
  "Retryable write commands should retry once with the same txnNumber."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :retry-writes t
                                :txn-number 0
                                :session-id session-id))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)))
         sends
         (recv-count 0)
         reconnected)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (push document sends)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (cl-incf recv-count)
                 (if (= recv-count 1)
                     (signal 'mongo-error
                             (list "Timed out waiting for MongoDB response"))
                   '(("ok" . 1)))))
              ((symbol-function 'mongo--reconnect-current-server)
               (lambda (retry-conn)
                 (setq reconnected t)
                 (setf (mongo-conn-topology retry-conn)
                       (mongo--topology-description-from-hello
                        retry-conn hello))
                 retry-conn)))
      (let ((mongo--retryable-write-context t))
        (mongo-command
         conn
         "app"
         '(("insert" . "users"))
         nil
         `(("documents" . [,(mongo-document '(("_id" . "a")))])))))
    (setq sends (nreverse sends))
    (should reconnected)
    (should (= recv-count 2))
    (should (= (length sends) 2))
    (should (equal (cdr (assoc "txnNumber" (nth 0 sends)))
                   (mongo-int64 1)))
    (should (equal (cdr (assoc "txnNumber" (nth 1 sends)))
                   (mongo-int64 1)))
    (should (= (mongo-conn-txn-number conn) 1))))



(ert-deftest mongo-test-command-retries-write-concern-error ()
  "Retryable writeConcernError responses should retry before surfacing."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :retry-writes t
                                :txn-number 0
                                :session-id session-id))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)))
         (recv-count 0)
         reconnected)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (cl-incf recv-count)
                 (if (= recv-count 1)
                     '(("ok" . 1)
                       ("writeConcernError" .
                        (("code" . 91)
                         ("codeName" . "ShutdownInProgress")
                         ("errmsg" . "shutdown"))))
                   '(("ok" . 1)))))
              ((symbol-function 'mongo--reconnect-current-server)
               (lambda (retry-conn)
                 (setq reconnected t)
                 (setf (mongo-conn-topology retry-conn)
                       (mongo--topology-description-from-hello
                        retry-conn hello))
                 retry-conn)))
      (let ((mongo--retryable-write-context t))
        (mongo-command
         conn
         "app"
         '(("update" . "users"))
         nil
         `(("updates" . [,(mongo-document
                           '(("q" . (("_id" . "a")))
                             ("u" . (("$set" . (("seen" . t)))))
                             ("multi" . :false)))])))))
    (should reconnected)
    (should (= recv-count 2))))



(ert-deftest mongo-test-command-does-not-retry-write-outside-helper-context ()
  "Generic command execution should not add txnNumber for writes."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :retry-writes t
                                :txn-number 0
                                :session-id session-id))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)))
         captured)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)))))
      (mongo-command
       conn
       "app"
       '(("insert" . "users"))
       nil
       `(("documents" . [,(mongo-document '(("_id" . "a")))]))))
    (should-not (assoc "txnNumber" captured))
    (should (= (mongo-conn-txn-number conn) 0))))



(ert-deftest mongo-test-command-does-not-retry-unsafe-update-many ()
  "updateMany-style statements should not be retryable writes."
  (let* ((session-id `(("id" . ,(mongo-binary 4 "abcdefghijklmnop"))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-wire-version 17
                                :retry-writes t
                                :txn-number 0
                                :session-id session-id))
         (hello '(("ok" . 1)
                  ("maxWireVersion" . 17)
                  ("setName" . "rs0")
                  ("isWritablePrimary" . t)))
         captured)
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document &optional _sequences)
                 (setq captured document)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 (signal 'mongo-error
                         (list "Timed out waiting for MongoDB response"))))
              ((symbol-function 'mongo--reconnect-current-server)
               (lambda (&rest _args)
                 (ert-fail "updateMany should not retry"))))
      (let ((mongo--retryable-write-context t))
        (should-error
         (mongo-command
          conn
          "app"
          '(("update" . "users"))
          nil
          `(("updates" . [,(mongo-document
                            '(("q" . (("active" . t)))
                              ("u" . (("$inc" . (("n" . 1)))))
                              ("multi" . t)))])))
         :type 'mongo-error)))
    (should-not (assoc "txnNumber" captured))
    (should (= (mongo-conn-txn-number conn) 0))))



(ert-deftest mongo-test-command-rejects-write-errors-with-ok ()
  "Write command replies with ok:1 and writeErrors should still signal."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil))
         (primary-hello '(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("writeErrors" .
                    ((("index" . 0)
                      ("code" . 11000)
                      ("codeName" . "DuplicateKey")
                      ("errmsg" . "E11000 duplicate key error"))))))))
      (let ((err (should-error
                  (mongo-command conn "app" '(("insert" . "users")))
                  :type 'mongo-error)))
        (should (string-match-p "DuplicateKey"
                                (error-message-string err)))
        (should (string-match-p "duplicate key"
                                (error-message-string err)))))))



(ert-deftest mongo-test-command-rejects-oversized-sequence-document ()
  "MongoDB command execution should reject oversized OP_MSG sequence documents."
  (let* ((sequence-document
          (mongo-document
           '(("q" . (("active" . t)))
             ("u" . (("$set" . (("payload" . "aaaaaaaaaa")))))
             ("multi" . :false))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-bson-object-size
                                (1- (length
                                     (mongo--encode-document
                                      sequence-document)))
                                :max-message-size-bytes 48000000))
         (primary-hello '(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'process-send-string)
               (lambda (&rest _args)
                 (ert-fail "oversized sequence document should not be sent"))))
      (should-error
       (mongo-command
        conn "app"
        '(("update" . "users"))
        nil
        `(("updates" . [,sequence-document])))
       :type 'mongo-error))))



(ert-deftest mongo-test-command-rejects-oversized-sequence-message ()
  "MongoDB command execution should reject oversized OP_MSG sequence messages."
  (let* ((command '(("delete" . "users")))
         (first (mongo-document '(("q" . (("_id" . "a")))
                                  ("limit" . 1))))
         (second (mongo-document '(("q" . (("_id" . "b")))
                                   ("limit" . 1))))
         (document (mongo--command-with-db command "app"))
         (message-size
          (+ (length (mongo--make-op-msg 1 document nil nil nil))
             (mongo--document-sequence-overhead-bytes "deletes")
             (length (mongo--encode-document first))
             (length (mongo--encode-document second))))
         (conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil
                                :max-bson-object-size 1000
                                :max-message-size-bytes (1- message-size)))
         (primary-hello '(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'process-send-string)
               (lambda (&rest _args)
                 (ert-fail "oversized sequence message should not be sent"))))
      (should-error
       (mongo-command
        conn "app"
        command
        nil
        `(("deletes" . [,first ,second])))
       :type 'mongo-error))))



(ert-deftest mongo-test-command-rejects-write-concern-error-with-ok ()
  "Write command replies with ok:1 and writeConcernError should signal."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil))
         (primary-hello '(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("writeConcernError" .
                    (("code" . 64)
                     ("codeName" . "WriteConcernFailed")
                     ("errmsg" . "waiting for replication timed out")))))))
      (let ((err (should-error
                  (mongo-command conn "app" '(("update" . "users")))
                  :type 'mongo-error)))
        (should (string-match-p "WriteConcernFailed"
                                (error-message-string err)))
        (should (string-match-p "replication timed out"
                                (error-message-string err)))))))



(ert-deftest mongo-test-command-preserves-error-labels ()
  "Command errors should expose server-returned errorLabels."
  (let* ((conn (make-mongo-conn :host "seed-a"
                                :port 27017
                                :database "app"
                                :process 'proc
                                :closed nil))
         (primary-hello '(("ok" . 1)
                          ("maxWireVersion" . 17)
                          ("setName" . "rs0")
                          ("isWritablePrimary" . t))))
    (setf (mongo-conn-topology conn)
          (mongo--topology-description-from-hello conn primary-hello))
    (cl-letf (((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'mongo--send-document)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 0)
                   ("errmsg" . "transaction conflict")
                   ("errorLabels" .
                    ["TransientTransactionError"])))))
      (let ((err (should-error
                  (mongo-command conn "app" '(("insert" . "users")))
                  :type 'mongo-error)))
        (should
         (mongo-error-has-label-p
          err "TransientTransactionError"))
        (should (string-match-p "transaction conflict"
                                (error-message-string err)))))))



(ert-deftest mongo-test-connect-direct-replica-set-uses-endpoint ()
  "Native mongo.el directConnection should use the requested host directly."
  (let (calls)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (_params host port database _credential authenticate)
                 (push (list host port database authenticate) calls)
                 (cons 'direct-conn
                       '(("ok" . 1)
                         ("maxWireVersion" . 17)
                         ("setName" . "rs0")
                         ("isWritablePrimary" . :false))))))
      (should (eq (mongo-connect
                   '(:url "mongodb://seed-a:27018/app?replicaSet=rs0&directConnection=true"))
                  'direct-conn)))
    (should (equal calls
                   '(("seed-a" 27018 "app" t))))))



(ert-deftest mongo-test-connect-caps-single-host-timeout-by-server-selection ()
  "Single-host connect should cap connect timeout by serverSelectionTimeoutMS."
  (let (captured-params)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (params _host _port _database _credential _authenticate)
                 (setq captured-params params)
                 (cons 'single-conn nil))))
      (should (eq (mongo-connect
                   '(:url "mongodb://seed-a:27018/app?connectTimeoutMS=7000&serverSelectionTimeoutMS=2500"))
                  'single-conn)))
    (should (= (plist-get captured-params :connect-timeout) 2.5))))



(ert-deftest mongo-test-connect-stores-socket-timeout-from-uri ()
  "Native mongo.el should store socketTimeoutMS on the connection."
  (let (conn)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest _args) 'mongo-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'process-send-string) #'ignore)
              ((symbol-function 'mongo--recv-handshake-message)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("maxWireVersion" . 17))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (unwind-protect
          (progn
            (setq conn
                  (mongo-connect
                   '(:url "mongodb://seed-a:27018/app?socketTimeoutMS=1500")))
            (should (= (mongo-conn-socket-timeout conn) 1.5)))
        (when conn
          (mongo-disconnect conn))))))



(ert-deftest mongo-test-connect-stores-operation-timeout-from-uri ()
  "Native mongo.el should store timeoutMS on the connection."
  (let (conn)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest _args) 'mongo-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'process-send-string) #'ignore)
              ((symbol-function 'mongo--recv-handshake-message)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("maxWireVersion" . 17))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (unwind-protect
          (progn
            (setq conn
                  (mongo-connect
                   '(:url "mongodb://seed-a:27018/app?timeoutMS=2500")))
            (should (= (mongo-conn-operation-timeout conn) 2.5)))
        (when conn
          (mongo-disconnect conn))))))



(ert-deftest mongo-test-connect-stores-monitoring-options-from-uri ()
  "Native mongo.el should store MongoDB monitoring URI options."
  (let (conn)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest _args) 'mongo-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'process-send-string) #'ignore)
              ((symbol-function 'mongo--recv-handshake-message)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("maxWireVersion" . 17))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (unwind-protect
          (progn
            (setq conn
                  (mongo-connect
                   '(:url
                     "mongodb://seed-a:27018/app?heartbeatFrequencyMS=1500&serverMonitoringMode=poll&localThresholdMS=25")))
            (should (= (mongo-conn-local-threshold conn) 0.025))
            (should (= (mongo-conn-heartbeat-frequency conn) 1.5))
            (should (eq (mongo-conn-server-monitoring-mode conn) 'poll)))
        (when conn
          (mongo-disconnect conn))))))



(ert-deftest mongo-test-connect-opens-unix-socket-endpoint ()
  "Native mongo.el should open UNIX-domain socket endpoints with local family."
  (let (conn captured-args)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest args)
                 (setq captured-args args)
                 'mongo-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'process-send-string) #'ignore)
              ((symbol-function 'mongo--recv-handshake-message)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("maxWireVersion" . 17))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (unwind-protect
          (progn
            (setq conn
                  (mongo-connect
                   '(:url "mongodb://%2Ftmp%2Fmongodb-27017.sock/app")))
            (should (equal (mongo-conn-host conn)
                           "/tmp/mongodb-27017.sock"))
            (should-not (mongo-conn-port conn))
            (should (eq (plist-get captured-args :family) 'local))
            (should (equal (plist-get captured-args :service)
                           "/tmp/mongodb-27017.sock"))
            (should-not (plist-member captured-args :host)))
        (when conn
          (mongo-disconnect conn))))))



(ert-deftest mongo-test-connect-rejects-tls-over-unix-socket ()
  "Native mongo.el should reject TLS over UNIX-domain socket endpoints."
  (cl-letf (((symbol-function 'make-network-process)
             (lambda (&rest _args)
               (ert-fail "TLS over local socket should fail before opening"))))
    (let ((err (should-error
                (mongo-connect
                 '(:url "mongodb://%2Ftmp%2Fmongodb-27017.sock/app?tls=true"))
                :type 'mongo-error)))
      (should (string-match-p "UNIX-domain sockets"
                              (error-message-string err))))))



(ert-deftest mongo-test-connect-caps-replica-attempt-timeout-by-server-selection ()
  "Replica discovery attempts should respect remaining serverSelectionTimeoutMS."
  (let ((primary-hello '(("ok" . 1)
                         ("maxWireVersion" . 17)
                         ("setName" . "rs0")
                         ("isWritablePrimary" . t)))
        captured-params)
    (cl-letf (((symbol-function 'mongo--connect-endpoint)
               (lambda (params host port database _credential _authenticate)
                 (setq captured-params params)
                 (cons (make-mongo-conn :host host
                                        :port port
                                        :database database
                                        :process nil
                                        :closed nil)
                       primary-hello))))
      (should (mongo-conn-p
               (mongo-connect
                '(:url "mongodb://seed-a:27018/app?replicaSet=rs0&connectTimeoutMS=7000&serverSelectionTimeoutMS=2500")))))
    (should (<= (plist-get captured-params :connect-timeout) 2.5))
    (should (> (plist-get captured-params :connect-timeout) 0))))



(ert-deftest mongo-test-connect-upgrades-tls-before-handshake ()
  "Native mongo.el should negotiate TLS before sending MongoDB handshake bytes."
  (let (events conn)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest _args)
                 (push :open events)
                 'mongo-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'mongo--upgrade-to-tls)
               (lambda (_proc _host _params _timeout)
                 (push :tls events)))
              ((symbol-function 'process-send-string)
               (lambda (_proc _data)
                 (push :handshake events)))
              ((symbol-function 'mongo--recv-handshake-message)
               (lambda (&rest _args)
                 '(("maxWireVersion" . 17) ("ok" . 1))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (unwind-protect
          (setq conn (mongo-connect '(:host "db.example.test"
                                      :port 27017
                                      :database "app"
                                      :tls t)))
        (when conn
          (mongo-disconnect conn))))
    (should (equal (nreverse events)
                   '(:open :tls :handshake)))))



(ert-deftest mongo-test-connect-uses-socks5-proxy ()
  "Native mongo.el should tunnel TCP connections through SOCKS5 proxies."
  (let (captured-args captured-buffer sent conn)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest args)
                 (setq captured-args args)
                 (setq captured-buffer (plist-get args :buffer))
                 'mongo-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'process-send-string)
               (lambda (_proc data)
                 (push data sent)
                 (with-current-buffer captured-buffer
                   (cond
                    ((equal data (unibyte-string #x05 #x01 #x00))
                     (insert (unibyte-string #x05 #x00)))
                    ((equal data
                            (concat (unibyte-string #x05 #x01 #x00 #x03
                                                    15)
                                    "db.example.test"
                                    (mongo--pack-uint16-be 27017)))
                     (insert (unibyte-string #x05 #x00 #x00 #x01
                                             0 0 0 0
                                             0 0)))))))
              ((symbol-function 'mongo--send-initial-handshake)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("maxWireVersion" . 17))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (unwind-protect
          (setq conn
                (mongo-connect
                 '(:url
                   "mongodb://db.example.test:27017/app?proxyHost=proxy.example&proxyPort=1081")))
        (when conn
          (mongo-disconnect conn))))
    (should (equal (plist-get captured-args :host) "proxy.example"))
    (should (= (plist-get captured-args :service) 1081))
    (should (equal (mongo-conn-host conn) "db.example.test"))
    (should (= (mongo-conn-port conn) 27017))
    (should (equal (nreverse sent)
                   (list (unibyte-string #x05 #x01 #x00)
                         (concat (unibyte-string #x05 #x01 #x00 #x03
                                                 15)
                                 "db.example.test"
                                 (mongo--pack-uint16-be 27017)))))))



(ert-deftest mongo-test-connect-socks5-proxy-authenticates ()
  "Native mongo.el should support SOCKS5 username/password auth."
  (let ((buffer (generate-new-buffer " *mongo-socks-test*"))
        sent)
    (unwind-protect
        (progn
          (with-current-buffer buffer
            (set-buffer-multibyte nil))
          (cl-letf (((symbol-function 'process-send-string)
                     (lambda (_proc data)
                       (push data sent)
                       (with-current-buffer buffer
                         (cond
                          ((equal data (unibyte-string #x05 #x02 #x00 #x02))
                           (insert (unibyte-string #x05 #x02)))
                          ((equal data (unibyte-string #x01 #x01 ?u #x01 ?p))
                           (insert (unibyte-string #x01 #x00)))
                          ((equal data
                                  (concat (unibyte-string #x05 #x01 #x00 #x03
                                                          15)
                                          "db.example.test"
                                          (mongo--pack-uint16-be 27017)))
                           (insert (unibyte-string #x05 #x00 #x00 #x03
                                                   0 0 0)))))))
                    ((symbol-function 'process-live-p)
                     (lambda (_proc) t)))
            (mongo--socks5-connect
             'mongo-proc
             buffer
             "db.example.test"
             27017
             '(:host "proxy.example"
               :port 1081
               :username "u"
               :password "p")
             1))
          (should (equal (nreverse sent)
                         (list (unibyte-string #x05 #x02 #x00 #x02)
                               (unibyte-string #x01 #x01 ?u #x01 ?p)
                               (concat (unibyte-string #x05 #x01 #x00 #x03
                                                       15)
                                       "db.example.test"
                                       (mongo--pack-uint16-be 27017))))))
      (when (buffer-live-p buffer)
        (kill-buffer buffer)))))



(ert-deftest mongo-test-connect-rejects-socks5-proxy-over-unix-socket ()
  "Native mongo.el should reject SOCKS5 proxies for UNIX-domain endpoints."
  (cl-letf (((symbol-function 'make-network-process)
             (lambda (&rest _args)
               (ert-fail "SOCKS5 over local socket should fail before opening"))))
    (let ((err (should-error
                (mongo-connect
                 '(:url
                   "mongodb://%2Ftmp%2Fmongodb-27017.sock/app?proxyHost=proxy.example"))
                :type 'mongo-error)))
      (should (string-match-p "SOCKS5 proxy"
                              (error-message-string err))))))



(ert-deftest mongo-test-connect-uses-modern-hello-after-legacy-handshake ()
  "Ordinary connections should switch to OP_MSG hello after helloOk."
  (let (events initial-command probe-command conn)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest _args)
                 (push :open events)
                 'mongo-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'mongo--send-handshake)
               (lambda (_conn document)
                 (setq initial-command document)
                 (push :legacy-hello events)
                 1))
              ((symbol-function 'mongo--recv-handshake-message)
               (lambda (&rest _args)
                 '(("maxWireVersion" . 17)
                   ("helloOk" . t)
                   ("ok" . 1))))
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document)
                 (setq probe-command document)
                 (push :op-msg-hello events)
                 2))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("ok" . 1)
                   ("isWritablePrimary" . t))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (unwind-protect
          (progn
            (setq conn (mongo-connect '(:host "db.example.test"
                                        :port 27017
                                        :database "app")))
            (setf (mongo-conn-session-id conn)
                  '(("id" . "session")))
            (should (equal (mongo-hello conn)
                           '(("ok" . 1)
                             ("isWritablePrimary" . t))))
            (setf (mongo-conn-session-id conn) nil))
        (when conn
          (mongo-disconnect conn))))
    (should (equal (nreverse events)
                   '(:open :legacy-hello :op-msg-hello)))
    (should (equal (cdr (assoc "isMaster" initial-command)) 1))
    (should (eq (cdr (assoc "helloOk" initial-command)) t))
    (should (equal (mongo-conn-hello-command conn) "hello"))
    (should (equal probe-command
                   '(("hello" . 1)
                     ("$db" . "admin"))))))



(ert-deftest mongo-test-connect-keeps-legacy-hello-without-hello-ok ()
  "Connections should retain legacy hello when the server does not return helloOk."
  (let (conn)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest _args) 'mongo-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'mongo--send-handshake)
               (lambda (&rest _args) 1))
              ((symbol-function 'mongo--recv-handshake-message)
               (lambda (&rest _args)
                 '(("maxWireVersion" . 17) ("ok" . 1))))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (unwind-protect
          (setq conn (mongo-connect '(:host "db.example.test"
                                      :port 27017
                                      :database "app")))
        (when conn
          (mongo-disconnect conn))))
    (should (equal (mongo-conn-hello-command conn) "isMaster"))))



(ert-deftest mongo-test-connect-uses-op-msg-hello-for-stable-api ()
  "Stable API connections should send the initial hello through OP_MSG."
  (let (events captured-command conn)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest _args)
                 (push :open events)
                 'mongo-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document)
                 (setq captured-command document)
                 (push :op-msg-hello events)
                 1))
              ((symbol-function 'mongo--send-handshake)
               (lambda (&rest _args)
                 (push :legacy-hello events)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("maxWireVersion" . 17) ("ok" . 1))))
              ((symbol-function 'mongo--recv-handshake-message)
               (lambda (&rest _args)
                 (ert-fail "Stable API must not use legacy handshake receive")))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (unwind-protect
          (setq conn (mongo-connect '(:host "db.example.test"
                                      :port 27017
                                      :database "app"
                                      :server-api "1"
                                      :api-strict t)))
        (when conn
          (mongo-disconnect conn))))
    (should (equal (nreverse events)
                   '(:open :op-msg-hello)))
    (should (equal (cdr (assoc "hello" captured-command)) 1))
    (should-not (assoc "isMaster" captured-command))
    (should (equal (cdr (assoc "$db" captured-command)) "admin"))
    (should (equal (cdr (assoc "apiVersion" captured-command)) "1"))
    (should (eq (cdr (assoc "apiStrict" captured-command)) t))
    (should (equal (mongo--server-api-version
                    (mongo-conn-server-api conn))
                   "1"))))



(ert-deftest mongo-test-connect-uses-op-msg-hello-for-load-balanced ()
  "Load-balanced connections should send OP_MSG hello and store serviceId."
  (let (events captured-command conn)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest _args)
                 (push :open events)
                 'mongo-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'mongo--send-document)
               (lambda (_conn document)
                 (cond
                  ((assoc "hello" document)
                   (setq captured-command document)
                   (push :op-msg-hello events))
                  ((assoc "endSessions" document)
                   (push :end-sessions events))
                  (t
                   (push :op-msg-command events)))
                 1))
              ((symbol-function 'mongo--send-handshake)
               (lambda (&rest _args)
                 (push :legacy-hello events)
                 1))
              ((symbol-function 'mongo--recv-message)
               (lambda (&rest _args)
                 '(("maxWireVersion" . 17)
                   ("serviceId" . (("$oid" . "64f000000000000000000001")))
                   ("ok" . 1))))
              ((symbol-function 'mongo--recv-handshake-message)
               (lambda (&rest _args)
                 (ert-fail "loadBalanced must not use legacy handshake receive")))
              ((symbol-function 'process-live-p)
               (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (unwind-protect
          (setq conn (mongo-connect '(:host "lb.example.test"
                                      :port 27017
                                      :database "app"
                                      :load-balanced t)))
        (when conn
          (mongo-disconnect conn))))
    (should (equal (nreverse events)
                   '(:open :op-msg-hello :end-sessions)))
    (should (equal (cdr (assoc "hello" captured-command)) 1))
    (should (eq (cdr (assoc "loadBalanced" captured-command)) t))
    (should (mongo-conn-load-balanced conn))
    (should (equal (mongo-conn-service-id conn)
                   '(("$oid" . "64f000000000000000000001"))))))



(ert-deftest mongo-test-connect-load-balanced-requires-service-id ()
  "Load-balanced hello responses must include serviceId."
  (cl-letf (((symbol-function 'make-network-process)
             (lambda (&rest _args) 'mongo-proc))
            ((symbol-function 'set-process-coding-system) #'ignore)
            ((symbol-function 'mongo--send-document)
             (lambda (&rest _args) 1))
            ((symbol-function 'mongo--recv-message)
             (lambda (&rest _args)
               '(("maxWireVersion" . 17) ("ok" . 1))))
            ((symbol-function 'process-live-p)
             (lambda (_proc) t))
            ((symbol-function 'delete-process) #'ignore))
    (let ((err (should-error
                (mongo-connect '(:host "lb.example.test"
                                  :database "app"
                                  :load-balanced t))
                :type 'mongo-error)))
      (should (string-match-p "server does not support this mode"
                              (error-message-string err))))))

(provide 'mongo-test)

;;; mongo-test.el ends here
