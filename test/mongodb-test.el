;;; mongodb-test.el --- Tests for mongodb.el -*- lexical-binding: t; -*-

;; Copyright (C) 2025-2026 Lucius Chen
;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Code:

(require 'cl-lib)
(require 'ert)
(require 'mongodb)

(ert-deftest mongodb-test-public-clutch-api-is-present ()
  (dolist (symbol
           '(mongodb-aggregate
             mongodb-aggregate-command
             mongodb-aggregate-database
             mongodb-command
             mongodb-connect
             mongodb-count-documents
             mongodb-create-collection
             mongodb-create-index
             mongodb-decimal128
             mongodb-delete
             mongodb-datetime
             mongodb-disconnect
             mongodb-distinct
             mongodb-document
             mongodb-document-elements
             mongodb-document-p
             mongodb-drop-collection
             mongodb-drop-database
             mongodb-drop-index
             mongodb-explain
             mongodb-find
             mongodb-find-command
             mongodb-insert
             mongodb-int32
             mongodb-int64
             mongodb-kill-cursors
             mongodb-list-collection-docs
             mongodb-list-collections
             mongodb-list-databases
             mongodb-list-indexes
             mongodb-live-p
             mongodb-new-object-id
             mongodb-object-id
             mongodb-timestamp
             mongodb-update))
    (should (fboundp symbol)))
  (should (fboundp 'mongodb-conn-database))
  (should (fboundp 'mongodb-conn-closed)))

(ert-deftest mongodb-test-connection-struct-keeps-public-closed-slot ()
  (let ((conn (make-mongodb-conn :database "app" :closed nil)))
    (should (equal (mongodb-conn-database conn) "app"))
    (should-not (mongodb-conn-closed conn))))

(ert-deftest mongodb-test-bson-roundtrip-keeps-wrapper-values ()
  (let* ((object-id (mongodb-object-id "64b64c2f40f9f2428b59d111"))
         (document `(("name" . "Ada")
                     ("active" . t)
                     ("count32" . ,(mongodb-int32 7))
                     ("count64" . ,(mongodb-int64 9223372036854775807))
                     ("createdAt" . ,(mongodb-datetime 1704164645678))
                     ("stamp" . ,(mongodb-timestamp 3 9))
                     ("_id" . ,object-id)))
         (decoded (mongodb--decode-document-from-string
                   (mongodb--encode-document document))))
    (should (equal (cdr (assoc "name" decoded)) "Ada"))
    (should (eq (cdr (assoc "active" decoded)) t))
    (should (= (cdr (assoc "count32" decoded)) 7))
    (should (= (cdr (assoc "count64" decoded)) 9223372036854775807))
    (should (equal (cdr (assoc "_id" decoded))
                   '(("$oid" . "64b64c2f40f9f2428b59d111"))))))

(ert-deftest mongodb-test-document-wrapper-preserves-empty-document ()
  (let ((doc (mongodb-document nil)))
    (should (mongodb-document-p doc))
    (should (equal (mongodb-document-elements doc) nil))
    (should (equal (mongodb--decode-document-from-string
                    (mongodb--encode-document `(("filter" . ,doc))))
                   '(("filter"))))))

(ert-deftest mongodb-test-new-object-id-has-valid-shape ()
  (let ((id (mongodb-new-object-id)))
    (should (mongodb-object-id-p id))
    (should (string-match-p "\\`[0-9a-f]\\{24\\}\\'"
                            (mongodb-object-id-hex id)))))

(ert-deftest mongodb-test-url-params-parse-basic-uri ()
  (let ((params (mongodb--normalize-params
                 '(:url "mongodb://user:p%40ss@127.0.0.1:27018/app?authSource=admin&authMechanism=SCRAM-SHA-1&tls=true"))))
    (should (equal (plist-get params :host) "127.0.0.1"))
    (should (= (plist-get params :port) 27018))
    (should (equal (plist-get params :database) "app"))
    (should (equal (plist-get params :username) "user"))
    (should (equal (plist-get params :password) "p@ss"))
    (should (equal (plist-get params :auth-source) "admin"))
    (should (equal (plist-get params :auth-mechanism) "SCRAM-SHA-1"))
    (should (plist-get params :tls))))

(ert-deftest mongodb-test-hello-command-can-be-sent-as-op-msg ()
  (let* ((message (mongodb--make-op-msg 42 (mongodb--hello-command nil)))
         (frame (mongodb--decode-message-frame message))
         (document (mongodb--decoded-message-document frame))
         (client (cdr (assoc "client" document))))
    (should (= (mongodb--decoded-message-request-id frame) 42))
    (should (equal (cdr (assoc "$db" document)) "admin"))
    (should (assoc "os" client))
    (should (assoc "type" (cdr (assoc "os" client))))))

(ert-deftest mongodb-test-command-with-db-replaces-existing-db ()
  (should (equal (mongodb--command-with-db
                  "app"
                  '(("ping" . 1) ("$db" . "admin")))
                 '(("ping" . 1) ("$db" . "app")))))

(ert-deftest mongodb-test-find-command-keeps-sort-before-options ()
  (let ((command
         (mongodb-find-command
          "users"
          '(("active" . t))
          '(("name" . 1))
          10
          5
          '(("createdAt" . -1))
          '(("batchSize" . 50) ("allowDiskUse" . t)))))
    (should (equal (cdr (assoc "find" command)) "users"))
    (should (equal (cdr (assoc "filter" command)) '(("active" . t))))
    (should (equal (cdr (assoc "projection" command)) '(("name" . 1))))
    (should (= (cdr (assoc "limit" command)) 10))
    (should (= (cdr (assoc "skip" command)) 5))
    (should (equal (cdr (assoc "sort" command)) '(("createdAt" . -1))))
    (should (= (cdr (assoc "batchSize" command)) 50))
    (should (eq (cdr (assoc "allowDiskUse" command)) t))))

(ert-deftest mongodb-test-aggregate-command-moves-batch-size-into-cursor ()
  (let* ((command (mongodb-aggregate-command
                   "orders"
                   (vector '(("$match" . (("status" . "paid")))))
                   '(("batchSize" . 25))))
         (cursor (cdr (assoc "cursor" command))))
    (should (equal (cdr (assoc "aggregate" command)) "orders"))
    (should (mongodb-document-p cursor))
    (should (= (cdr (assoc "batchSize" (mongodb-document-elements cursor)))
               25))))

(ert-deftest mongodb-test-error-labels-come-from-condition-data ()
  (condition-case err
      (mongodb--signal-command-error
       '(("ok" . 0)
         ("errmsg" . "not primary")
         ("errorLabels" . ["RetryableWriteError" "TransientTransactionError"])))
    (mongodb-error
     (should (equal (mongodb-error-labels err)
                    '("RetryableWriteError" "TransientTransactionError")))
     (should (mongodb-error-has-label-p err "RetryableWriteError")))))

(ert-deftest mongodb-test-insert-builds-command-with-generated-id ()
  (let (captured)
    (cl-letf (((symbol-function 'mongodb-command)
               (lambda (_conn database command &rest _)
                 (setq captured (list database command))
                 '(("ok" . 1)))))
      (mongodb-insert :conn "app" "users" '((("name" . "Ada")))))
    (pcase-let ((`(,database ,command) captured))
      (should (equal database "app"))
      (should (equal (cdr (assoc "insert" command)) "users"))
      (let* ((docs (cdr (assoc "documents" command)))
             (first (aref docs 0)))
        (should (assoc "_id" first))
        (should (equal (cdr (assoc "name" first)) "Ada"))))))

(ert-deftest mongodb-test-insert-accepts-single-document-alist ()
  (let (captured)
    (cl-letf (((symbol-function 'mongodb-command)
               (lambda (_conn _database command &rest _)
                 (setq captured command)
                 '(("ok" . 1)))))
      (mongodb-insert :conn "app" "users" '(("name" . "Ada"))))
    (let ((docs (cdr (assoc "documents" captured))))
      (should (= (length docs) 1))
      (should (equal (cdr (assoc "name" (aref docs 0))) "Ada")))))

(ert-deftest mongodb-test-update-and-delete-command-shapes ()
  (let (commands)
    (cl-letf (((symbol-function 'mongodb-command)
               (lambda (_conn _database command &rest _)
                 (push command commands)
                 '(("ok" . 1)))))
      (mongodb-update :conn "app" "users"
                      '(("name" . "Ada"))
                      '(("$set" . (("active" . t))))
                      t
                      '(("upsert" . t)))
      (mongodb-delete :conn "app" "users" '(("active" . :false)) nil))
    (let ((delete (car commands))
          (update (cadr commands)))
      (should (equal (cdr (assoc "update" update)) "users"))
      (should (eq (cdr (assoc "multi" (aref (cdr (assoc "updates" update)) 0)))
                  t))
      (should (equal (cdr (assoc "delete" delete)) "users"))
      (should (= (cdr (assoc "limit" (aref (cdr (assoc "deletes" delete)) 0)))
                 1)))))

;;; mongodb-test.el ends here
