;;; mongodb-test.el --- Tests for mongodb.el -*- lexical-binding: t; -*-

;; Copyright (C) 2025-2026 Lucius Chen
;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Code:

(require 'cl-lib)
(require 'ert)
(require 'mongodb)

(defun mongodb-test--hex-bytes (hex)
  "Return unibyte data decoded from HEX."
  (apply #'unibyte-string
         (cl-loop for offset from 0 below (length hex) by 2
                  collect (string-to-number
                           (substring hex offset (+ offset 2)) 16))))

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

(ert-deftest mongodb-test-little-endian-primitives ()
  (let* ((data (concat (mongodb--pack-int32 -1)
                       (mongodb--pack-int64 mongodb--int64-min)
                       (mongodb--pack-uint-le #x1234 2)
                       (mongodb--pack-uint-le #x0102030405060708 8)))
         (reader (make-mongodb--reader :data data :pos 0)))
    (should (= (mongodb--read-int32 reader) -1))
    (should (= (mongodb--read-int64 reader) mongodb--int64-min))
    (should (= (mongodb--read-uint-le reader 2) #x1234))
    (should (= (mongodb--read-uint-le reader 8) #x0102030405060708))
    (should (= (mongodb--reader-pos reader) (length data)))))

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
    (should (eq (plist-get params :tls) t))
    (should (eq (plist-get params :tls-verify) t))))

(ert-deftest mongodb-test-url-tls-verification-options ()
  "TLS URI and plist options should normalize to explicit booleans."
  (should-not
   (plist-get
    (mongodb--normalize-params
     '(:url "mongodb://db/app?tls=true&tlsAllowInvalidCertificates=true"))
    :tls-verify))
  (should
   (plist-get
    (mongodb--normalize-params
     '(:url "mongodb://db/app?tls=true&tlsAllowInvalidCertificates=false"))
    :tls-verify))
  (should-not
   (plist-get (mongodb--normalize-params
               '(:host "db" :tls t :tls-verify nil))
              :tls-verify))
  (should-not
   (plist-get (mongodb--normalize-params '(:host "db" :tls :false))
              :tls))
  (should-error
   (mongodb--normalize-params '(:url "mongodb://db/app?tls=maybe"))
   :type 'mongodb-error)
  (should-error (mongodb--normalize-params "mongodb+srv://db/app")
                :type 'mongodb-error))

(ert-deftest mongodb-test-tls-upgrade-enforces-verification-option ()
  "TLS negotiation should receive certificate and hostname verification flags."
  (let (captured)
    (cl-letf (((symbol-function 'mongodb--tls-available-p) (lambda () t))
              ((symbol-function 'gnutls-negotiate)
               (lambda (&rest args) (setq captured args)))
              ((symbol-function 'process-status) (lambda (_proc) 'open))
              ((symbol-function 'process-contact) (lambda (&rest _args) nil))
              ((symbol-function 'process-live-p) (lambda (_proc) t)))
      (mongodb--upgrade-to-tls 'proc "db.example" 1 t))
    (should (eq (plist-get captured :verify-error) t))
    (should (eq (plist-get captured :verify-hostname-error) t))
    (should (equal (plist-get captured :priority-string) "NORMAL"))))

(ert-deftest mongodb-test-receive-rejects-invalid-frame-length ()
  "Wire frame lengths should be bounded before reading the body."
  (dolist (case '((2 . 48000000) (100 . 64)))
    (let* ((buffer (generate-new-buffer " *mongodb-test-frame*"))
           (process (make-pipe-process :name "mongodb-test-frame"
                                       :buffer buffer :noquery t))
           (conn (make-mongodb-conn
                  :process process :buffer buffer :live t
                  :max-message-size-bytes (cdr case))))
      (unwind-protect
          (progn
            (with-current-buffer buffer
              (set-buffer-multibyte nil)
              (insert (mongodb--pack-int32 (car case))))
            (should-error (mongodb--recv-message-frame conn 1 nil)
                          :type 'mongodb-error))
        (mongodb-disconnect conn)))))

(ert-deftest mongodb-test-command-timeout-invalidates-connection ()
  "A response timeout should close the connection before reuse."
  (let* ((buffer (generate-new-buffer " *mongodb-test-timeout*"))
         (process (make-pipe-process :name "mongodb-test-timeout"
                                     :buffer buffer :noquery t))
         (conn (make-mongodb-conn :process process :buffer buffer :live t)))
    (cl-letf (((symbol-function 'process-send-string) #'ignore))
      (should-error (mongodb-command conn "admin" '(("ping" . 1)) 0)
                    :type 'mongodb-error))
    (should (mongodb-conn-closed conn))
    (should-not (mongodb-live-p conn))
    (should-not (buffer-live-p buffer))))

(ert-deftest mongodb-test-write-error-is-structured-and-invalidates-connection ()
  "A process write failure should surface as `mongodb-error'."
  (let* ((buffer (generate-new-buffer " *mongodb-test-write*"))
         (process (make-pipe-process :name "mongodb-test-write"
                                     :buffer buffer :noquery t))
         (conn (make-mongodb-conn :process process :buffer buffer :live t)))
    (cl-letf (((symbol-function 'process-send-string)
               (lambda (&rest _args) (error "write failed"))))
      (should-error (mongodb-command conn "admin" '(("ping" . 1)))
                    :type 'mongodb-error))
    (should (mongodb-conn-closed conn))
    (should-not (buffer-live-p buffer))))

(ert-deftest mongodb-test-connect-uses-bounded-asynchronous-socket ()
  "Connection setup should use :nowait and run the timeout wait helper."
  (let (captured waited conn)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest args) (setq captured args) 'proc))
              ((symbol-function 'mongodb--wait-for-connect)
               (lambda (&rest _args) (setq waited t)))
              ((symbol-function 'mongodb--send-document)
               (lambda (&rest _args)
                 '(("ok" . 1) ("minWireVersion" . 6)
                   ("maxWireVersion" . 25))))
              ((symbol-function 'process-live-p) (lambda (_proc) t))
              ((symbol-function 'delete-process) #'ignore))
      (unwind-protect
          (setq conn (mongodb-connect '(:host "db" :port 27017)))
        (when conn (mongodb-disconnect conn))))
    (should (eq (plist-get captured :nowait) t))
    (should waited)))

(ert-deftest mongodb-test-connect-wait-enforces-deadline ()
  "The socket wait helper should stop when its deadline expires."
  (let ((times '(0 2)))
    (cl-letf (((symbol-function 'float-time)
               (lambda (&optional _time) (pop times)))
              ((symbol-function 'process-status) (lambda (_proc) 'connect))
              ((symbol-function 'accept-process-output) #'ignore))
      (should-error (mongodb--wait-for-connect 'proc "db" 27017 1)
                    :type 'mongodb-error))))

(ert-deftest mongodb-test-connect-wraps-socket-errors-and-cleans-buffer ()
  "Socket creation errors should be structured and release the process buffer."
  (let (buffer)
    (cl-letf (((symbol-function 'generate-new-buffer)
               (lambda (_name)
                 (setq buffer (get-buffer-create " *mongodb-test-connect*"))))
              ((symbol-function 'make-network-process)
               (lambda (&rest _args) (error "connect failed"))))
      (should-error (mongodb-connect '(:host "db")) :type 'mongodb-error)
      (should-not (buffer-live-p buffer)))))

(ert-deftest mongodb-test-scram-mechanism-selection ()
  "SCRAM should prefer SHA-256 and reject unsupported explicit mechanisms."
  (let ((credential (make-mongodb--credential :username "user")))
    (should
     (equal (mongodb--choose-auth-mechanism
             credential
             '(("saslSupportedMechs" . ("SCRAM-SHA-1" "SCRAM-SHA-256"))))
            "SCRAM-SHA-256"))
    (setf (mongodb--credential-mechanism credential) "PLAIN")
    (should-error (mongodb--choose-auth-mechanism credential nil)
                  :type 'mongodb-error)))

(ert-deftest mongodb-test-pbkdf2-known-vectors ()
  "SCRAM PBKDF2 primitives should match published test vectors."
  (should
   (equal (mongodb-bytes-to-hex
           (mongodb--pbkdf2-hmac-sha1 "password" "salt" 1))
          "0c60c80f961f0e71f3a9b524af6012062fe037a6"))
  (should
   (equal (mongodb-bytes-to-hex
           (mongodb--pbkdf2-hmac-sha256 "password" "salt" 1))
          "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")))

(ert-deftest mongodb-test-negative-bson-string-length-is-structured-error ()
  "Malformed BSON string lengths should signal `mongodb-error'."
  (should-error
   (mongodb--decode-string-value
    (make-mongodb--reader :data (mongodb--pack-int32 0) :pos 0))
   :type 'mongodb-error))

(ert-deftest mongodb-test-bson-corpus-decode-errors-are-rejected ()
  "Reject representative malformed documents from the official BSON corpus."
  (dolist (hex '("090000000862000200"
                 "1C00000003666F6F001200000002626172000500000062617A000000"
                 "0E00000002610002000000E90000"
                 "0500000000FF"))
    (should-error
     (mongodb--decode-document-from-string (mongodb-test--hex-bytes hex))
     :type 'mongodb-error)))

(ert-deftest mongodb-test-decimal128-noncanonical-coefficients-decode-as-zero ()
  "Decode the three lossy zero cases from the official BSON corpus."
  (dolist (case '(("180000001364000000000000000000000000000000106C00" . "0")
                  ("18000000136400DCBA9876543210DEADBEEF00000010EC00" . "-0")
                  ("18000000136400FFFFFFFFFFFFFFFFFFFFFFFFFFFF116C00" . "0E+3")))
    (let* ((document
            (mongodb--decode-document-from-string
             (mongodb-test--hex-bytes (car case))))
           (decimal (cdr (assoc "d" document))))
      (should (equal (cdr (assoc "$numberDecimal" decimal)) (cdr case))))))

(ert-deftest mongodb-test-auth-database-alias-and-connection-metadata ()
  "Auth database alias and normalized metadata should be public and stable."
  (let* ((params (mongodb--normalize-params
                  '(:url "mongodb://db.example:27018/app"
                    :username "ada" :auth-database "accounts")))
         (credential (mongodb--params-credential params))
         (conn (make-mongodb-conn
                :host (plist-get params :host)
                :port (plist-get params :port)
                :credential credential)))
    (should (equal (mongodb--credential-source credential) "accounts"))
    (should (equal (mongodb-connection-host conn) "db.example"))
    (should (= (mongodb-connection-port conn) 27018))
    (should (equal (mongodb-connection-username conn) "ada"))))

(ert-deftest mongodb-test-write-limits-reject-before-send ()
  "Server BSON and write batch limits should be enforced before transport."
  (let* ((buffer (generate-new-buffer " *mongodb-test-write-limit*"))
         (process (make-pipe-process :name "mongodb-test-write-limit"
                                     :buffer buffer :noquery t))
         (conn (make-mongodb-conn
                :process process :buffer buffer :live t
                :max-bson-object-size 64 :max-write-batch-size 1))
         sent)
    (unwind-protect
        (cl-letf (((symbol-function 'process-send-string)
                   (lambda (&rest _) (setq sent t))))
          (should-error
           (mongodb--send-document
            conn `(("insert" . "items")
                   ("documents" . ,(vector '(("x" . 1)) '(("x" . 2))))
                   ("$db" . "app")))
           :type 'mongodb-error)
          (should-not sent)
          (should-error
           (mongodb--validate-bson-size
            conn `(("value" . ,(make-string 100 ?x))) "test document")
           :type 'mongodb-error))
      (mongodb-disconnect conn))))

(ert-deftest mongodb-test-cursor-document-limit-kills-open-cursor ()
  "Cursor helpers should kill and reject results beyond their hard cap."
  (let ((mongodb-max-cursor-documents 2)
        commands)
    (cl-letf (((symbol-function 'mongodb-command)
               (lambda (_conn _database command &rest _)
                 (push command commands)
                 (if (assoc "killCursors" command)
                     '(("ok" . 1))
                   '(("ok" . 1)
                     ("cursor" . (("id" . 11)
                                   ("ns" . "app.users")
                                   ("nextBatch" . ("c")))))))))
      (should-error
       (mongodb--cursor-results
        :conn "app" "users"
        '(("cursor" . (("id" . 10)
                        ("ns" . "app.users")
                        ("firstBatch" . ("a" "b")))))
        "firstBatch")
       :type 'mongodb-error))
    (let ((kill (cl-find-if (lambda (command) (assoc "killCursors" command))
                            commands)))
      (should kill)
      (should (equal (append (cdr (assoc "cursors" kill)) nil) '(11))))))

(ert-deftest mongodb-test-cursor-envelope-fails-closed ()
  "Malformed cursor ids and batches should not return partial results."
  (should-error
   (mongodb--cursor-results
    :conn "app" "users"
    '(("cursor" . (("id" . "not-an-int")
                    ("ns" . "app.users")
                    ("firstBatch" . ("partial")))))
    "firstBatch")
   :type 'mongodb-error)
  (should-error
   (mongodb--cursor-results
    :conn "app" "users"
    '(("cursor" . (("id" . 0)
                    ("ns" . "app.users")
                    ("firstBatch" . "not-an-array"))))
    "firstBatch")
   :type 'mongodb-error))

(ert-deftest mongodb-test-scram-resource-limits ()
  "SCRAM iteration and continuation work should be bounded."
  (let ((mongodb-scram-max-iterations 1))
    (should-error (mongodb--pbkdf2-hmac-sha256 "password" "salt" 2)
                  :type 'mongodb-error))
  (let ((mongodb-scram-max-rounds 2)
        (credential (make-mongodb--credential
                     :username "user" :password "pw" :source "admin"))
        (calls 0))
    (cl-letf (((symbol-function 'mongodb--scram-start-data)
               (lambda (&rest _)
                 '(:client-nonce "n" :client-first-bare "n=user,r=n")))
              ((symbol-function 'mongodb--scram-start-command)
               (lambda (&rest _) '(("saslStart" . 1))))
              ((symbol-function 'mongodb--scram-payload-string)
               (lambda (&rest _) ""))
              ((symbol-function 'mongodb--scram-client-final)
               (lambda (&rest _)
                 (list :message "proof" :server-signature "signature")))
              ((symbol-function 'mongodb-command)
               (lambda (&rest _)
                 (setq calls (1+ calls))
                 '(("done" . :false)
                   ("conversationId" . 1)
                   ("payload" . "")))))
      (should-error
       (mongodb--authenticate-scram :conn credential "SCRAM-SHA-256")
       :type 'mongodb-error))
    (should (= calls 3))))

(ert-deftest mongodb-test-hello-limits-are-validated ()
  "Malformed server limits should fail before they reach transport math."
  (let ((conn (make-mongodb-conn)))
    (mongodb--apply-hello-limits
     conn '(("maxBsonObjectSize" . 1024)
            ("maxMessageSizeBytes" . 4096)
            ("maxWriteBatchSize" . 10)))
    (should (= (mongodb-conn-max-message-size-bytes conn) 4096))
    (should-error
     (mongodb--apply-hello-limits
      conn '(("maxMessageSizeBytes" . "large")))
     :type 'mongodb-error))
  (let ((conn (make-mongodb-conn)))
    (mongodb--apply-hello-limits
     conn `(("maxBsonObjectSize" . ,(* 1024 1024 1024))
            ("maxMessageSizeBytes" . ,mongodb--int32-max)
            ("maxWriteBatchSize" . 1000000)))
    (should (= (mongodb-conn-max-bson-object-size conn) (* 16 1024 1024)))
    (should (= (mongodb-conn-max-message-size-bytes conn) 48000000))
    (should (= (mongodb-conn-max-write-batch-size conn) 100000))))

(ert-deftest mongodb-test-busy-connection-rejects-command ()
  "A connection should not interleave command/response exchanges."
  (let* ((buffer (generate-new-buffer " *mongodb-test-busy*"))
         (process (make-pipe-process :name "mongodb-test-busy"
                                     :buffer buffer :noquery t))
         (conn (make-mongodb-conn :process process :buffer buffer
                                  :live t :busy t)))
    (unwind-protect
        (should-error (mongodb-command conn "admin" '(("ping" . 1)))
                      :type 'mongodb-error)
      (mongodb-disconnect conn))))

(ert-deftest mongodb-test-hello-command-can-be-sent-as-op-msg ()
  (let* ((message (mongodb--make-op-msg 42 (mongodb--hello-command nil)))
         (frame (mongodb--decode-message-frame message))
         (document (mongodb--decoded-message-document frame))
         (client (cdr (assoc "client" document))))
    (should (= (mongodb--decoded-message-request-id frame) 42))
    (should (equal (cdr (assoc "$db" document)) "admin"))
    (should (assoc "os" client))
    (should (assoc "type" (cdr (assoc "os" client))))))

(ert-deftest mongodb-test-op-msg-requires-one-body-and-unique-sequences ()
  "OP_MSG replies should have one body and unique sequence identifiers."
  (cl-labels
      ((frame (sections)
         (let ((length (+ 16 4 (length sections))))
           (concat (mongodb--pack-int32 length)
                   (mongodb--pack-int32 1)
                   (mongodb--pack-int32 0)
                   (mongodb--pack-int32 mongodb--op-msg)
                   (mongodb--pack-int32 0)
                   sections))))
    (let ((body (mongodb--encode-document '(("ok" . 1))))
          (sequence
           (mongodb--encode-op-msg-document-sequence
            '("documents" . [(("x" . 1))]))))
      (should-error
       (mongodb--decode-message-frame
        (frame (concat (unibyte-string 0) body
                       (unibyte-string 0) body)))
       :type 'mongodb-error)
      (should
       (mongodb--decoded-message-document
        (mongodb--decode-message-frame
         (frame (concat sequence (unibyte-string 0) body)))))
      (should-error
       (mongodb--decode-message-frame
        (frame (concat (unibyte-string 0) body sequence sequence)))
       :type 'mongodb-error)
      (should-not
       (mongodb--decoded-message-document
        (mongodb--decode-message-frame
         (frame (concat (unibyte-string 0)
                        (mongodb--encode-document nil)))))))))

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

(ert-deftest mongodb-test-cursor-results-keeps-batch-order ()
  (let ((response '(("cursor" . (("id" . 10)
                                 ("ns" . "app.users")
                                 ("firstBatch" . ("a"))))))
        (calls 0)
        commands)
    (cl-letf (((symbol-function 'mongodb-command)
               (lambda (_conn _database command &rest _)
                 (push command commands)
                 (setq calls (1+ calls))
                 `(("ok" . 1)
                   ("cursor" . (("id" . ,(if (= calls 1) 11 0))
                                ("ns" . "app.users")
                                ("nextBatch" . ,(if (= calls 1)
                                                    '("b" "c")
                                                  '("d")))))))))
      (should (equal (mongodb--cursor-results
                      :conn "app" "users" response "firstBatch"
                      '(("batchSize" . 2)))
                     '("a" "b" "c" "d"))))
    (setq commands (nreverse commands))
    (should (equal (mapcar (lambda (command) (cdr (assoc "getMore" command)))
                           commands)
                   '(10 11)))
    (should (equal (cdr (assoc "collection" (car commands))) "users"))
    (should (= (cdr (assoc "batchSize" (car commands))) 2))))

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

(ert-deftest mongodb-test-multi-insert-uses-document-sequence ()
  "Multi-document inserts should use an OP_MSG document sequence."
  (let (captured)
    (cl-letf (((symbol-function 'mongodb-command)
               (lambda (_conn _database command timeout sequences)
                 (setq captured (list command timeout sequences))
                 '(("ok" . 1)))))
      (mongodb-insert :conn "app" "users"
                      '((("name" . "Ada")) (("name" . "Grace")))))
    (pcase-let ((`(,command ,timeout ,sequences) captured))
      (should-not timeout)
      (should-not (assoc "documents" command))
      (should (equal (caar sequences) "documents"))
      (let ((documents (cdar sequences)))
        (should (= (length documents) 2))
        (should (seq-every-p (lambda (document) (assoc "_id" document))
                             documents))))))

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
