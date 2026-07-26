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

(ert-deftest mongodb-test-document-wrapper-reports-elements ()
  "The document wrapper exposes its pairs through the public accessor."
  (should (equal (mongodb-document-elements (mongodb-document nil)) nil))
  (should (equal (mongodb-document-elements
                  (mongodb-document '(("a" . 1))))
                 '(("a" . 1)))))

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

(defmacro mongodb-test--with-pipe-conn (spec &rest body)
  "Run BODY with a live `mongodb-conn' over a fresh pipe process.
SPEC is (VAR EXTRA-SLOT...); EXTRA-SLOTS are passed to `make-mongodb-conn'
after the process, buffer, and :live t.  Cleanup runs even when an
assertion fails, so a red test cannot leak the process or buffer."
  (declare (indent 1) (debug ((symbolp &rest form) body)))
  (let ((buf (make-symbol "buffer"))
        (proc (make-symbol "process"))
        (var (car spec))
        (slots (cdr spec)))
    `(let* ((,buf (generate-new-buffer " *mongodb-test-conn*"))
            (,proc (make-pipe-process :name "mongodb-test-conn"
                                      :buffer ,buf :noquery t))
            (,var (make-mongodb-conn :process ,proc :buffer ,buf :live t
                                     ,@slots)))
       (unwind-protect
           (progn ,@body)
         (mongodb-disconnect ,var)
         (when (buffer-live-p ,buf)
           (kill-buffer ,buf))))))

(ert-deftest mongodb-test-receive-rejects-invalid-frame-length ()
  "Wire frame lengths should be bounded before reading the body."
  (dolist (case '((2 . 48000000) (100 . 64)))
    (ert-info ((format "length %s limit %s" (car case) (cdr case)))
      (mongodb-test--with-pipe-conn
          (conn :max-message-size-bytes (cdr case))
        (with-current-buffer (mongodb-conn-buffer conn)
          (set-buffer-multibyte nil)
          (insert (mongodb--pack-int32 (car case))))
        (should-error (mongodb--recv-message-frame conn 1 nil)
                      :type 'mongodb-error)))))

(ert-deftest mongodb-test-command-timeout-invalidates-connection ()
  "A response timeout should close the connection before reuse."
  (mongodb-test--with-pipe-conn (conn)
    (cl-letf (((symbol-function 'process-send-string) #'ignore))
      (should-error (mongodb-command conn "admin" '(("ping" . 1)) 0)
                    :type 'mongodb-error))
    (should (mongodb-conn-closed conn))
    (should-not (mongodb-live-p conn))
    (should-not (buffer-live-p (mongodb-conn-buffer conn)))))

(ert-deftest mongodb-test-write-error-is-structured-and-invalidates-connection ()
  "A process write failure should surface as `mongodb-error'."
  (mongodb-test--with-pipe-conn (conn)
    (cl-letf (((symbol-function 'process-send-string)
               (lambda (&rest _args) (error "write failed"))))
      (should-error (mongodb-command conn "admin" '(("ping" . 1)))
                    :type 'mongodb-error))
    (should (mongodb-conn-closed conn))
    (should-not (buffer-live-p (mongodb-conn-buffer conn)))))

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

(ert-deftest mongodb-test-connect-quit-cleans-transport ()
  "Quitting after socket setup should release its process and buffer."
  (let (buffer process quit-seen)
    (unwind-protect
        (progn
          (cl-letf (((symbol-function 'make-network-process)
                     (lambda (&rest args)
                       (setq buffer (plist-get args :buffer)
                             process
                             (make-pipe-process
                              :name "mongodb-test-connect-quit"
                              :buffer buffer :noquery t))))
                    ((symbol-function 'mongodb--wait-for-connect) #'ignore)
                    ((symbol-function 'mongodb--send-document)
                     (lambda (&rest _args) (signal 'quit nil))))
            (condition-case nil
                (mongodb-connect '(:host "db" :port 27017))
              (quit (setq quit-seen t))))
          (should quit-seen)
          (should-not (process-live-p process))
          (should-not (buffer-live-p buffer)))
      (when (process-live-p process)
        (delete-process process))
      (when (buffer-live-p buffer)
        (kill-buffer buffer)))))

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

(ert-deftest mongodb-test-noncanonical-decimal128-canonicalizes ()
  "Non-canonical Decimal128 encodings decode to values, then re-encode canonically.
The corpus steering encodings decode as signed zero and a garbage-payload
NaN decodes as plain NaN -- the codec's semantic-not-byte class: the
roundtrip changes bytes while keeping the value, and the canonical form
is a fixed point."
  (dolist (case '(("180000001364000000000000000000000000000000106C00" . "0")
                  ("18000000136400DCBA9876543210DEADBEEF00000010EC00" . "-0")
                  ("18000000136400FFFFFFFFFFFFFFFFFFFFFFFFFFFF116C00" . "0E+3")
                  ("18000000136400BEBAFECAEFBEADDE341200000000007C00" . "NaN")))
    (let* ((bytes (mongodb-test--hex-bytes (car case)))
           (document (mongodb--decode-document-from-string bytes))
           (decimal (cdr (assoc "d" document))))
      (should (mongodb-decimal128-p decimal))
      (should (equal (mongodb-decimal128-value decimal) (cdr case)))
      (let ((canonical (mongodb--encode-document document)))
        (should-not (equal canonical bytes))
        ;; The canonical form is a fixed point.
        (should (equal (mongodb--encode-document
                        (mongodb--decode-document-from-string canonical))
                       canonical))))))

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
  (mongodb-test--with-pipe-conn
      (conn :max-bson-object-size 64 :max-write-batch-size 1)
    (let (sent)
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
         :type 'mongodb-error)))))

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
      (should (equal (mapcar #'mongodb-int64-value
                             (append (cdr (assoc "cursors" kill)) nil))
                     '(11))))))

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
  (mongodb-test--with-pipe-conn (conn :busy t)
    (should-error (mongodb-command conn "admin" '(("ping" . 1)))
                  :type 'mongodb-error)))

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
    ;; Cursor ids ride the wire as int64 wrappers so a small id cannot
    ;; encode as int32, which the server rejects for getMore.
    (should (equal (mapcar (lambda (command)
                             (mongodb-int64-value
                              (cdr (assoc "getMore" command))))
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

;;;; BSON roundtrip bijectivity

(defun mongodb-test--all-types-document ()
  "Return a document exercising every BSON type the encoder can write."
  (list (cons "_id" (mongodb-object-id "65f1a2b3c4d5e6f708090a0b"))
        (cons "double" 1.5)
        (cons "nan" (/ 0.0 0.0))
        (cons "inf" 1.0e+INF)
        (cons "ninf" -1.0e+INF)
        (cons "string" "héllo")
        (cons "doc" (list (cons "nested" 1)))
        (cons "empty-doc" (mongodb-document nil))
        (cons "arr" (vector 1 "two" (vector 3)))
        (cons "empty-arr" (vector))
        (cons "binary" (mongodb-binary 0 (unibyte-string 1 0 255)))
        (cons "undef" (mongodb-undefined))
        (cons "bool-t" t)
        (cons "bool-f" :false)
        (cons "date" (mongodb-datetime 1700000000000))
        (cons "null" nil)
        (cons "regex" (mongodb-regex "^a.*b$" "i"))
        (cons "pointer" (mongodb-db-pointer
                         "db.coll"
                         (mongodb-object-id "65f1a2b3c4d5e6f708090a0c")))
        (cons "code" (mongodb-code "function () { return 1; }"))
        (cons "code-scope" (mongodb-code "x" (list (cons "k" 1))))
        (cons "code-empty-scope" (mongodb-code "y" (mongodb-document nil)))
        (cons "symbol" (mongodb-symbol "sym"))
        (cons "int32" 41)
        (cons "timestamp" (mongodb-timestamp 7 3))
        (cons "int64" (* 1024 mongodb--int32-max))
        (cons "int64-small" (mongodb-int64 7))
        (cons "decimal" (mongodb-decimal128 "1.23"))
        (cons "decimal-nan" (mongodb-decimal128 "NaN"))
        (cons "min" (mongodb-min-key))
        (cons "max" (mongodb-max-key))
        (cons "operator" (list (cons "$set" (list (cons "a" 1)))))))

(ert-deftest mongodb-test-bson-decode-encode-is-byte-identical ()
  "Decoding a document and re-encoding it reproduces the exact bytes.
This is the property that makes generated mutations safe: any value read
from the server can be written back without changing its BSON type.  The
one canonicalization is NaN payloads, covered separately: this document
carries the canonical quiet NaN, which roundtrips byte-identically."
  (let* ((bytes (mongodb--encode-document (mongodb-test--all-types-document)))
         (decoded (mongodb--decode-document-from-string bytes))
         (re-encoded (mongodb--encode-document decoded)))
    (should (equal bytes re-encoded))
    ;; The decoded representation is a fixed point, so a document that
    ;; roundtrips twice keeps the same shapes.
    (should (equal decoded
                   (mongodb--decode-document-from-string re-encoded)))))

(ert-deftest mongodb-test-bson-decode-distinguishes-empty-collections ()
  "Empty array, empty document, and null decode to three distinct values."
  (let* ((bytes (mongodb--encode-document
                 (list (cons "arr" (vector))
                       (cons "doc" (mongodb-document nil))
                       (cons "null" nil))))
         (decoded (mongodb--decode-document-from-string bytes)))
    (should (equal (cdr (assoc "arr" decoded)) (vector)))
    (should (mongodb-document-p (cdr (assoc "doc" decoded))))
    (should (null (cdr (assoc "null" decoded))))))

(ert-deftest mongodb-test-bson-arrays-decode-to-vectors ()
  "Arrays decode to vectors so they stay distinct from alist documents."
  (let* ((bytes (mongodb--encode-document
                 (list (cons "docs" (vector (list (cons "a" 1)))))))
         (docs (cdr (assoc "docs" (mongodb--decode-document-from-string
                                   bytes)))))
    (should (vectorp docs))
    (should (equal (aref docs 0) '(("a" . 1))))))

(ert-deftest mongodb-test-alists-always-encode-as-documents ()
  "An alist encodes as an embedded document whatever its keys look like.
A legitimate nested document whose first key is \"$oid\" must survive the
roundtrip as a document; inferring types from key names would silently
turn it into an ObjectId."
  (dolist (value '((("$oid" . "65f1a2b3c4d5e6f708090a0b"))
                   (("$set" . (("a" . 1))))
                   (("$gt" . 5))
                   (("$numberDouble" . "NaN"))
                   (("$minKey" . 1))))
    (ert-info ((format "value: %S" value))
      (should (= (aref (mongodb--encode-element "k" value) 0) #x03))))
  (let* ((bytes (mongodb--encode-document
                 '(("v" . (("$oid" . "65f1a2b3c4d5e6f708090a0b"))))))
         (decoded (mongodb--decode-document-from-string bytes)))
    (should (equal (mongodb--encode-document decoded) bytes))
    (should (equal (cdr (assoc "v" decoded))
                   '(("$oid" . "65f1a2b3c4d5e6f708090a0b"))))))

(ert-deftest mongodb-test-scalar-types-decode-to-wrapper-structs ()
  "BSON scalar types decode to the wrapper structs the encoder accepts.
Key names never carry type information, so a decoded scalar cannot be
confused with a document that happens to use the same spelling."
  (let* ((doc (list (cons "id" (mongodb-object-id
                                "65f1a2b3c4d5e6f708090a0b"))
                    (cons "name" "Ada")
                    (cons "active" t)
                    (cons "inactive" :false)
                    (cons "count32" (mongodb-int32 7))
                    (cons "when" (mongodb-datetime 1700000000000))
                    (cons "dec" (mongodb-decimal128 "1.23"))
                    (cons "bin" (mongodb-binary 4 (unibyte-string 1 2)))
                    (cons "re" (mongodb-regex "^a" "i"))
                    (cons "ts" (mongodb-timestamp 7 3))
                    (cons "sym" (mongodb-symbol "s"))
                    (cons "undef" (mongodb-undefined))
                    (cons "min" (mongodb-min-key))
                    (cons "max" (mongodb-max-key))))
         (decoded (mongodb--decode-document-from-string
                   (mongodb--encode-document doc))))
    (cl-flet ((field (name) (cdr (assoc name decoded))))
      (should (equal (field "name") "Ada"))
      (should (eq (field "active") t))
      (should (eq (field "inactive") :false))
      ;; int32 wrappers decode bare; the value survives.
      (should (eql (field "count32") 7))
      (should (mongodb-object-id-p (field "id")))
      (should (equal (mongodb-object-id-hex (field "id"))
                     "65f1a2b3c4d5e6f708090a0b"))
      (should (mongodb-datetime-p (field "when")))
      (should (mongodb-decimal128-p (field "dec")))
      (should (equal (mongodb-decimal128-value (field "dec")) "1.23"))
      (should (mongodb-binary-p (field "bin")))
      (should (= (mongodb-binary-subtype (field "bin")) 4))
      (should (mongodb-regex-p (field "re")))
      (should (mongodb-timestamp-p (field "ts")))
      (should (mongodb-symbol-p (field "sym")))
      (should (mongodb-undefined-p (field "undef")))
      (should (mongodb-min-key-p (field "min")))
      (should (mongodb-max-key-p (field "max"))))))

(ert-deftest mongodb-test-small-int64-keeps-its-width ()
  "An int64 whose value fits an int32 must stay an int64.
Bare integers re-encode by numeric range, so 0x12 decodes to the
`mongodb-int64' wrapper; without it, (mongodb-int64 7) came back as
0x10 and changed type on the server."
  (dolist (value (list -1 0 1 7
                       (- (expt 2 31)) (1- (expt 2 31))
                       (expt 2 31) (- (1+ (expt 2 31)))
                       (1- (expt 2 63)) (- (expt 2 63))))
    (ert-info ((format "value: %d" value))
      (let* ((bytes (mongodb--encode-document
                     `(("v" . ,(mongodb-int64 value)))))
             (decoded (mongodb--decode-document-from-string bytes))
             (v (cdr (assoc "v" decoded))))
        (should (= (aref bytes 4) #x12))
        (should (mongodb-int64-p v))
        (should (= (mongodb-int64-value v) value))
        (should (equal (mongodb--encode-document decoded) bytes)))))
  ;; Bare int32-range integers keep decoding bare: they re-encode as
  ;; int32 deterministically.
  (let* ((bytes (mongodb--encode-document '(("v" . 7))))
         (decoded (mongodb--decode-document-from-string bytes)))
    (should (= (aref bytes 4) #x10))
    (should (eql (cdr (assoc "v" decoded)) 7))
    (should (equal (mongodb--encode-document decoded) bytes))))

(ert-deftest mongodb-test-cursor-id-accepts-wrapped-int64 ()
  "Cursor ids arrive as int64 wrappers and unwrap to bare integers."
  (should (= (mongodb--cursor-id `(("id" . ,(mongodb-int64 7)))) 7))
  (should (= (mongodb--cursor-id `(("id" . ,(mongodb-int64 0)))) 0))
  (should (= (mongodb--cursor-id '(("id" . 9))) 9))
  (should-error (mongodb--cursor-id '(("id" . "nope")))
                :type 'mongodb-error))

(ert-deftest mongodb-test-non-finite-doubles-roundtrip-semantically ()
  "Non-finite doubles decode as native floats and re-encode canonically.
The sign survives; a non-canonical NaN payload does not, so the
roundtrip is semantic equivalence rather than byte identity for NaN."
  (let* ((doc (list (cons "nan" (/ 0.0 0.0))
                    (cons "neg-nan" (copysign (/ 0.0 0.0) -1.0))
                    (cons "inf" 1.0e+INF)
                    (cons "ninf" -1.0e+INF)))
         (bytes (mongodb--encode-document doc))
         (decoded (mongodb--decode-document-from-string bytes)))
    ;; Canonical NaN bit patterns roundtrip byte-identically.
    (should (equal (mongodb--encode-document decoded) bytes))
    (should (isnan (cdr (assoc "nan" decoded))))
    (should (isnan (cdr (assoc "neg-nan" decoded))))
    (should (< (copysign 1.0 (cdr (assoc "neg-nan" decoded))) 0))
    (should (= (cdr (assoc "inf" decoded)) 1.0e+INF))
    (should (= (cdr (assoc "ninf" decoded)) -1.0e+INF))
    ;; A non-canonical NaN payload collapses to the canonical quiet NaN
    ;; of the same sign: same semantics, not the same bytes.
    (let* ((payload-nan (concat (mongodb--pack-int32 16)
                                (unibyte-string #x01) "n" (unibyte-string 0)
                                (unibyte-string #xbe #xba #xfe #xca
                                                #x00 #x00 #xf8 #x7f)
                                (unibyte-string 0)))
           (redecoded (mongodb--decode-document-from-string payload-nan)))
      (should (isnan (cdr (assoc "n" redecoded))))
      (should-not (equal (mongodb--encode-document redecoded) payload-nan))
      (should (isnan (cdr (assoc "n" (mongodb--decode-document-from-string
                                      (mongodb--encode-document
                                       redecoded)))))))))

;;;; Live smoke tests (need a reachable MongoDB server)

(defun mongodb-test--live-params ()
  "Return connection params for live tests, or nil when unconfigured.
Set the MONGODB_TEST_URI environment variable, e.g.
mongodb://127.0.0.1:27017/clutch_test, to enable them."
  (when-let* ((uri (getenv "MONGODB_TEST_URI")))
    (list :url uri)))

(ert-deftest mongodb-test-live-roundtrip-through-server ()
  "Every BSON type survives an insert/find roundtrip through a server."
  (skip-unless (mongodb-test--live-params))
  (let* ((conn (mongodb-connect (mongodb-test--live-params)))
         (database (or (mongodb-conn-database conn) "clutch_test"))
         (collection "roundtrip_test"))
    (unwind-protect
        (let ((doc (mongodb-test--all-types-document)))
          (ignore-errors
            (mongodb-command conn database `(("drop" . ,collection))))
          (mongodb-insert conn database collection (vector doc))
          (let* ((found (mongodb-find conn database collection
                                      (list (cons "_id" (cdr (assoc "_id" doc))))))
                 (stored (car found)))
            (should stored)
            ;; What came back re-encodes to the same bytes we stored.
            (should (equal (mongodb--encode-document stored)
                           (mongodb--encode-document
                            (mongodb--decode-document-from-string
                             (mongodb--encode-document doc)))))))
      (ignore-errors
        (mongodb-command conn database `(("drop" . ,collection))))
      (mongodb-disconnect conn))))

;;; mongodb-test.el ends here
