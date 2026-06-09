;;; mongodb.el --- MongoDB wire protocol client -*- lexical-binding: t; -*-

;; Copyright (C) 2025-2026 Lucius Chen
;; SPDX-License-Identifier: GPL-3.0-or-later

;; Author: Lucius Chen <chenyh572@gmail.com>
;; Maintainer: Lucius Chen <chenyh572@gmail.com>
;; Version: 0.1.0
;; Package-Requires: ((emacs "29.1"))
;; Keywords: data, tools
;; URL: https://github.com/LuciusChen/mongodb.el

;; This file is part of mongodb.el.

;; mongodb.el is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; mongodb.el is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with mongodb.el.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; Minimal MongoDB wire protocol implementation for ordinary mongod
;; connections, including TCP and UNIX-domain socket endpoints, TLS,
;; SCRAM-SHA-256/SCRAM-SHA-1 authentication, SRV DNS discovery,
;; snappy/zlib wire compression, and replica-set primary/read-preference
;; selection from seed lists.
;;
;; This module speaks modern OP_MSG and encodes/decodes BSON directly.  It is
;; intentionally a command-level client, not a JavaScript evaluator.  Higher
;; layers translate supported MongoDB shell helper forms into command
;; documents before calling this module.

;;; Code:

(require 'cl-lib)
(require 'mongodb-bson)
(require 'mongodb-wire)
(require 'mongodb-params)
(require 'mongodb-auth)
(require 'seq)
(require 'subr-x)
(require 'gnutls)

(defgroup mongodb nil
  "MongoDB wire protocol client."
  :group 'applications)

(defcustom mongodb-timeout-seconds 30
  "Seconds to wait for MongoDB wire protocol responses."
  :type 'number
  :group 'mongodb)

(defcustom mongodb-connect-timeout-seconds 10
  "Seconds to wait while opening a MongoDB socket."
  :type 'number
  :group 'mongodb)

(defcustom mongodb-server-selection-timeout-seconds 30
  "Seconds to wait while selecting a MongoDB server."
  :type 'number
  :group 'mongodb)

(defcustom mongodb-local-threshold-seconds 0.015
  "MongoDB server selection latency window in seconds.
This maps to the driver's localThresholdMS connection string option."
  :type 'number
  :group 'mongodb)

(defcustom mongodb-monitor-heartbeat-seconds 10
  "Seconds between explicit MongoDB monitor heartbeat ticks."
  :type 'number
  :group 'mongodb)

(defcustom mongodb-monitor-max-await-time-ms 10000
  "Maximum await time in milliseconds for MongoDB awaitable hello monitoring."
  :type 'integer
  :group 'mongodb)

(defcustom mongodb-pool-event-hook nil
  "Abnormal hook run with one argument for MongoDB pool events.
Each EVENT is an alist with at least `type', `address', and `pool' entries.
Event types currently include `connection-pool-created',
`connection-pool-ready', `connection-pool-cleared',
`connection-pool-closed', `connection-created', `connection-ready',
`connection-closed', `connection-check-out-started',
`connection-check-out-failed', `connection-checked-out', and
`connection-checked-in'.  Load-balanced pool-cleared and connection-ready
events may include `service-id'.  Pool-cleared events may include
`interrupt-in-use-connections' when checked-out connections are interrupted."
  :type 'hook
  :group 'mongodb)

(defcustom mongodb-command-event-hook nil
  "Abnormal hook run with one argument for MongoDB command events.
Each EVENT is an alist with at least `type', `command-name',
`database-name', `request-id', and `connection-id' entries.  Event types are
`command-started', `command-succeeded', and `command-failed'.  Bulk write
events include `operation-id'; load-balanced events include `service-id'.
Pooled command events include `driver-connection-id'."
  :type 'hook
  :group 'mongodb)

(defcustom mongodb-sdam-event-hook nil
  "Abnormal hook run with one argument for MongoDB SDAM events.
Each EVENT is an alist with at least a `type' entry.  Heartbeat event types are
`server-heartbeat-started', `server-heartbeat-succeeded', and
`server-heartbeat-failed'; these include `connection-id', `address', and
`awaited'.  Terminal heartbeat events include `duration-ms' and either `reply'
or `failure'.  Lifecycle event types are `topology-opening', `server-opening',
`server-closed', and `topology-closed'.  Description event types are
`server-description-changed' and `topology-description-changed'; these include
`topology-id', `previous-description', and `new-description'."
  :type 'hook
  :group 'mongodb)

(defcustom mongodb-tls-verify-server t
  "Non-nil means verify MongoDB TLS certificates and hostnames by default."
  :type 'boolean
  :group 'mongodb)

(defcustom mongodb-tls-trustfiles nil
  "List of PEM certificate authority files for MongoDB TLS verification."
  :type '(repeat file)
  :group 'mongodb)

(defcustom mongodb-tls-keylist nil
  "Client certificate key list for MongoDB TLS.
Each element has the form (KEY-FILE CERT-FILE), matching `gnutls-negotiate'."
  :type '(repeat (list file file))
  :group 'mongodb)

(defconst mongodb-version "0.1.0")

(defconst mongodb--client-min-wire-version 6
  "Minimum MongoDB wire version supported by this OP_MSG client.")

(defconst mongodb--client-max-wire-version 25
  "Maximum MongoDB wire version this client declares compatible.")

(defconst mongodb--client-min-wire-version-release "MongoDB 3.6"
  "Server release corresponding to `mongodb--client-min-wire-version'.")

(defconst mongodb--default-max-bson-object-size (* 16 1024 1024)
  "Default MongoDB max BSON object size when hello omits the field.")

(defconst mongodb--default-max-message-size-bytes 48000000
  "Default MongoDB max wire message size when hello omits the field.")

(defconst mongodb--default-max-write-batch-size 100000
  "Default MongoDB max write batch size when hello omits the field.")

(defconst mongodb--write-batch-message-safety-bytes 1024
  "Conservative byte allowance for driver metadata added to write batches.")

(defconst mongodb--round-trip-time-alpha 0.2
  "MongoDB SDAM average RTT EWMA weight.")

(defconst mongodb--sensitive-command-names
  '("authenticate" "saslStart" "saslContinue" "getnonce"
    "createUser" "updateUser" "copydbgetnonce" "copydbsaslstart"
    "copydb")
  "MongoDB command names whose monitoring event documents must be redacted.")

(defconst mongodb--write-command-names
  '("insert" "update" "delete" "findAndModify" "findandmodify"
    "create" "drop" "dropDatabase" "createIndexes" "dropIndexes"
    "renameCollection" "collMod" "bulkWrite"
    "createUser" "updateUser" "dropUser"
    "grantRolesToUser" "revokeRolesFromUser")
  "MongoDB command names that require a writable server.")

(defconst mongodb--read-command-names
  '("aggregate" "collStats" "count" "dbStats" "distinct" "explain" "find"
    "listCollections" "listDatabases" "listIndexes" "mapReduce")
  "MongoDB command names that may carry OP_MSG $readPreference.")

(defconst mongodb--retryable-read-command-names
  '("aggregate" "collStats" "count" "dbStats" "distinct" "find"
    "listCollections" "listDatabases" "listIndexes")
  "MongoDB read command names that may be retried once.")

(defconst mongodb--retryable-read-error-codes
  '(6 7 89 91 134 189 262 9001 10107 11600 11602 13435 13436)
  "MongoDB server error codes that make a read retryable.")

(defconst mongodb--retryable-write-error-codes
  '(6 7 89 91 189 262 9001 10107 11600 11602 13435 13436)
  "MongoDB server error codes that make a write retryable.")

(defconst mongodb--state-change-error-code-names
  '("InterruptedAtShutdown" "InterruptedDueToReplStateChange"
    "NotMaster" "NotMasterNoSlaveOk" "NotPrimaryNoSecondaryOk"
    "NotPrimaryOrSecondary" "NotWritablePrimary" "PrimarySteppedDown"
    "ShutdownInProgress")
  "MongoDB command error names that imply a server state change.")

(defconst mongodb--unknown-transaction-commit-result-label
  "UnknownTransactionCommitResult")

(defconst mongodb--transient-transaction-error-label
  "TransientTransactionError")

(defconst mongodb--system-overloaded-error-label "SystemOverloadedError")

(defconst mongodb--retryable-error-label "RetryableError")

(defconst mongodb--retryable-write-error-label "RetryableWriteError")

(defconst mongodb--commit-non-unknown-write-concern-error-codes '(79 100)
  "Commit write concern error codes that do not imply unknown commit result.
79 is UnknownReplWriteConcern and 100 is CannotSatisfyWriteConcern /
UnsatisfiableWriteConcern.")

(defvar mongodb--retryable-write-context nil
  "Non-nil when a helper is executing a supported retryable write operation.")

(defvar mongodb--operation-command-context nil
  "Non-nil when a command is sent for a typed helper operation.")

(defvar mongodb--command-event-context nil
  "Dynamic context for command monitoring around low-level OP_MSG sends.")

(defvar mongodb--command-operation-id nil
  "Dynamic command monitoring operation id for related commands.")

(defvar mongodb--next-command-operation-id 0
  "Last allocated command monitoring operation id.")

(defvar mongodb--next-topology-id 0
  "Last allocated SDAM topology id.")

(defvar mongodb--suppress-command-events nil
  "Non-nil suppresses command monitoring events for internal monitor heartbeats.")

(cl-defstruct mongodb-server-description
  "MongoDB SDAM-style description of one server."
  address
  type
  set-name
  hosts
  passives
  arbiters
  primary
  me
  min-wire-version
  max-wire-version
  logical-session-timeout-minutes
  service-id
  topology-version
  election-id
  set-version
  tags
  last-write-date
  last-update-time
  round-trip-time
  error)

(cl-defstruct mongodb-topology-description
  "MongoDB SDAM-style description of the known deployment topology."
  type
  set-name
  servers
  primary-address
  max-election-id
  max-set-version
  logical-session-timeout-minutes
  compatible
  compatibility-error)

(cl-defstruct mongodb--pool-entry
  conn
  idle-since
  generation)

(cl-defstruct mongodb--server-candidate
  "A connected MongoDB server candidate during initial server selection."
  conn
  hello
  server)

(cl-defstruct mongodb-pool
  "A small MongoDB connection pool for reusing native wire connections."
  params
  max-size
  min-size
  max-idle-time
  wait-queue-timeout
  max-connecting
  connecting
  generation
  service-generations
  service-counts
  conn-generations
  conn-service-ids
  conn-ids
  conn-purposes
  next-connection-id
  monitor-conn
  monitor-timer
  monitor-error
  paused
  available
  in-use
  closed)

(cl-defstruct mongodb-conn
  "A MongoDB TCP connection using OP_MSG."
  params
  credential
  authenticate
  process
  buffer
  host
  port
  database
  socket-timeout
  operation-timeout
  local-threshold
  heartbeat-frequency
  server-monitoring-mode
  retry-reads
  retry-writes
  request-id
  txn-number
  max-wire-version
  max-bson-object-size
  max-message-size-bytes
  max-write-batch-size
  compressors
  server-api
  read-preference
  read-concern
  write-concern
  load-balanced
  service-id
  hello-command
  last-hello
  topology
  topology-id
  monitor-timer
  monitor-error
  session-id
  cluster-time
  session-cluster-time
  transaction-state
  transaction-number
  transaction-read-preference
  transaction-read-concern
  transaction-write-concern
  transaction-max-commit-time-ms
  transaction-recovery-token
  transaction-pinned-address
  transaction-pinned-service-id
  transaction-commit-sent
  pool-connection-id
  closed)

;;;; Wire transport

(defun mongodb--maybe-compress-request (conn document message)
  "Return MESSAGE, optionally compressed for CONN and DOCUMENT."
  (let ((compressor (car (mongodb-conn-compressors conn))))
    (if (and compressor
             (mongodb--command-compressible-p document))
        (mongodb--make-op-compressed message compressor)
      message)))

(defun mongodb--wait-for-bytes (conn count timeout)
  "Wait until CONN buffer contains at least COUNT bytes.

Arguments: CONN, COUNT, TIMEOUT."
  (let* ((proc (mongodb-conn-process conn))
         (buffer (mongodb-conn-buffer conn))
         (deadline (+ (float-time) timeout)))
    (while (and (process-live-p proc)
                (< (with-current-buffer buffer (buffer-size)) count)
                (< (float-time) deadline))
      (accept-process-output proc 0.05)
      (sit-for 0 t))
    (unless (process-live-p proc)
      (signal 'mongodb-error
              (list "MongoDB connection closed while waiting for response")))
    (when (< (with-current-buffer buffer (buffer-size)) count)
      (signal 'mongodb-error
              (list "Timed out waiting for MongoDB response")))))

(defun mongodb--recv-message-frame
    (conn &optional timeout expected-response-to allow-more-to-come)
  "Read one OP_MSG wire message frame from CONN.

Arguments: CONN, TIMEOUT, EXPECTED-RESPONSE-TO, ALLOW-MORE-TO-COME."
  (let* ((buffer (mongodb-conn-buffer conn))
         (timeout (or timeout
                      (mongodb-conn-socket-timeout conn)
                      mongodb-timeout-seconds))
         length message)
    (mongodb--wait-for-bytes conn 4 timeout)
    (setq length
          (with-current-buffer buffer
            (mongodb--read-int32-from-string
             (buffer-substring-no-properties (point-min) (+ (point-min) 4)))))
    (when (< length 16)
      (signal 'mongodb-error
              (list (format "Invalid MongoDB wire message length: %s" length))))
    (mongodb--wait-for-bytes conn length timeout)
    (setq message
          (with-current-buffer buffer
            (prog1 (buffer-substring-no-properties
                    (point-min)
                    (+ (point-min) length))
              (delete-region (point-min) (+ (point-min) length)))))
    (let ((frame (mongodb--decode-message-frame message allow-more-to-come)))
      (mongodb--validate-response-to frame expected-response-to)
      frame)))

(defun mongodb--recv-message
    (conn &optional timeout expected-response-to allow-more-to-come)
  "Read one OP_MSG wire message from CONN.

Arguments: CONN, TIMEOUT, EXPECTED-RESPONSE-TO, ALLOW-MORE-TO-COME."
  (mongodb--decoded-message-document
   (mongodb--recv-message-frame
    conn timeout expected-response-to allow-more-to-come)))

(defun mongodb--recv-handshake-message (conn &optional timeout expected-response-to)
  "Read one legacy handshake reply from CONN.

Arguments: CONN, TIMEOUT, EXPECTED-RESPONSE-TO."
  (let* ((buffer (mongodb-conn-buffer conn))
         (timeout (or timeout
                      (mongodb-conn-socket-timeout conn)
                      mongodb-timeout-seconds))
         length message)
    (mongodb--wait-for-bytes conn 4 timeout)
    (setq length
          (with-current-buffer buffer
            (mongodb--read-int32-from-string
             (buffer-substring-no-properties (point-min) (+ (point-min) 4)))))
    (when (< length 16)
      (signal 'mongodb-error
              (list (format "Invalid MongoDB wire message length: %s" length))))
    (mongodb--wait-for-bytes conn length timeout)
    (setq message
          (with-current-buffer buffer
            (prog1 (buffer-substring-no-properties
                    (point-min)
                    (+ (point-min) length))
              (delete-region (point-min) (+ (point-min) length)))))
    (let ((frame (mongodb--decode-op-reply-frame message)))
      (mongodb--validate-response-to frame expected-response-to)
      (mongodb--decoded-message-document frame))))

(defun mongodb--next-request-id (conn)
  "Return the next request id for CONN."
  (let ((next (1+ (or (mongodb-conn-request-id conn) 0))))
    (setf (mongodb-conn-request-id conn) next)
    next))

(defun mongodb--send-document-with-flags
    (conn document &optional sequences flag-bits)
  "Send DOCUMENT as an OP_MSG request over CONN with FLAG-BITS.
SEQUENCES, when non-nil, is a list of OP_MSG document sequences."
  (mongodb--validate-op-msg-size conn document sequences)
  (let* ((request-id (mongodb--next-request-id conn))
         (message (mongodb--make-op-msg
                   request-id document flag-bits nil sequences))
         (wire-message (mongodb--maybe-compress-request conn document message)))
    (mongodb--command-event-started conn request-id)
    (condition-case err
        (progn
          (process-send-string
           (mongodb-conn-process conn)
           wire-message)
          request-id)
      (error
       (mongodb--command-event-failed conn err)
       (signal (car err) (cdr err))))))

(defun mongodb--send-document (conn document &optional sequences)
  "Send DOCUMENT as an OP_MSG request over CONN.
SEQUENCES, when non-nil, is a list of OP_MSG document sequences."
  (mongodb--send-document-with-flags conn document sequences))

(defun mongodb--send-handshake (conn document)
  "Send initial legacy handshake DOCUMENT over CONN."
  (let ((request-id (mongodb--next-request-id conn)))
    (process-send-string
     (mongodb-conn-process conn)
     (mongodb--make-op-query request-id "admin" document))
    request-id))

;;;; Hello limits

(defun mongodb--hello-positive-integer (hello field default)
  "Return positive integer FIELD from HELLO, or DEFAULT when omitted."
  (let ((value (cdr (assoc field hello))))
    (cond
     ((null value) default)
     ((and (integerp value)
           (> value 0))
      value)
     (t
      (signal 'mongodb-error
              (list (format "MongoDB hello field %s must be a positive integer, got %S"
                            field value)))))))

(defun mongodb--apply-hello-limits (conn hello)
  "Cache MongoDB command size and write batch limits from HELLO on CONN."
  (setf (mongodb-conn-max-bson-object-size conn)
        (mongodb--hello-positive-integer
         hello "maxBsonObjectSize" mongodb--default-max-bson-object-size))
  (setf (mongodb-conn-max-message-size-bytes conn)
        (mongodb--hello-positive-integer
         hello "maxMessageSizeBytes" mongodb--default-max-message-size-bytes))
  (setf (mongodb-conn-max-write-batch-size conn)
        (mongodb--hello-positive-integer
         hello "maxWriteBatchSize" mongodb--default-max-write-batch-size))
  conn)

(defun mongodb--max-write-batch-size (conn)
  "Return CONN's effective MongoDB max write batch size."
  (or (and (mongodb-conn-p conn)
           (mongodb-conn-max-write-batch-size conn))
      mongodb--default-max-write-batch-size))

(defun mongodb--max-bson-object-size (conn)
  "Return CONN's effective MongoDB max BSON object size."
  (or (and (mongodb-conn-p conn)
           (mongodb-conn-max-bson-object-size conn))
      mongodb--default-max-bson-object-size))

(defun mongodb--max-message-size-bytes (conn)
  "Return CONN's effective MongoDB max wire message size."
  (or (and (mongodb-conn-p conn)
           (mongodb-conn-max-message-size-bytes conn))
      mongodb--default-max-message-size-bytes))

;;;; Command helpers

(defun mongodb--os-type ()
  "Return the MongoDB handshake os.type value for this Emacs."
  (pcase system-type
    ('darwin "Darwin")
    ((or 'gnu 'gnu/linux) "Linux")
    ('windows-nt "Windows")
    ('berkeley-unix "BSD")
    ('cygwin "Cygwin")
    (_ "unknown")))

(defun mongodb--client-metadata (&optional app-name)
  "Return MongoDB handshake client metadata.
APP-NAME, when non-nil, is sent as client.application.name."
  `(,@(when (mongodb--validate-app-name app-name)
        `(("application" . (("name" . ,app-name)))))
    ("driver" . (("name" . "mongodb.el")
                 ("version" . ,mongodb-version)))
    ("os" . (("type" . ,(mongodb--os-type))))
    ("platform" . ,(format "Emacs %s" emacs-version))))

(defun mongodb--initial-handshake-command
    (&optional credential compressors server-api load-balanced
               speculative-auth app-name)
  "Return the initial MongoDB handshake command document.
When CREDENTIAL is non-nil, include SCRAM mechanism negotiation metadata.
When COMPRESSORS is non-nil, request MongoDB wire compression negotiation.
When SERVER-API or LOAD-BALANCED is non-nil, return modern hello for OP_MSG.
Otherwise return legacy hello for the first handshake message.
When SPECULATIVE-AUTH is non-nil, include the first SCRAM command in the
handshake.  APP-NAME is sent as client.application.name."
  `(,(if (or server-api load-balanced)
         '("hello" . 1)
       '("isMaster" . 1))
    ,@(unless (or server-api load-balanced)
        '(("helloOk" . t)))
    ("client" . ,(mongodb--client-metadata app-name))
    ,@(when load-balanced
        '(("loadBalanced" . t)))
    ,@(when compressors
        `(("compression" . ,(apply #'vector compressors))))
    ,@(when (mongodb--credential-scram-negotiation-p credential)
        `(("saslSupportedMechs" .
           ,(format "%s.%s"
                    (mongodb--credential-source credential)
                    (mongodb--credential-username credential)))))
    ,@(when speculative-auth
        `(("speculativeAuthenticate" .
           ,(mongodb--scram-start-command speculative-auth t))))))

(defun mongodb--truthy-handshake-value-p (value)
  "Return non-nil when handshake VALUE represents truth."
  (or (eq value t)
      (and (numberp value) (> value 0))
      (equal value "1")
      (equal value "true")))

(defun mongodb--post-handshake-hello-command (hello modern-initial-p)
  "Return the command name to use for subsequent hello probes.
HELLO is the initial handshake response.  MODERN-INITIAL-P is non-nil when
the initial handshake was already sent as OP_MSG hello."
  (if (or modern-initial-p
          (mongodb--truthy-handshake-value-p
           (cdr (assoc "helloOk" hello))))
      "hello"
    "isMaster"))

(defun mongodb--session-command-p (pairs)
  "Return non-nil when command PAIRS should carry a MongoDB lsid."
  (not (member (caar pairs)
               '("endSessions" "hello" "isMaster" "ismaster"))))

(defun mongodb--sdam-command-p (pairs)
  "Return non-nil when command PAIRS are SDAM hello commands."
  (member (caar pairs) '("hello" "isMaster" "ismaster")))

(defun mongodb--cluster-time-command-p (pairs)
  "Return non-nil when command PAIRS may carry MongoDB $clusterTime."
  (not (mongodb--sdam-command-p pairs)))

(defun mongodb--timestamp-components (value)
  "Return (SECONDS . INCREMENT) for MongoDB timestamp VALUE, or nil."
  (cond
   ((mongodb-timestamp-p value)
    (cons (mongodb-timestamp-seconds value)
          (mongodb-timestamp-increment value)))
   ((and (mongodb--document-value-p value)
         (assoc "$timestamp" (mongodb--document-pairs value)))
    (let* ((timestamp (cdr (assoc "$timestamp"
                                  (mongodb--document-pairs value))))
           (pairs (mongodb--document-pairs timestamp))
           (seconds (cdr (assoc "t" pairs)))
           (increment (cdr (assoc "i" pairs))))
      (and (integerp seconds)
           (integerp increment)
           (cons seconds increment))))))

(defun mongodb--cluster-time-components (cluster-time)
  "Return timestamp components for CLUSTER-TIME, or nil."
  (when cluster-time
    (mongodb--timestamp-components
     (cdr (assoc "clusterTime"
                 (mongodb--document-pairs cluster-time))))))

(defun mongodb--cluster-time-newer-p (left right)
  "Return non-nil when cluster time LEFT is newer than RIGHT."
  (let ((l (mongodb--cluster-time-components left))
        (r (mongodb--cluster-time-components right)))
    (and l
         (or (not r)
             (> (car l) (car r))
             (and (= (car l) (car r))
                  (> (cdr l) (cdr r)))))))

(defun mongodb--max-cluster-time (left right)
  "Return the newest MongoDB cluster time among LEFT and RIGHT."
  (if (mongodb--cluster-time-newer-p right left)
      right
    left))

(defun mongodb--extended-json-wrapper-p (pairs key)
  "Return non-nil when PAIRS represent a single Extended JSON KEY wrapper."
  (and (= (length pairs) 1)
       (assoc key pairs)))

(defun mongodb--extended-json-to-bson-value (value)
  "Return VALUE with Extended JSON wrappers restored to BSON wrappers.
This is used when a server-returned document, such as $clusterTime, must be
sent back to MongoDB without changing BSON types used in signatures."
  (cond
   ((vectorp value)
    (vconcat (mapcar #'mongodb--extended-json-to-bson-value
                     (append value nil))))
   ((and (consp value)
         (consp (car value)))
    (let ((pairs (mongodb--document-pairs value)))
      (cond
       ((mongodb--extended-json-wrapper-p pairs "$timestamp")
        (let* ((timestamp (cdr (assoc "$timestamp" pairs)))
               (timestamp-pairs (mongodb--document-pairs timestamp)))
          (mongodb-timestamp
           (cdr (assoc "t" timestamp-pairs))
           (cdr (assoc "i" timestamp-pairs)))))
       ((mongodb--extended-json-wrapper-p pairs "$binary")
        (let* ((binary (cdr (assoc "$binary" pairs)))
               (binary-pairs (mongodb--document-pairs binary))
               (subtype (cdr (assoc "subType" binary-pairs)))
               (bytes (cdr (assoc "bytes" binary-pairs))))
          (mongodb-binary
           (string-to-number (or subtype "0") 16)
           (mongodb--base64-decode bytes))))
       ((mongodb--extended-json-wrapper-p pairs "$oid")
        (mongodb-object-id (cdr (assoc "$oid" pairs))))
       ((mongodb--extended-json-wrapper-p pairs "$date")
        (mongodb-datetime (cdr (assoc "$date" pairs))))
       ((mongodb--extended-json-wrapper-p pairs "$numberDecimal")
        (mongodb-decimal128 (cdr (assoc "$numberDecimal" pairs))))
       ((mongodb--extended-json-wrapper-p pairs "$undefined")
        (mongodb-undefined))
       ((mongodb--extended-json-wrapper-p pairs "$dbPointer")
        (let* ((db-pointer (cdr (assoc "$dbPointer" pairs)))
               (db-pointer-pairs (mongodb--document-pairs db-pointer))
               (object-id (cdr (assoc "$id" db-pointer-pairs))))
          (mongodb-db-pointer
           (cdr (assoc "$ref" db-pointer-pairs))
           (if (and (mongodb--document-value-p object-id)
                    (assoc "$oid" (mongodb--document-pairs object-id)))
               (cdr (assoc "$oid" (mongodb--document-pairs object-id)))
             object-id))))
       ((and (assoc "$code" pairs)
             (seq-every-p (lambda (pair)
                            (member (car pair) '("$code" "$scope")))
                          pairs))
        (mongodb-code
         (cdr (assoc "$code" pairs))
         (when-let* ((scope (assoc "$scope" pairs)))
           (mongodb--extended-json-to-bson-value (cdr scope)))))
       ((mongodb--extended-json-wrapper-p pairs "$symbol")
        (mongodb-symbol (cdr (assoc "$symbol" pairs))))
       ((mongodb--extended-json-wrapper-p pairs "$regularExpression")
        (let* ((regex (cdr (assoc "$regularExpression" pairs)))
               (regex-pairs (mongodb--document-pairs regex)))
          (mongodb-regex
           (cdr (assoc "pattern" regex-pairs))
           (cdr (assoc "options" regex-pairs)))))
       ((mongodb--extended-json-wrapper-p pairs "$minKey")
        (mongodb-min-key))
       ((mongodb--extended-json-wrapper-p pairs "$maxKey")
        (mongodb-max-key))
       (t
        (mongodb-document
         (mapcar (lambda (pair)
                   (cons (car pair)
                         (mongodb--extended-json-to-bson-value (cdr pair))))
                 pairs))))))
   ((listp value)
    (mapcar #'mongodb--extended-json-to-bson-value value))
   (t value)))

(defun mongodb-extended-json-to-bson-value (value)
  "Return VALUE with Extended JSON wrappers restored to BSON wrappers.
This is useful for callers that need to feed server-returned Extended JSON
values back into MongoDB command documents without losing BSON wire types."
  (mongodb--extended-json-to-bson-value value))

(defun mongodb--cluster-time-for-command (cluster-time)
  "Return CLUSTER-TIME normalized for BSON command encoding."
  (and cluster-time
       (mongodb--extended-json-to-bson-value cluster-time)))

(defun mongodb--cluster-time-to-send (conn)
  "Return the highest MongoDB cluster time CONN should gossip, or nil."
  (when (>= (or (mongodb-conn-max-wire-version conn) 0) 6)
    (mongodb--max-cluster-time
     (mongodb-conn-cluster-time conn)
     (mongodb-conn-session-cluster-time conn))))

(defun mongodb-advance-cluster-time (conn cluster-time)
  "Advance CONN's session cluster time to CLUSTER-TIME if it is newer.
This mirrors MongoDB driver's `advanceClusterTime' behavior for explicit
session state without advancing the deployment-level cluster time."
  (when (mongodb--cluster-time-newer-p
         cluster-time
         (mongodb-conn-session-cluster-time conn))
    (setf (mongodb-conn-session-cluster-time conn) cluster-time))
  conn)

(defun mongodb--advance-cluster-time-from-response (conn command response)
  "Advance CONN cluster time using RESPONSE to COMMAND."
  (let ((pairs (mongodb--document-pairs command)))
    (unless (mongodb--sdam-command-p pairs)
      (when-let* ((cluster-time (cdr (assoc "$clusterTime" response))))
        (when (mongodb--cluster-time-newer-p
               cluster-time
               (mongodb-conn-cluster-time conn))
          (setf (mongodb-conn-cluster-time conn) cluster-time))
        (mongodb-advance-cluster-time conn cluster-time)))))

(defun mongodb--advance-transaction-recovery-token-from-response
    (conn transaction-state response)
  "Cache latest transaction recoveryToken from RESPONSE on CONN.

Arguments: CONN, TRANSACTION-STATE, RESPONSE."
  (when (and transaction-state
             (mongodb--ok-p response))
    (when-let* ((token (cdr (assoc "recoveryToken" response))))
      (setf (mongodb-conn-transaction-recovery-token conn) token)))
  conn)

(defun mongodb--read-preference-command-p (pairs)
  "Return non-nil when command PAIRS may carry $readPreference."
  (member (format "%s" (caar pairs))
          mongodb--read-command-names))

(defun mongodb--command-with-db
    (command database &optional server-api session-id read-preference
             read-concern write-concern txn-number transaction-state
             transaction-read-concern cluster-time)
  "Return COMMAND with MongoDB driver-level metadata added.

Arguments: COMMAND, DATABASE, SERVER-API, SESSION-ID, READ-PREFERENCE,
READ-CONCERN, WRITE-CONCERN, TXN-NUMBER, TRANSACTION-STATE,
TRANSACTION-READ-CONCERN, CLUSTER-TIME."
  (let ((pairs (copy-sequence
                (mongodb--document-pairs command))))
    (unless (assoc "$db" pairs)
      (setq pairs (append pairs (list (cons "$db" database)))))
    (dolist (field (mongodb--server-api-fields server-api))
      (unless (assoc (car field) pairs)
        (setq pairs (append pairs (list field)))))
    (when (and cluster-time
               (mongodb--cluster-time-command-p pairs)
               (not (assoc "$clusterTime" pairs)))
      (setq pairs
            (append pairs
                    (list (cons "$clusterTime"
                                (mongodb--cluster-time-for-command
                                 cluster-time))))))
    (when (and session-id
               (mongodb--session-command-p pairs)
               (not (assoc "lsid" pairs)))
      (setq pairs (append pairs (list (cons "lsid" session-id)))))
    (when (and txn-number
               session-id
               (not (assoc "txnNumber" pairs)))
      (setq pairs
            (append pairs (list (cons "txnNumber" txn-number)))))
    (when (and transaction-state
               (not (assoc "autocommit" pairs)))
      (setq pairs (append pairs (list (cons "autocommit" :false)))))
    (when (and (eq transaction-state 'starting)
               (not (assoc "startTransaction" pairs)))
      (setq pairs (append pairs (list (cons "startTransaction" t)))))
    (when-let* ((value (and (eq transaction-state 'starting)
                            (not (assoc "readConcern" pairs))
                            (mongodb--read-concern-command-document
                             transaction-read-concern))))
      (setq pairs
            (append pairs (list (cons "readConcern" value)))))
    (when-let* ((value (and (not transaction-state)
                            (mongodb--read-preference-command-p pairs)
                            (not (assoc "$readPreference" pairs))
                            (mongodb--read-preference-document
                             read-preference))))
      (setq pairs
            (append pairs (list (cons "$readPreference" value)))))
    (when-let* ((value (and (not transaction-state)
                            (mongodb--read-command-p pairs)
                            (not (assoc "readConcern" pairs))
                            (mongodb--read-concern-document
                             read-concern))))
      (setq pairs
            (append pairs (list (cons "readConcern" value)))))
    (when-let* ((value (and (not transaction-state)
                            (mongodb--write-command-p pairs)
                            (not (assoc "writeConcern" pairs))
                            (mongodb--write-concern-document
                             write-concern))))
      (setq pairs
            (append pairs (list (cons "writeConcern" value)))))
    pairs))

(defun mongodb--ok-p (response)
  "Return non-nil when RESPONSE is an ok MongoDB command response."
  (let ((ok (cdr (assoc "ok" response))))
    (or (eq ok t)
        (and (numberp ok)
             (> ok 0))
        (equal ok "1"))))

(defun mongodb-response-ok-p (response)
  "Return non-nil when RESPONSE is an ok MongoDB command response."
  (mongodb--ok-p response))

(defun mongodb--response-message (response)
  "Return an error message from MongoDB command RESPONSE."
  (or (cdr (assoc "errmsg" response))
      (cdr (assoc "$err" response))
      (format "MongoDB command failed: %S" response)))

(defun mongodb--label-list (labels)
  "Return LABELS as a list of strings."
  (cond
   ((null labels) nil)
   ((vectorp labels) (append labels nil))
   ((and (listp labels)
         (not (stringp labels)))
    labels)
   ((stringp labels) (list labels))
   (t nil)))

(defun mongodb--add-error-labels (&rest label-groups)
  "Return de-duplicated error labels from LABEL-GROUPS."
  (let (labels)
    (dolist (group label-groups)
      (dolist (label (mongodb--label-list group))
        (unless (member label labels)
          (push label labels))))
    (nreverse labels)))

(defun mongodb--response-error-labels (response)
  "Return top-level MongoDB errorLabels from RESPONSE."
  (mongodb--label-list (cdr (assoc "errorLabels" response))))

(defun mongodb-error-labels (condition)
  "Return MongoDB error labels stored on CONDITION.
CONDITION may be an error object captured by `condition-case' or a raw signal
data list."
  (let ((data (if (and (consp condition)
                       (symbolp (car condition)))
                  (cdr condition)
                condition)))
    (mongodb--label-list (plist-get (cdr data) :error-labels))))

(defun mongodb-error-has-label-p (condition label)
  "Return non-nil when CONDITION has MongoDB error LABEL."
  (member label (mongodb-error-labels condition)))

(defun mongodb--transaction-unpin-for-labels (conn labels)
  "Unpin CONN's transaction when LABELS require it."
  (when (and (mongodb-conn-p conn)
             (mongodb--label-list labels)
             (or (member mongodb--transient-transaction-error-label
                         (mongodb--label-list labels))
                 (member mongodb--unknown-transaction-commit-result-label
                         (mongodb--label-list labels))))
    (mongodb--unpin-transaction conn))
  conn)

(defun mongodb--condition-message (condition)
  "Return the primary error message from CONDITION."
  (if (and (consp condition)
           (eq (car condition) 'mongodb-error)
           (stringp (cadr condition)))
      (cadr condition)
    (error-message-string condition)))

(defun mongodb--signal-error-with-labels (message labels)
  "Signal `mongodb-error' with MESSAGE and MongoDB error LABELS."
  (let ((labels (mongodb--add-error-labels labels)))
    (if labels
        (signal 'mongodb-error (list message :error-labels labels))
      (signal 'mongodb-error (list message)))))

(defun mongodb--signal-transaction-error-with-labels (conn message labels)
  "Signal MongoDB transaction error MESSAGE after applying LABELS side effects.

Arguments: CONN, MESSAGE, LABELS."
  (mongodb--transaction-unpin-for-labels conn labels)
  (mongodb--signal-error-with-labels message labels))

(defun mongodb--write-error-message (response)
  "Return a write error message from MongoDB command RESPONSE, or nil."
  (let ((write-errors (cdr (assoc "writeErrors" response)))
        (write-concern-error (cdr (assoc "writeConcernError" response))))
    (cond
     ((and write-errors
           (> (length write-errors) 0))
      (let* ((error (if (vectorp write-errors)
                        (aref write-errors 0)
                      (car write-errors)))
             (code-name (cdr (assoc "codeName" error)))
             (code (cdr (assoc "code" error)))
             (index (cdr (assoc "index" error)))
             (message (or (cdr (assoc "errmsg" error))
                          (format "%S" error))))
        (format "MongoDB write error%s%s: %s"
                (if index (format " at index %s" index) "")
                (cond
                 (code-name (format " (%s)" code-name))
                 (code (format " (%s)" code))
                 (t ""))
                message)))
     (write-concern-error
      (let ((code-name (cdr (assoc "codeName" write-concern-error)))
            (code (cdr (assoc "code" write-concern-error)))
            (message (or (cdr (assoc "errmsg" write-concern-error))
                         (format "%S" write-concern-error))))
        (format "MongoDB write concern error%s: %s"
                (cond
                 (code-name (format " (%s)" code-name))
                 (code (format " (%s)" code))
                 (t ""))
                message))))))

(defun mongodb--command-name (command)
  "Return the command name from MongoDB COMMAND."
  (let ((pairs (mongodb--document-pairs command)))
    (when pairs
      (format "%s" (caar pairs)))))

(defun mongodb--sensitive-command-p (command)
  "Return non-nil when COMMAND must be redacted in monitoring events."
  (let ((name (mongodb--command-name command))
        (pairs (mongodb--document-pairs command)))
    (or (member name mongodb--sensitive-command-names)
        (and (member name '("hello" "isMaster" "ismaster"))
             (assoc "speculativeAuthenticate" pairs)))))

(defun mongodb--command-event-document (document sequences)
  "Return DOCUMENT as it should appear in command-started events.
OP_MSG SEQUENCES are exposed as BSON array fields on the command event
document, matching MongoDB command monitoring semantics."
  (let ((pairs (copy-sequence (mongodb--document-pairs document))))
    (dolist (sequence sequences)
      (setq pairs
            (append
             (cl-remove (car sequence) pairs :key #'car :test #'equal)
             (list sequence))))
    pairs))

(defun mongodb--redact-command-event-document (document sensitive)
  "Return command monitoring DOCUMENT, redacted when SENSITIVE is non-nil."
  (if sensitive nil document))

(defun mongodb--redact-command-event-failure (failure sensitive)
  "Return command monitoring FAILURE, redacted when SENSITIVE is non-nil."
  (if (not sensitive)
      failure
    (when (mongodb--document-value-p failure)
      (let ((pairs (mongodb--document-pairs failure))
            redacted)
        (dolist (key '("code" "codeName" "errorLabels"))
          (when-let* ((entry (assoc key pairs)))
            (push entry redacted)))
        (nreverse redacted)))))

(defun mongodb--command-event-server-connection-id (conn)
  "Return CONN's server-generated connectionId, or nil."
  (cdr (assoc "connectionId" (mongodb-conn-last-hello conn))))

(defun mongodb--next-command-operation-id ()
  "Return the next command monitoring operation id."
  (setq mongodb--next-command-operation-id
        (1+ mongodb--next-command-operation-id)))

(defun mongodb--command-event-common-fields
    (conn database command-name request-id)
  "Return common command monitoring fields for CONN.

Arguments: CONN, DATABASE, COMMAND-NAME, REQUEST-ID."
  (let ((fields `((connection . ,conn)
                  (connection-id . ,(mongodb--conn-address conn))
                  (database-name . ,database)
                  (command-name . ,command-name)
                  (request-id . ,request-id))))
    (when-let* ((operation-id
                 (plist-get mongodb--command-event-context :operation-id)))
      (setq fields (append fields (list (cons 'operation-id operation-id)))))
    (when-let* ((server-id (mongodb--command-event-server-connection-id conn)))
      (setq fields (append fields
                           (list (cons 'server-connection-id server-id)))))
    (when-let* ((driver-id (mongodb-conn-pool-connection-id conn)))
      (setq fields (append fields
                           (list (cons 'driver-connection-id driver-id)))))
    (when-let* ((service-id (and (mongodb-conn-load-balanced conn)
                                 (mongodb-conn-service-id conn))))
      (setq fields (append fields (list (cons 'service-id service-id)))))
    fields))

(defun mongodb--emit-command-event (type &rest fields)
  "Emit MongoDB command monitoring event TYPE with FIELDS."
  (unless mongodb--suppress-command-events
    (let ((event `((type . ,type)
                   ,@fields)))
      (run-hook-with-args 'mongodb-command-event-hook event)
      event)))

(defun mongodb--command-event-started (conn request-id)
  "Emit a command-started event for CONN and REQUEST-ID."
  (unless (or mongodb--suppress-command-events
              (not mongodb-command-event-hook)
              (not mongodb--command-event-context)
              (plist-get mongodb--command-event-context :started))
    (let* ((database
            (plist-get mongodb--command-event-context :database-name))
           (command-name
            (plist-get mongodb--command-event-context :command-name))
           (command
            (plist-get mongodb--command-event-context :command))
           (sensitive
            (plist-get mongodb--command-event-context :sensitive))
           (started-at (float-time)))
      (setq mongodb--command-event-context
            (plist-put mongodb--command-event-context :request-id request-id))
      (setq mongodb--command-event-context
            (plist-put mongodb--command-event-context :started-at started-at))
      (setq mongodb--command-event-context
            (plist-put mongodb--command-event-context :started t))
      (apply #'mongodb--emit-command-event
             'command-started
             (append
              (mongodb--command-event-common-fields
               conn database command-name request-id)
              (list
               (cons 'command
                     (mongodb--redact-command-event-document
                      command sensitive))))))))

(defun mongodb--command-event-duration-ms ()
  "Return the current command monitoring context duration in milliseconds."
  (mongodb--pool-duration-ms
   (or (plist-get mongodb--command-event-context :started-at)
       (float-time))))

(defun mongodb--command-event-finished-p ()
  "Return non-nil when current command monitoring context already finished."
  (plist-get mongodb--command-event-context :finished))

(defun mongodb--command-event-failed (conn failure)
  "Emit command-failed for CONN with FAILURE unless already emitted."
  (unless (or mongodb--suppress-command-events
              (not mongodb-command-event-hook)
              (not mongodb--command-event-context)
              (mongodb--command-event-finished-p))
    (let ((request-id (plist-get mongodb--command-event-context :request-id)))
      (when request-id
        (let* ((database
                (plist-get mongodb--command-event-context :database-name))
               (command-name
                (plist-get mongodb--command-event-context :command-name))
               (sensitive
                (plist-get mongodb--command-event-context :sensitive)))
          (setq mongodb--command-event-context
                (plist-put mongodb--command-event-context :finished t))
          (apply #'mongodb--emit-command-event
                 'command-failed
                 (append
                  (mongodb--command-event-common-fields
                   conn database command-name request-id)
                  (list
                   (cons 'duration-ms
                         (mongodb--command-event-duration-ms))
                   (cons 'failure
                         (mongodb--redact-command-event-failure
                          failure sensitive))))))))))

(defun mongodb--command-event-succeeded (conn reply)
  "Emit command-succeeded for CONN with REPLY unless already emitted."
  (unless (or mongodb--suppress-command-events
              (not mongodb-command-event-hook)
              (not mongodb--command-event-context)
              (mongodb--command-event-finished-p))
    (let ((request-id (plist-get mongodb--command-event-context :request-id)))
      (when request-id
        (let* ((database
                (plist-get mongodb--command-event-context :database-name))
               (command-name
                (plist-get mongodb--command-event-context :command-name))
               (sensitive
                (plist-get mongodb--command-event-context :sensitive)))
          (setq mongodb--command-event-context
                (plist-put mongodb--command-event-context :finished t))
          (apply #'mongodb--emit-command-event
                 'command-succeeded
                 (append
                  (mongodb--command-event-common-fields
                   conn database command-name request-id)
                  (list
                   (cons 'duration-ms
                         (mongodb--command-event-duration-ms))
                   (cons 'reply
                          (mongodb--redact-command-event-document
                           reply sensitive))))))))))

(defun mongodb--emit-sdam-event (type &rest fields)
  "Emit MongoDB SDAM monitoring event TYPE with FIELDS."
  (when mongodb-sdam-event-hook
    (let ((event `((type . ,type)
                   ,@fields)))
      (run-hook-with-args 'mongodb-sdam-event-hook event)
      event)))

(defun mongodb--sdam-heartbeat-event-fields (conn awaited)
  "Return common SDAM heartbeat event fields for CONN.

Arguments: CONN, AWAITED."
  (let* ((address (mongodb--conn-address conn))
         (fields `((connection . ,conn)
                   (connection-id . ,address)
                   (address . ,address)
                   (awaited . ,awaited))))
    (when-let* ((server-id
                 (cdr (assoc "connectionId" (mongodb-conn-last-hello conn)))))
      (setq fields (append fields
                           (list (cons 'server-connection-id server-id)))))
    fields))

(defun mongodb--conn-topology-id (conn)
  "Return CONN's stable SDAM topology id."
  (or (mongodb-conn-topology-id conn)
      (setf (mongodb-conn-topology-id conn)
            (setq mongodb--next-topology-id
                  (1+ mongodb--next-topology-id)))))

(defun mongodb--sdam-description-event-fields (conn)
  "Return common SDAM description event fields for CONN."
  `((connection . ,conn)
    (topology-id . ,(mongodb--conn-topology-id conn))))

(defun mongodb--emit-sdam-lifecycle-event (conn type &optional address)
  "Emit SDAM lifecycle event TYPE for CONN."
  (apply #'mongodb--emit-sdam-event
         type
         (append
          (mongodb--sdam-description-event-fields conn)
          (when address
            (list (cons 'address address))))))

(defun mongodb--sdam-server-description-event-value (server)
  "Return SERVER normalized for SDAM description-changed comparison."
  (when (mongodb-server-description-p server)
    (let ((copy (copy-mongodb-server-description server)))
      (setf (mongodb-server-description-last-update-time copy) nil)
      (setf (mongodb-server-description-round-trip-time copy) nil)
      copy)))

(defun mongodb--sdam-topology-description-event-value (topology)
  "Return TOPOLOGY normalized for SDAM description-changed comparison."
  (when (mongodb-topology-description-p topology)
    (let ((copy (copy-mongodb-topology-description topology)))
      (setf (mongodb-topology-description-servers copy)
            (mapcar
             (lambda (entry)
               (cons (car entry)
                     (mongodb--sdam-server-description-event-value
                      (cdr entry))))
             (mongodb-topology-description-servers topology)))
      copy)))

(defun mongodb--sdam-description-event-equal-p (old new)
  "Return non-nil when OLD and NEW are equal for SDAM changed events."
  (cond
   ((or (mongodb-server-description-p old)
        (mongodb-server-description-p new))
    (equal (mongodb--sdam-server-description-event-value old)
           (mongodb--sdam-server-description-event-value new)))
   ((or (mongodb-topology-description-p old)
        (mongodb-topology-description-p new))
    (equal (mongodb--sdam-topology-description-event-value old)
           (mongodb--sdam-topology-description-event-value new)))
   (t
    (equal old new))))

(defun mongodb--topology-server-description (topology address)
  "Return TOPOLOGY's server description for ADDRESS."
  (when (mongodb-topology-description-p topology)
    (cdr (assoc address (mongodb-topology-description-servers topology)))))

(defun mongodb--unknown-topology-description (conn)
  "Return an Unknown SDAM topology description for CONN's current address."
  (let* ((address (mongodb--conn-address conn))
         (server (mongodb--unknown-server-description address)))
    (make-mongodb-topology-description
     :type 'unknown
     :servers `((,address . ,server))
     :compatible t)))

(defun mongodb--emit-sdam-description-changes (conn old-topology new-topology)
  "Emit SDAM description-changed events for CONN topology changes.

Arguments: CONN, OLD-TOPOLOGY, NEW-TOPOLOGY."
  (when (and mongodb-sdam-event-hook old-topology new-topology)
    (let* ((address (mongodb--conn-address conn))
           (old-server (mongodb--topology-server-description
                        old-topology address))
           (new-server (mongodb--topology-server-description
                        new-topology address)))
      (unless (mongodb--sdam-description-event-equal-p old-server new-server)
        (apply #'mongodb--emit-sdam-event
               'server-description-changed
               (append
                (mongodb--sdam-description-event-fields conn)
                (list (cons 'address address)
                      (cons 'previous-description old-server)
                      (cons 'new-description new-server)))))
      (unless (mongodb--sdam-description-event-equal-p
               old-topology new-topology)
        (apply #'mongodb--emit-sdam-event
               'topology-description-changed
               (append
                (mongodb--sdam-description-event-fields conn)
                (list (cons 'previous-description old-topology)
                      (cons 'new-description new-topology))))))))

(defun mongodb--set-conn-topology (conn topology)
  "Set CONN's TOPOLOGY and emit SDAM description change events."
  (let ((old-topology (mongodb-conn-topology conn)))
    (setf (mongodb-conn-topology conn) topology)
    (when old-topology
      (mongodb--emit-sdam-description-changes conn old-topology topology)))
  topology)

(defun mongodb--emit-sdam-opening-events (conn topology)
  "Emit initial SDAM opening events for CONN and TOPOLOGY."
  (when mongodb-sdam-event-hook
    (let ((address (mongodb--conn-address conn))
          (previous (mongodb--unknown-topology-description conn)))
      (mongodb--emit-sdam-lifecycle-event conn 'topology-opening)
      (mongodb--emit-sdam-lifecycle-event conn 'server-opening address)
      (mongodb--emit-sdam-description-changes conn previous topology))))

(defun mongodb--emit-sdam-closing-events (conn)
  "Emit terminal SDAM closing events for CONN."
  (when (and mongodb-sdam-event-hook
             (mongodb-conn-topology conn)
             (not (mongodb-conn-closed conn)))
    (let ((address (mongodb--conn-address conn)))
      (mongodb--set-conn-topology conn (mongodb--unknown-topology-description conn))
      (mongodb--emit-sdam-lifecycle-event conn 'server-closed address)
      (mongodb--emit-sdam-lifecycle-event conn 'topology-closed))))

(defun mongodb--monitor-awaitable-p (conn)
  "Return non-nil when CONN's next monitor heartbeat is awaitable."
  (and (not (eq (mongodb-conn-server-monitoring-mode conn) 'poll))
       (when-let* ((server (mongodb--current-server-description conn)))
         (mongodb-server-description-topology-version server))))

(defun mongodb--make-command-event-context (database document sequences)
  "Return command monitoring context for DATABASE, DOCUMENT, and SEQUENCES."
  (let* ((command (mongodb--command-event-document document sequences))
         (command-name (mongodb--command-name command))
         (sensitive (mongodb--sensitive-command-p command)))
    (list :database-name database
          :command-name command-name
          :command command
          :operation-id mongodb--command-operation-id
          :sensitive sensitive)))

(defun mongodb--write-command-p (command)
  "Return non-nil when COMMAND requires a writable server."
  (member (mongodb--command-name command)
          mongodb--write-command-names))

(defun mongodb--read-command-p (command)
  "Return non-nil when COMMAND is a read command."
  (member (mongodb--command-name command)
          mongodb--read-command-names))

(defun mongodb--aggregate-write-stage-p (command)
  "Return non-nil when aggregate COMMAND contains a write stage."
  (when (equal (mongodb--command-name command) "aggregate")
    (when-let* ((pipeline (cdr (assoc "pipeline"
                                      (mongodb--document-pairs command)))))
      (seq-some (lambda (stage)
                  (let ((pairs (mongodb--document-pairs stage)))
                    (or (assoc "$out" pairs)
                        (assoc "$merge" pairs))))
                (append pipeline nil)))))

(defun mongodb--retryable-read-command-p (command)
  "Return non-nil when COMMAND is eligible for retryable reads."
  (and (member (mongodb--command-name command)
               mongodb--retryable-read-command-names)
       (not (mongodb--aggregate-write-stage-p command))))

(defun mongodb--retryable-reads-supported-p (conn)
  "Return non-nil when CONN's server supports retryable reads."
  (>= (or (mongodb-conn-max-wire-version conn) 0) 6))

(defun mongodb--retryable-server-error-p (response)
  "Return non-nil when RESPONSE reports a retryable read server error."
  (let ((code (cdr (assoc "code" response)))
        (labels (cdr (assoc "errorLabels" response))))
    (or (member code mongodb--retryable-read-error-codes)
        (and labels
             (seq-some (lambda (label)
                         (member label '("RetryableReadError"
                                         "RetryableWriteError"
                                         "ResumableChangeStreamError")))
                       (append labels nil))))))

(defun mongodb--network-error-p (err)
  "Return non-nil when ERR looks like a MongoDB network read error."
  (let ((message (error-message-string err)))
    (and (eq (car err) 'mongodb-error)
         (string-match-p
          "\\(connection closed\\|Timed out waiting for MongoDB response\\)"
          message))))

(defun mongodb--network-timeout-error-p (err)
  "Return non-nil when ERR is a MongoDB command response timeout."
  (and (eq (car err) 'mongodb-error)
       (string-match-p
        "Timed out waiting for MongoDB response"
        (error-message-string err))))

(defun mongodb--pool-command-clear-error-p (err)
  "Return non-nil when ERR should clear a checked-out command's pool."
  (and (mongodb--network-error-p err)
       (not (mongodb--network-timeout-error-p err))
       (not (mongodb-error-has-label-p
             err mongodb--system-overloaded-error-label))))

(defun mongodb--connect-non-overload-error-message-p (message)
  "Return non-nil when MESSAGE is known not to indicate server overload."
  (let ((message (downcase message)))
    (or (string-match-p
         (regexp-opt
          '("socks5" "unix-domain sockets" "requires gnutls support"
            "authentication" "certificate" "hostname" "verification"
            "x509" "does not support this mode"))
         message)
        (string-match-p
         "\\(name or service\\|nodename nor servname\\|unknown host\\|host lookup\\|could not resolve\\|no address associated\\|dns\\|resolver\\)"
         message))))

(defun mongodb--connect-network-overload-error-p (phase err)
  "Return non-nil when PHASE and ERR should receive backpressure labels."
  (let ((message (error-message-string err)))
    (and (memq phase '(socket tls hello))
         (not (mongodb--connect-non-overload-error-message-p message))
         (or (mongodb--network-error-p err)
             (string-match-p
              "\\(timed out\\|connection \\(?:refused\\|reset\\|closed\\)\\|end of file\\|broken pipe\\|network is unreachable\\|host unreachable\\)"
              (downcase message))
             (and (eq phase 'tls)
                  (string-match-p
                   "\\(gnutls\\|tls negotiation failed\\)"
                   (downcase message)))))))

(defun mongodb--resignal-connect-error (phase err)
  "Resignal connection ERR from PHASE, adding CMAP backpressure labels."
  (if (mongodb--connect-network-overload-error-p phase err)
      (mongodb--signal-error-with-labels
       (mongodb--condition-message err)
       (mongodb--add-error-labels
        (mongodb-error-labels err)
        mongodb--system-overloaded-error-label
        mongodb--retryable-error-label))
    (signal (car err) (cdr err))))

(defun mongodb--server-selection-error-p (err)
  "Return non-nil when ERR looks like a MongoDB server-selection error."
  (let ((message (error-message-string err)))
    (and (eq (car err) 'mongodb-error)
         (string-match-p
          "\\(No writable MongoDB server\\|No readable MongoDB server\\|serverSelectionTimeoutMS\\|server selection\\|did not find a server matching\\)"
          message))))

(defun mongodb--transaction-transient-condition-p (conn command err)
  "Return non-nil when ERR should have TransientTransactionError.

Arguments: CONN, COMMAND, ERR."
  (and (mongodb-in-transaction-p conn)
       (not (equal (mongodb--command-name command) "commitTransaction"))
       (or (mongodb--network-error-p err)
           (mongodb--server-selection-error-p err))))

(defun mongodb--signal-transaction-transient-error (err &optional conn)
  "Signal ERR with TransientTransactionError added.

Arguments: ERR, CONN."
  (when conn
    (mongodb--unpin-transaction conn))
  (mongodb--signal-error-with-labels
   (mongodb--condition-message err)
   (mongodb--add-error-labels
    (mongodb-error-labels err)
    mongodb--transient-transaction-error-label)))

(defun mongodb--retryable-read-enabled-p (conn command)
  "Return non-nil when CONN should retry read COMMAND once."
  (and (mongodb-conn-retry-reads conn)
       (not (mongodb-in-transaction-p conn))
       (mongodb--retryable-reads-supported-p conn)
       (mongodb--retryable-read-command-p command)))

(defun mongodb--sequence-values (sequences identifier)
  "Return OP_MSG sequence values named IDENTIFIER from SEQUENCES."
  (when-let* ((value (cdr (assoc identifier sequences))))
    (cond
     ((vectorp value) (append value nil))
     ((listp value) value)
     (t nil))))

(defun mongodb--sequence-document-list (sequence)
  "Return the document list from OP_MSG SEQUENCE after basic validation."
  (let ((identifier (car sequence))
        (documents (cdr sequence)))
    (unless (stringp identifier)
      (signal 'mongodb-error
              (list (format "MongoDB OP_MSG sequence identifier must be a string: %S"
                            identifier))))
    (cond
     ((vectorp documents) (append documents nil))
     ((listp documents) documents)
     (t
      (signal 'mongodb-error
              (list (format "MongoDB OP_MSG sequence documents must be a list or vector: %S"
                            documents)))))))

(defun mongodb--validate-op-msg-size (conn document sequences)
  "Signal if OP_MSG DOCUMENT and SEQUENCES exceed CONN wire limits."
  (let* ((max-bson (mongodb--max-bson-object-size conn))
         (max-message (mongodb--max-message-size-bytes conn))
         (body-bytes (mongodb--encode-document document))
         (message-size (+ 16 4 1 (length body-bytes))))
    (when (> (length body-bytes) max-bson)
      (signal 'mongodb-error
              (list
               (format "MongoDB command document is %s bytes, exceeding maxBsonObjectSize %s"
                       (length body-bytes) max-bson))))
    (dolist (sequence sequences)
      (let* ((identifier (car sequence))
             (section-size
              (mongodb--document-sequence-overhead-bytes identifier)))
        (dolist (sequence-document
                 (mongodb--sequence-document-list sequence))
          (let ((sequence-document-size
                 (length (mongodb--encode-document sequence-document))))
            (when (> sequence-document-size max-bson)
              (signal 'mongodb-error
                      (list
                       (format "MongoDB OP_MSG sequence document is %s bytes, exceeding maxBsonObjectSize %s"
                               sequence-document-size max-bson))))
            (setq section-size (+ section-size sequence-document-size))))
        (setq message-size (+ message-size section-size))))
    (when (> message-size max-message)
      (signal 'mongodb-error
              (list
               (format "MongoDB OP_MSG message is %s bytes, exceeding maxMessageSizeBytes %s"
                       message-size max-message))))
    message-size))

(defun mongodb--document-field (document field)
  "Return DOCUMENT FIELD value, or nil."
  (cdr (assoc field (mongodb--document-pairs document))))

(defun mongodb--document-has-field-p (document field)
  "Return non-nil when DOCUMENT has FIELD."
  (assoc field (mongodb--document-pairs document)))

(defun mongodb--insert-documents-retryable-p (sequences)
  "Return non-nil when insert SEQUENCES are safe for retryable writes."
  (let ((docs (mongodb--sequence-values sequences "documents")))
    (and docs
         (seq-every-p
          (lambda (doc)
            (mongodb--document-has-field-p doc "_id"))
          docs))))

(defun mongodb--update-statements-retryable-p (sequences)
  "Return non-nil when update SEQUENCES are safe for retryable writes."
  (let ((updates (mongodb--sequence-values sequences "updates")))
    (and updates
         (seq-every-p
          (lambda (update)
            (not (mongodb--wire-truthy-p
                  (mongodb--document-field update "multi"))))
          updates))))

(defun mongodb--delete-statements-retryable-p (sequences)
  "Return non-nil when delete SEQUENCES are safe for retryable writes."
  (let ((deletes (mongodb--sequence-values sequences "deletes")))
    (and deletes
         (seq-every-p
          (lambda (delete)
            (= (or (mongodb--document-field delete "limit") 0) 1))
          deletes))))

(defun mongodb--document-with-generated-id (document)
  "Return DOCUMENT with a generated `_id' when it lacks one.
Documents that already contain `_id' are returned unchanged."
  (if (mongodb--document-has-field-p document "_id")
      document
    (mongodb-document
     (cons (cons "_id" (mongodb-new-object-id))
           (mongodb--document-pairs document)))))

(defun mongodb--insert-documents-with-generated-ids (documents)
  "Return DOCUMENTS vector with `_id' generated for any missing document ids."
  (let* ((docs (cond
                ((vectorp documents) (append documents nil))
                ((and (listp documents)
                      (not (mongodb--document-value-p documents)))
                 documents)
                (t (list documents))))
         (materialized
          (mapcar #'mongodb--document-with-generated-id docs)))
    (vconcat materialized)))

(defun mongodb--chunk-vector (values chunk-size)
  "Return VALUES vector split into vectors of at most CHUNK-SIZE."
  (unless (and (integerp chunk-size)
               (> chunk-size 0))
    (signal 'mongodb-error
            (list (format "MongoDB write batch size must be positive, got %S"
                          chunk-size))))
  (let ((length (length values))
        (start 0)
        chunks)
    (while (< start length)
      (let ((end (min length (+ start chunk-size))))
        (push (cl-subseq values start end) chunks)
        (setq start end)))
    (nreverse chunks)))

(defun mongodb--command-for-size-estimate (conn database command)
  "Return COMMAND with the metadata known before send for size estimates.

Arguments: CONN, DATABASE, COMMAND."
  (if (mongodb-conn-p conn)
      (let* ((transaction-state (mongodb--transaction-command-state conn command))
             (transaction-number
              (mongodb--transaction-command-number conn transaction-state)))
        (mongodb--command-with-db
         command
         (or database (mongodb-conn-database conn))
         (mongodb-conn-server-api conn)
         (mongodb-conn-session-id conn)
         (mongodb--effective-command-read-preference conn command)
         (mongodb-conn-read-concern conn)
         (mongodb-conn-write-concern conn)
         transaction-number
         transaction-state
         (mongodb-conn-transaction-read-concern conn)
         (mongodb--cluster-time-to-send conn)))
    (mongodb--command-with-db command database)))

(defun mongodb--document-sequence-overhead-bytes (identifier)
  "Return OP_MSG kind 1 sequence overhead bytes for IDENTIFIER."
  (+ 1 4 (length (mongodb--encode-cstring identifier))))

(defun mongodb--insert-batch-byte-budget (conn database command)
  "Return safe document-sequence byte budget for insert COMMAND.

Arguments: CONN, DATABASE, COMMAND."
  (let* ((command-document
          (mongodb--command-for-size-estimate conn database command))
         (base-message
          (mongodb--make-op-msg 1 command-document nil nil nil))
         (budget (- (mongodb--max-message-size-bytes conn)
                    (length base-message)
                    (mongodb--document-sequence-overhead-bytes "documents")
                    mongodb--write-batch-message-safety-bytes)))
    (unless (> budget 0)
      (signal 'mongodb-error
              (list
               (format "MongoDB maxMessageSizeBytes is too small for insert command metadata: %s"
                       (mongodb--max-message-size-bytes conn)))))
    budget))

(defun mongodb--insert-document-batches (conn database command docs)
  "Return DOCS split for insert using count and wire-size limits.

Arguments: CONN, DATABASE, COMMAND, DOCS."
  (let ((max-bson (mongodb--max-bson-object-size conn))
        (max-count (mongodb--max-write-batch-size conn))
        (max-bytes (mongodb--insert-batch-byte-budget conn database command))
        current
        (current-count 0)
        (current-bytes 0)
        batches)
    (cl-loop for doc across docs
             for doc-bytes = (length (mongodb--encode-document doc))
             do
             (when (> doc-bytes max-bson)
               (signal 'mongodb-error
                       (list
                        (format "MongoDB insert document is %s bytes, exceeding maxBsonObjectSize %s"
                                doc-bytes max-bson))))
             (when (> doc-bytes max-bytes)
               (signal 'mongodb-error
                       (list
                        (format "MongoDB insert document is %s bytes, exceeding safe maxMessageSizeBytes batch budget %s"
                                doc-bytes max-bytes))))
             (when (and current
                        (or (>= current-count max-count)
                            (> (+ current-bytes doc-bytes) max-bytes)))
               (push (vconcat (nreverse current)) batches)
               (setq current nil
                     current-count 0
                     current-bytes 0))
             (push doc current)
             (setq current-count (1+ current-count)
                   current-bytes (+ current-bytes doc-bytes)))
    (when current
      (push (vconcat (nreverse current)) batches))
    (nreverse batches)))

(defun mongodb--retryable-write-command-p (command sequences)
  "Return non-nil when COMMAND and SEQUENCES are eligible for retryable writes."
  (pcase (mongodb--command-name command)
    ("insert"
     (mongodb--insert-documents-retryable-p sequences))
    ("update"
     (mongodb--update-statements-retryable-p sequences))
    ("delete"
     (mongodb--delete-statements-retryable-p sequences))
    ((or "findAndModify" "findandmodify") t)
    (_ nil)))

(defun mongodb--write-concern-value (conn command)
  "Return the effective writeConcern document for CONN and COMMAND."
  (or (mongodb--document-field command "writeConcern")
      (mongodb--write-concern-document
       (and conn (mongodb-conn-write-concern conn)))))

(defun mongodb--unacknowledged-write-concern-p (write-concern)
  "Return non-nil when WRITE-CONCERN is unacknowledged."
  (when write-concern
    (let ((w (mongodb--document-field write-concern "w"))
          (journal (or (mongodb--document-field write-concern "j")
                       (mongodb--document-field write-concern "journal"))))
      (and (or (and (numberp w) (zerop w))
               (equal w "0"))
           (not (mongodb--wire-truthy-p journal))))))

(defun mongodb--unacknowledged-write-command-p (_conn command)
  "Return non-nil when COMMAND should be sent as fire-and-forget."
  (and (mongodb--write-command-p command)
       (mongodb--unacknowledged-write-concern-p
        (mongodb--document-field command "writeConcern"))))

(defun mongodb--retryable-writes-supported-p (conn)
  "Return non-nil when CONN's selected server supports retryable writes."
  (and (mongodb-conn-session-id conn)
       (>= (or (mongodb-conn-max-wire-version conn) 0) 6)
       (when-let* ((server (mongodb-select-server conn 'write)))
         (let ((type (mongodb-server-description-type server)))
           (and (memq type '(rs-primary mongos load-balanced))
                (or (eq type 'load-balanced)
                    (mongodb-server-description-logical-session-timeout-minutes
                     server)))))))

(defun mongodb--retryable-write-enabled-p (conn command sequences)
  "Return non-nil when CONN should retry write COMMAND once.

Arguments: CONN, COMMAND, SEQUENCES."
  (and mongodb--retryable-write-context
       (mongodb-conn-retry-writes conn)
       (not (mongodb-in-transaction-p conn))
       (not (mongodb--unacknowledged-write-concern-p
             (mongodb--write-concern-value conn command)))
       (mongodb--retryable-writes-supported-p conn)
       (mongodb--retryable-write-command-p command sequences)))

(defun mongodb--next-transaction-number (conn)
  "Increment and return CONN's next retryable-write transaction number."
  (let ((next (1+ (or (mongodb-conn-txn-number conn) 0))))
    (setf (mongodb-conn-txn-number conn) next)
    (mongodb-int64 next)))

(defun mongodb--retryable-write-concern-error-p (conn response)
  "Return non-nil when RESPONSE has a retryable writeConcernError.

Arguments: CONN, RESPONSE."
  (let ((write-concern-error (cdr (assoc "writeConcernError" response))))
    (and write-concern-error
         (not (eq (mongodb--topology-current-server-type conn) 'mongos))
         (member (mongodb--document-field write-concern-error "code")
                 mongodb--retryable-write-error-codes))))

(defun mongodb--retryable-write-server-error-p (conn response)
  "Return non-nil when RESPONSE reports a retryable write server error.

Arguments: CONN, RESPONSE."
  (let ((code (cdr (assoc "code" response)))
        (labels (cdr (assoc "errorLabels" response))))
    (or (and labels
             (seq-some (lambda (label)
                         (equal label "RetryableWriteError"))
                       (append labels nil)))
        (member code mongodb--retryable-write-error-codes)
        (mongodb--retryable-write-concern-error-p conn response))))

(defun mongodb--conn-address (conn)
  "Return CONN's normalized server address."
  (mongodb--endpoint-key (mongodb-conn-host conn)
                       (mongodb-conn-port conn)))

(defun mongodb--ensure-topology-description (conn)
  "Return CONN's topology description, deriving it from last hello if needed."
  (or (mongodb-conn-topology conn)
      (when-let* ((hello (mongodb-conn-last-hello conn)))
        (setf (mongodb-conn-topology conn)
              (mongodb--topology-description-from-hello conn hello)))))

(defun mongodb--current-server-description (conn)
  "Return the current server description for CONN, or nil."
  (when-let* ((topology (mongodb--ensure-topology-description conn)))
    (cdr (assoc (mongodb--conn-address conn)
                (mongodb-topology-description-servers topology)))))

(defun mongodb--replace-server-description (servers address server)
  "Return SERVERS with ADDRESS replaced by SERVER."
  (let ((updated nil)
        result)
    (dolist (entry servers)
      (if (equal (car entry) address)
          (progn
            (push (cons address server) result)
            (setq updated t))
        (push entry result)))
    (unless updated
      (push (cons address server) result))
    (nreverse result)))

(defun mongodb--topology-with-replaced-server
    (conn server &optional old-topology)
  "Return topology for CONN with current address replaced by SERVER.

Arguments: CONN, SERVER, OLD-TOPOLOGY."
  (let* ((topology (or old-topology
                       (mongodb--ensure-topology-description conn)))
         (address (mongodb--conn-address conn))
         (servers (mongodb--replace-server-description
                   (and topology
                        (mongodb-topology-description-servers topology))
                   address
                   server))
         (topology-type
          (mongodb--topology-type-after-hello
           conn server servers topology))
         (primary-address
          (mongodb--topology-primary-address-from-servers servers))
         (compatible
          (mongodb--topology-compatible-p servers)))
    (make-mongodb-topology-description
     :type topology-type
     :set-name (or (mongodb-server-description-set-name server)
                   (and topology
                        (mongodb-topology-description-set-name topology)))
     :servers servers
     :primary-address primary-address
     :max-election-id
     (and topology
          (mongodb-topology-description-max-election-id topology))
     :max-set-version
     (and topology
          (mongodb-topology-description-max-set-version topology))
     :logical-session-timeout-minutes
     (or (mongodb-server-description-logical-session-timeout-minutes server)
         (and topology
              (mongodb-topology-description-logical-session-timeout-minutes
               topology)))
     :compatible compatible
     :compatibility-error
     (unless compatible
       (mongodb--topology-compatibility-error servers)))))

(defun mongodb--mark-current-server-unknown
    (conn error &optional topology-version)
  "Mark CONN's current server Unknown after ERROR.
TOPOLOGY-VERSION, when non-nil, is stored on the Unknown description so later
state-change errors can be compared for freshness."
  (let* ((address (mongodb--conn-address conn))
         (unknown (mongodb--unknown-server-description
                   address
                   (error-message-string error)
                   topology-version)))
    (mongodb--set-conn-topology
     conn
     (mongodb--topology-with-replaced-server conn unknown)))
  conn)

(defun mongodb--object-id-value (value)
  "Return VALUE as a `mongodb-object-id' when it is Extended JSON ObjectId."
  (cond
   ((mongodb-object-id-p value) value)
   ((and (consp value)
         (consp (car value))
         (assoc "$oid" value))
    (mongodb-object-id (cdr (assoc "$oid" value))))
   (t value)))

(defun mongodb--topology-version-command-value (topology-version)
  "Return TOPOLOGY-VERSION encoded for a hello command."
  (when topology-version
    (mongodb-document
     (mapcar (lambda (pair)
               (pcase (car pair)
                 ("processId"
                  (cons (car pair)
                        (mongodb--object-id-value (cdr pair))))
                 ("counter"
                  (cons (car pair)
                        (if (mongodb-int64-p (cdr pair))
                            (cdr pair)
                          (mongodb-int64 (cdr pair)))))
                 (_ pair)))
             (mongodb--document-pairs topology-version)))))

(defun mongodb--datetime-value-seconds (value)
  "Return BSON datetime VALUE as epoch seconds, or nil."
  (cond
   ((mongodb-datetime-p value)
    (/ (mongodb-datetime-millis value) 1000.0))
   ((integerp value)
    (/ value 1000.0))
   ((and (mongodb--document-value-p value)
         (assoc "$date" (mongodb--document-pairs value)))
    (/ (cdr (assoc "$date" (mongodb--document-pairs value))) 1000.0))
   (t nil)))

(defun mongodb--hello-last-write-date (hello)
  "Return HELLO lastWrite.lastWriteDate as epoch seconds, or nil."
  (when-let* ((last-write (cdr (assoc "lastWrite" hello))))
    (mongodb--datetime-value-seconds
     (cdr (assoc "lastWriteDate"
                 (mongodb--document-pairs last-write))))))

(defun mongodb--writable-server-p (server)
  "Return non-nil when SERVER is writable for command selection."
  (memq (mongodb-server-description-type server)
        '(standalone mongos rs-primary load-balanced)))

(defun mongodb--tag-set-matches-server-p (tag-set server)
  "Return non-nil when TAG-SET matches SERVER's hello tags."
  (let ((required (mongodb--document-pairs tag-set))
        (server-tags (mongodb--document-pairs
                      (mongodb-server-description-tags server))))
    (or (null required)
        (seq-every-p
         (lambda (tag)
           (equal (cdr tag)
                  (cdr (assoc (car tag) server-tags))))
         required))))

(defun mongodb--server-matches-read-preference-tags-p (server read-preference)
  "Return non-nil when SERVER matches READ-PREFERENCE tag sets."
  (let ((tags (and read-preference
                   (mongodb--read-preference-tags read-preference))))
    (or (not tags)
        (seq-some (lambda (tag-set)
                    (mongodb--tag-set-matches-server-p tag-set server))
                  (append tags nil)))))

(defun mongodb--topology-primary-server (topology)
  "Return TOPOLOGY's known primary server description, or nil."
  (when-let* ((address (and topology
                            (mongodb-topology-description-primary-address
                             topology))))
    (cdr (assoc address (mongodb-topology-description-servers topology)))))

(defun mongodb--topology-secondary-servers (topology)
  "Return known secondary server descriptions in TOPOLOGY."
  (when topology
    (seq-keep
     (lambda (entry)
       (let ((server (cdr entry)))
         (and (eq (mongodb-server-description-type server) 'rs-secondary)
              server)))
     (mongodb-topology-description-servers topology))))

(defun mongodb--server-staleness-seconds
    (server topology heartbeat-seconds)
  "Return SERVER's estimated staleness in seconds, or nil.

Arguments: SERVER, TOPOLOGY, HEARTBEAT-SECONDS."
  (let ((server-last-write (mongodb-server-description-last-write-date server))
        (heartbeat (or heartbeat-seconds
                       mongodb-monitor-heartbeat-seconds)))
    (when server-last-write
      (if-let* ((primary (mongodb--topology-primary-server topology))
                (primary-last-write
                 (mongodb-server-description-last-write-date primary)))
          (+ (- (- (mongodb-server-description-last-update-time server)
                   server-last-write)
                (- (mongodb-server-description-last-update-time primary)
                   primary-last-write))
             heartbeat)
        (let ((secondary-last-writes
               (delq nil
                     (mapcar
                      #'mongodb-server-description-last-write-date
                      (mongodb--topology-secondary-servers topology)))))
          (when secondary-last-writes
            (+ (- (apply #'max secondary-last-writes)
                  server-last-write)
               heartbeat)))))))

(defun mongodb--server-within-max-staleness-p
    (server read-preference topology heartbeat-seconds)
  "Return non-nil when SERVER satisfies READ-PREFERENCE max staleness.

Arguments: SERVER, READ-PREFERENCE, TOPOLOGY, HEARTBEAT-SECONDS."
  (let ((max-staleness
         (and read-preference
              (mongodb--read-preference-max-staleness-seconds
               read-preference))))
    (cond
     ((not max-staleness) t)
     ((not (eq (mongodb-server-description-type server) 'rs-secondary)) t)
     ((< (or (mongodb-server-description-max-wire-version server) 0) 5)
      (signal 'mongodb-error
              (list "MongoDB maxStalenessSeconds requires servers with maxWireVersion >= 5")))
     (t
      (when-let* ((staleness
                   (mongodb--server-staleness-seconds
                    server topology heartbeat-seconds)))
        (<= staleness max-staleness))))))

(defun mongodb--server-matches-read-preference-constraints-p
    (server read-preference topology heartbeat-seconds)
  "Return non-nil when SERVER satisfies read preference constraints.

Arguments: SERVER, READ-PREFERENCE, TOPOLOGY, HEARTBEAT-SECONDS."
  (and (mongodb--server-matches-read-preference-tags-p
        server read-preference)
       (mongodb--server-within-max-staleness-p
        server read-preference topology heartbeat-seconds)))

(defun mongodb--readable-server-p
    (server read-preference topology &optional heartbeat-seconds)
  "Return non-nil when SERVER satisfies READ-PREFERENCE in TOPOLOGY.

Arguments: SERVER, READ-PREFERENCE, TOPOLOGY, HEARTBEAT-SECONDS."
  (let ((type (and server
                   (mongodb-server-description-type server)))
        (mode (if read-preference
                  (mongodb--read-preference-mode read-preference)
                "primary")))
    (pcase type
      ((or 'standalone 'mongos 'load-balanced)
       t)
      ('rs-primary
       (cond
        ((member mode '("primary" "primaryPreferred"
                        "secondaryPreferred"))
         t)
        ((equal mode "nearest")
         (mongodb--server-matches-read-preference-constraints-p
          server read-preference topology heartbeat-seconds))))
      ('rs-secondary
       (and
        (pcase mode
          ("primary" nil)
          ("primaryPreferred"
           (not (mongodb-topology-description-primary-address topology)))
          ((or "secondary" "secondaryPreferred" "nearest") t)
          (_ nil))
        (mongodb--server-matches-read-preference-constraints-p
         server read-preference topology heartbeat-seconds)))
      (_ nil))))

(defun mongodb--available-server-p (server)
  "Return non-nil when SERVER is available for Single topology selection."
  (and server
       (not (eq (mongodb-server-description-type server) 'unknown))))

(defun mongodb-topology-description-has-readable-server-p
    (topology &optional read-preference heartbeat-seconds)
  "Return non-nil when TOPOLOGY has a readable MongoDB server.
READ-PREFERENCE accepts the same values as command and transaction options:
nil or primary by default, a read preference mode string/symbol, or a
readPreference document.  HEARTBEAT-SECONDS is used for maxStalenessSeconds
calculation and defaults to `mongodb-monitor-heartbeat-seconds'."
  (when (mongodb-topology-description-p topology)
    (let ((read-preference (mongodb--read-preference-value read-preference)))
      (pcase (mongodb-topology-description-type topology)
        ('unknown nil)
        ('load-balanced t)
        ('single
         (seq-some (lambda (entry)
                     (mongodb--available-server-p (cdr entry)))
                   (mongodb-topology-description-servers topology)))
        ('sharded
         (seq-some (lambda (entry)
                     (mongodb--available-server-p (cdr entry)))
                   (mongodb-topology-description-servers topology)))
        (_
         (seq-some (lambda (entry)
                     (mongodb--readable-server-p
                      (cdr entry) read-preference topology heartbeat-seconds))
                   (mongodb-topology-description-servers topology)))))))

(defun mongodb-topology-description-has-writable-server-p (topology)
  "Return non-nil when TOPOLOGY has a writable MongoDB server."
  (when (mongodb-topology-description-p topology)
    (pcase (mongodb-topology-description-type topology)
      ('unknown nil)
      ('load-balanced t)
      ('single
       (seq-some (lambda (entry)
                   (mongodb--available-server-p (cdr entry)))
                 (mongodb-topology-description-servers topology)))
      ('sharded
       (seq-some (lambda (entry)
                   (mongodb--available-server-p (cdr entry)))
                 (mongodb-topology-description-servers topology)))
      (_
       (seq-some (lambda (entry)
                   (mongodb--writable-server-p (cdr entry)))
                 (mongodb-topology-description-servers topology))))))

(defun mongodb--single-topology-read-preference (conn command read-preference)
  "Return effective OP_MSG read preference for CONN and COMMAND.
In Server Selection Spec Single topology, reads against a replica-set member
must carry primaryPreferred when the application did not request a non-primary
read preference.  This allows directConnection=true reads from secondaries.

Arguments: CONN, COMMAND, READ-PREFERENCE."
  (let* ((topology (mongodb--ensure-topology-description conn))
         (server (mongodb--current-server-description conn))
         (mode (and read-preference
                    (mongodb--read-preference-mode read-preference))))
    (if (and (mongodb--read-command-p command)
             (eq (and topology
                      (mongodb-topology-description-type topology))
                 'single)
             server
             (memq (mongodb-server-description-type server)
                   '(rs-primary rs-secondary rs-other rs-arbiter rs-ghost))
             (or (not mode)
                 (equal mode "primary")))
        (make-mongodb--read-preference :mode "primaryPreferred")
      read-preference)))

(defun mongodb--effective-command-read-preference (conn command)
  "Return the read preference to attach to COMMAND on CONN."
  (mongodb--single-topology-read-preference
   conn command (mongodb-conn-read-preference conn)))

(defun mongodb-select-server (conn &optional purpose read-preference)
  "Return the selected current server description for CONN and PURPOSE.
PURPOSE may be `write' or `read'.  The current implementation tracks one
socket; this function exposes the server-selection boundary used by future
  multi-server topology monitoring.

Arguments: CONN, PURPOSE, READ-PREFERENCE."
  (let* ((topology (mongodb--ensure-topology-description conn))
         (server (mongodb--current-server-description conn))
         (read-preference (or read-preference
                              (mongodb-conn-read-preference conn))))
    (mongodb--ensure-topology-compatible topology)
    (if (eq (and topology
                 (mongodb-topology-description-type topology))
            'single)
        (and (mongodb--available-server-p server)
             server)
      (pcase (or purpose 'read)
        ('write
         (and server
              (mongodb--writable-server-p server)
              server))
        (_
         (and server
              (mongodb--readable-server-p
               server
               read-preference
               topology
               (or (mongodb-conn-heartbeat-frequency conn)
                   mongodb-monitor-heartbeat-seconds))
              server))))))

(defun mongodb--topology-current-server-type (conn)
  "Return CONN's current topology server type, or nil."
  (when-let* ((server (mongodb--current-server-description conn)))
    (mongodb-server-description-type server)))

(defun mongodb--topology-current-server-error (conn)
  "Return CONN's current server description error, or nil."
  (when-let* ((server (mongodb--current-server-description conn)))
    (mongodb-server-description-error server)))

(defun mongodb--topology-current-server-context (conn)
  "Return a user-facing summary of CONN's current selected server state."
  (let ((type (or (mongodb--topology-current-server-type conn) 'unknown))
        (error (mongodb--topology-current-server-error conn)))
    (if error
        (format "%s (%s)" type error)
      (format "%s" type))))

(defun mongodb--ensure-writable-server (conn command &optional timeout)
  "Refresh CONN if COMMAND needs a writable server and none is selected.

Arguments: CONN, COMMAND, TIMEOUT."
  (when (and (mongodb--write-command-p command)
             (not (mongodb-select-server conn 'write)))
    (ignore-errors
      (mongodb-hello conn timeout))
    (unless (mongodb-select-server conn 'write)
      (signal 'mongodb-error
              (list
               (format
                "No writable MongoDB server available for %s; current server type is %s"
                (or (mongodb--command-name command) "command")
                (mongodb--topology-current-server-context conn)))))))

(defun mongodb--ensure-readable-server
    (conn command &optional timeout read-preference)
  "Refresh CONN if COMMAND needs a readable server and none is selected.

Arguments: CONN, COMMAND, TIMEOUT, READ-PREFERENCE."
  (when (and (mongodb--read-command-p command)
             (not (mongodb-select-server conn 'read read-preference)))
    (ignore-errors
      (mongodb-hello conn timeout))
    (unless (mongodb-select-server conn 'read read-preference)
      (signal 'mongodb-error
              (list
               (format
                "No readable MongoDB server available for %s with readPreference=%s; current server type is %s"
                (or (mongodb--command-name command) "command")
                (if read-preference
                    (mongodb--read-preference-mode
                     read-preference)
                  "primary")
                (mongodb--topology-current-server-context conn)))))))

(defun mongodb--not-writable-error-p (response)
  "Return non-nil when RESPONSE reports a stale/non-writable primary."
  (let ((code-name (cdr (assoc "codeName" response)))
        (errmsg (downcase (or (mongodb--response-message response) ""))))
    (or (member code-name
                '("NotWritablePrimary" "NotPrimaryNoSecondaryOk"
                  "PrimarySteppedDown" "InterruptedDueToReplStateChange"
                  "NotMaster" "NotMasterNoSlaveOk"))
        (string-match-p
         "\\(not writable primary\\|not primary\\|not master\\|primary stepped down\\)"
         errmsg))))

(defun mongodb--state-change-error-p (response)
  "Return non-nil when RESPONSE means the current server state is stale."
  (let ((code-name (cdr (assoc "codeName" response)))
        (errmsg (downcase (or (mongodb--response-message response) ""))))
    (or (member code-name mongodb--state-change-error-code-names)
        (string-match-p
         (concat "\\(not writable primary\\|not primary\\|not master\\|"
                 "primary stepped down\\|node is recovering\\|"
                 "node is shutting down\\|interrupted at shutdown\\|"
                 "interrupted due to repl state change\\)")
         errmsg))))

(defun mongodb--state-change-error-fresh-p (conn response)
  "Return non-nil if RESPONSE should update CONN's server description."
  (let* ((server (mongodb--current-server-description conn))
         (current-topology-version
          (and server
               (mongodb-server-description-topology-version server)))
         (error-topology-version
          (mongodb--topology-version-from-response response)))
    (mongodb--topology-version-newer-p
     error-topology-version current-topology-version)))

(defun mongodb--handle-state-change-error (conn response)
  "Apply SDAM state-change side effects for RESPONSE on CONN.
Return `marked' when the current server was marked Unknown, `stale' when
RESPONSE contained an old topologyVersion and was ignored for topology
purposes, or nil when RESPONSE is not a state-change error."
  (when (and conn
             (mongodb--state-change-error-p response))
    (if (mongodb--state-change-error-fresh-p conn response)
        (progn
          (mongodb--mark-current-server-unknown
           conn
           (list 'mongodb-error (mongodb--response-message response))
           (mongodb--topology-version-from-response response))
          'marked)
      'stale)))

(defun mongodb--transaction-control-command-p (command)
  "Return non-nil when COMMAND is a transaction control command."
  (member (mongodb--command-name command)
          '("commitTransaction" "abortTransaction")))

(defun mongodb--transaction-active-state-p (state)
  "Return non-nil when transaction STATE is active."
  (memq state '(starting in-progress)))

(defun mongodb--transaction-ended-state-p (state)
  "Return non-nil when transaction STATE is committed or aborted."
  (memq state '(committed aborted)))

(defun mongodb--clear-ended-transaction-for-command (conn command)
  "Clear ended transaction state on CONN before non-control COMMAND."
  (when (and (mongodb--transaction-ended-state-p
              (mongodb-conn-transaction-state conn))
             (not (mongodb--transaction-control-command-p command)))
    (mongodb--clear-transaction conn))
  conn)

(defun mongodb--transaction-command-state (conn command)
  "Return transaction state for COMMAND on CONN, or nil."
  (mongodb--clear-ended-transaction-for-command conn command)
  (let ((state (mongodb-conn-transaction-state conn)))
    (cond
     ((and state
           (mongodb--transaction-control-command-p command))
      'in-progress)
     ((mongodb--transaction-active-state-p state) state)
     (t nil))))

(defun mongodb--transaction-command-number (conn state)
  "Return CONN transaction number for transaction STATE, or nil."
  (and state
       (mongodb-conn-transaction-number conn)))

(defun mongodb--primary-read-preference-p (read-preference)
  "Return non-nil when READ-PREFERENCE is nil or primary."
  (or (not read-preference)
      (equal (mongodb--read-preference-mode read-preference) "primary")))

(defun mongodb--validate-transaction-command (conn command transaction-state)
  "Signal when COMMAND violates transaction command rules for CONN."
  (when (and transaction-state
             (not (mongodb--transaction-control-command-p command)))
    (let ((pairs (mongodb--document-pairs command)))
      (when (and (mongodb--read-command-p pairs)
                 (not (mongodb--primary-read-preference-p
                       (mongodb-conn-transaction-read-preference conn))))
        (signal 'mongodb-error
                (list "read preference in a transaction must be primary")))
      (when (assoc "readConcern" pairs)
        (signal 'mongodb-error
                (list "Cannot set read concern after starting a transaction")))
      (when (assoc "writeConcern" pairs)
        (signal 'mongodb-error
                (list "Cannot set write concern after starting a transaction"))))))

(defun mongodb--command-timeout (conn timeout)
  "Return the effective timeout seconds for a MongoDB command on CONN.

Arguments: CONN, TIMEOUT."
  (or timeout
      (mongodb-conn-operation-timeout conn)
      (mongodb-conn-socket-timeout conn)
      mongodb-timeout-seconds))

(defun mongodb--mark-transaction-command-sent (conn state)
  "Mark transaction STATE as having sent one command on CONN."
  (when (and (eq state 'starting)
             (eq (mongodb-conn-transaction-state conn) 'starting))
    (setf (mongodb-conn-transaction-state conn) 'in-progress)))

(defun mongodb--unpin-transaction (conn)
  "Clear CONN's transaction server/connection pin."
  (setf (mongodb-conn-transaction-pinned-address conn) nil)
  (setf (mongodb-conn-transaction-pinned-service-id conn) nil)
  conn)

(defun mongodb--transaction-pinnable-server (conn)
  "Return current server when transaction commands should pin to it.

Arguments: CONN."
  (when-let* ((server (mongodb--current-server-description conn)))
    (when (memq (mongodb-server-description-type server)
                '(mongos load-balanced))
      server)))

(defun mongodb--ensure-transaction-pin (conn transaction-state)
  "Pin or validate CONN for TRANSACTION-STATE commands.
Sharded transactions pin to a mongos address.  Load-balanced transactions pin
to the selected serviceId on the single socket."
  (when transaction-state
    (let* ((server (mongodb--transaction-pinnable-server conn))
           (address (and server
                         (mongodb-server-description-address server)))
           (service-id (and server
                            (mongodb-server-description-service-id server)))
           (pinned-address
            (mongodb-conn-transaction-pinned-address conn))
           (pinned-service-id
            (mongodb-conn-transaction-pinned-service-id conn)))
      (cond
       ((and pinned-address
             (not (equal pinned-address address)))
        (signal 'mongodb-error
                (list
                 (format
                  "MongoDB transaction is pinned to %s but current server is %s"
                  pinned-address
                  (or address "<none>")))))
       ((and pinned-service-id
             (not (equal pinned-service-id service-id)))
        (signal 'mongodb-error
                (list "MongoDB load-balanced transaction changed serviceId")))
       ((and server
             (not pinned-address))
        (setf (mongodb-conn-transaction-pinned-address conn) address)
        (when service-id
          (setf (mongodb-conn-transaction-pinned-service-id conn)
                service-id))))))
  conn)

(defun mongodb--send-command-and-receive
    (conn database command timeout sequences txn-number)
  "Send one MongoDB COMMAND attempt and return the response alist.
SEQUENCES, when non-nil, is sent as OP_MSG document sequence sections.

Arguments: CONN, DATABASE, COMMAND, TIMEOUT, SEQUENCES, TXN-NUMBER."
  (unless (mongodb-live-p conn)
    (signal 'mongodb-error
            (list "MongoDB connection is closed")))
  (let* ((timeout (mongodb--command-timeout conn timeout))
         (transaction-state (mongodb--transaction-command-state conn command))
         (transaction-number
          (mongodb--transaction-command-number conn transaction-state)))
    (mongodb--validate-transaction-command conn command transaction-state)
    (mongodb--ensure-writable-server conn command timeout)
    (mongodb--ensure-readable-server
     conn command timeout
     (and transaction-state
          (mongodb-conn-transaction-read-preference conn)))
    (mongodb--ensure-transaction-pin conn transaction-state)
    (let* ((effective-txn-number (or transaction-number txn-number))
	   (document
	    (mongodb--command-with-db
	     command
	     (or database (mongodb-conn-database conn))
	     (mongodb-conn-server-api conn)
	     (mongodb-conn-session-id conn)
	     (mongodb--effective-command-read-preference conn command)
	     (and mongodb--operation-command-context
	          (mongodb-conn-read-concern conn))
	     (and mongodb--operation-command-context
	          (mongodb-conn-write-concern conn))
	     effective-txn-number
	     transaction-state
	     (mongodb-conn-transaction-read-concern conn)
	     (mongodb--cluster-time-to-send conn)))
	   (request-id nil))
      (let ((mongodb--command-event-context
	     (mongodb--make-command-event-context
	      (or database (mongodb-conn-database conn))
	      document
	      sequences)))
	(condition-case err
	    (progn
	      (if (mongodb--unacknowledged-write-command-p conn document)
	          (let ((response '(("ok" . 1))))
	            (setq request-id
	                  (mongodb--send-document-with-flags
	                   conn document sequences mongodb--op-msg-more-to-come))
	            (mongodb--command-event-started conn request-id)
	            (mongodb--command-event-succeeded conn response)
	            response)
	        (setq request-id
	              (if sequences
	                  (mongodb--send-document conn document sequences)
	                (mongodb--send-document conn document)))
	        (mongodb--command-event-started conn request-id)
	        (mongodb--mark-transaction-command-sent
	         conn transaction-state)
	        (let ((response
	               (mongodb--recv-message conn timeout request-id)))
	          (mongodb--advance-cluster-time-from-response
	           conn command response)
	          (mongodb--advance-transaction-recovery-token-from-response
	           conn transaction-state response)
	          (if (mongodb--ok-p response)
	              (mongodb--command-event-succeeded conn response)
	            (mongodb--command-event-failed conn response))
	          response)))
	  (error
	   (mongodb--command-event-failed conn err)
	   (signal (car err) (cdr err))))))))

(defun mongodb--decoded-message-more-to-come-p (frame)
  "Return non-nil when decoded OP_MSG FRAME has the moreToCome flag."
  (not (zerop (logand (mongodb--decoded-message-flags frame)
                      mongodb--op-msg-more-to-come))))

(defun mongodb--send-command-exhaust-and-receive
    (conn database command timeout sequences)
  "Send one MongoDB COMMAND attempt with exhaustAllowed and return responses.
SEQUENCES, when non-nil, is sent as OP_MSG document sequence sections.  The
caller must only use commands whose server semantics allow exhaust replies.

Arguments: CONN, DATABASE, COMMAND, TIMEOUT, SEQUENCES."
  (unless (mongodb-live-p conn)
    (signal 'mongodb-error
            (list "MongoDB connection is closed")))
  (unless (>= (or (mongodb-conn-max-wire-version conn) 0) 6)
    (signal 'mongodb-error
            (list "MongoDB OP_MSG exhaustAllowed requires MongoDB 3.6+ wire version support")))
  (let* ((timeout (mongodb--command-timeout conn timeout))
         (transaction-state (mongodb--transaction-command-state conn command))
         (transaction-number
          (mongodb--transaction-command-number conn transaction-state)))
    (mongodb--validate-transaction-command conn command transaction-state)
    (mongodb--ensure-writable-server conn command timeout)
    (mongodb--ensure-readable-server
     conn command timeout
     (and transaction-state
          (mongodb-conn-transaction-read-preference conn)))
    (mongodb--ensure-transaction-pin conn transaction-state)
    (let* ((document
            (mongodb--command-with-db
             command
             (or database (mongodb-conn-database conn))
	     (mongodb-conn-server-api conn)
	     (mongodb-conn-session-id conn)
	     (mongodb--effective-command-read-preference conn command)
	     (and mongodb--operation-command-context
	          (mongodb-conn-read-concern conn))
	     (and mongodb--operation-command-context
	          (mongodb-conn-write-concern conn))
	     transaction-number
	     transaction-state
	     (mongodb-conn-transaction-read-concern conn)
	     (mongodb--cluster-time-to-send conn)))
	   (request-id nil)
	   responses
	   more-to-come)
      (let ((mongodb--command-event-context
	     (mongodb--make-command-event-context
	      (or database (mongodb-conn-database conn))
	      document
	      sequences)))
	(condition-case err
	    (progn
	      (setq request-id
	            (mongodb--send-document-with-flags
	             conn document sequences mongodb--op-msg-exhaust-allowed))
	      (mongodb--command-event-started conn request-id)
	      (mongodb--mark-transaction-command-sent conn transaction-state)
	      (setq more-to-come t)
	      (while more-to-come
	        (let* ((frame (mongodb--recv-message-frame
	                       conn timeout request-id t))
	               (response (mongodb--decoded-message-document frame)))
	          (push response responses)
	          (mongodb--advance-cluster-time-from-response conn command response)
	          (mongodb--advance-transaction-recovery-token-from-response
	           conn transaction-state response)
	          (setq more-to-come
	                (mongodb--decoded-message-more-to-come-p frame))))
	      (setq responses (nreverse responses))
	      (dolist (response responses)
	        (unless (mongodb--ok-p response)
	          (mongodb--command-event-failed conn response)
	          (signal 'mongodb-error
	                  (list (mongodb--response-message response)))))
	      (mongodb--command-event-succeeded
	       conn (or (car (last responses)) '(("ok" . 1))))
	      (dolist (response responses)
	        (when-let* ((message (and mongodb--operation-command-context
	                                  (mongodb--write-command-p command)
	                                  (mongodb--write-error-message response))))
	          (signal 'mongodb-error (list message))))
	        responses)
	    (error
	     (mongodb--command-event-failed conn err)
	     (signal (car err) (cdr err))))))))

(defun mongodb--replace-conn-transport (conn replacement old-session-id)
  "Replace CONN's transport and server state with REPLACEMENT.
OLD-SESSION-ID, when non-nil, is preserved so retryable reads reuse the same
implicit session across a reconnect."
  (setf (mongodb-conn-process conn)
        (mongodb-conn-process replacement))
  (setf (mongodb-conn-buffer conn)
        (mongodb-conn-buffer replacement))
  (setf (mongodb-conn-host conn)
        (mongodb-conn-host replacement))
  (setf (mongodb-conn-port conn)
        (mongodb-conn-port replacement))
  (setf (mongodb-conn-database conn)
        (mongodb-conn-database replacement))
  (setf (mongodb-conn-socket-timeout conn)
        (mongodb-conn-socket-timeout replacement))
  (setf (mongodb-conn-operation-timeout conn)
        (mongodb-conn-operation-timeout replacement))
  (setf (mongodb-conn-local-threshold conn)
        (mongodb-conn-local-threshold replacement))
  (setf (mongodb-conn-heartbeat-frequency conn)
        (mongodb-conn-heartbeat-frequency replacement))
  (setf (mongodb-conn-server-monitoring-mode conn)
        (mongodb-conn-server-monitoring-mode replacement))
  (setf (mongodb-conn-request-id conn)
        (mongodb-conn-request-id replacement))
  (setf (mongodb-conn-max-wire-version conn)
        (mongodb-conn-max-wire-version replacement))
  (setf (mongodb-conn-max-bson-object-size conn)
        (mongodb-conn-max-bson-object-size replacement))
  (setf (mongodb-conn-max-message-size-bytes conn)
        (mongodb-conn-max-message-size-bytes replacement))
  (setf (mongodb-conn-max-write-batch-size conn)
        (mongodb-conn-max-write-batch-size replacement))
  (setf (mongodb-conn-compressors conn)
        (mongodb-conn-compressors replacement))
  (setf (mongodb-conn-server-api conn)
        (mongodb-conn-server-api replacement))
  (setf (mongodb-conn-read-preference conn)
        (mongodb-conn-read-preference replacement))
  (setf (mongodb-conn-read-concern conn)
        (mongodb-conn-read-concern replacement))
  (setf (mongodb-conn-write-concern conn)
        (mongodb-conn-write-concern replacement))
  (setf (mongodb-conn-load-balanced conn)
        (mongodb-conn-load-balanced replacement))
  (setf (mongodb-conn-service-id conn)
        (mongodb-conn-service-id replacement))
  (setf (mongodb-conn-hello-command conn)
        (mongodb-conn-hello-command replacement))
  (setf (mongodb-conn-last-hello conn)
        (mongodb-conn-last-hello replacement))
  (setf (mongodb-conn-topology conn)
        (mongodb-conn-topology replacement))
  (setf (mongodb-conn-session-id conn)
        (or old-session-id
            (mongodb-conn-session-id replacement)))
  (setf (mongodb-conn-cluster-time conn)
        (mongodb--max-cluster-time
         (mongodb-conn-cluster-time conn)
         (mongodb-conn-cluster-time replacement)))
  (setf (mongodb-conn-session-cluster-time conn)
        (mongodb--max-cluster-time
         (mongodb-conn-session-cluster-time conn)
         (mongodb-conn-session-cluster-time replacement)))
  (setf (mongodb-conn-transaction-state conn)
        (mongodb-conn-transaction-state replacement))
  (setf (mongodb-conn-transaction-number conn)
        (mongodb-conn-transaction-number replacement))
  (setf (mongodb-conn-transaction-read-preference conn)
        (mongodb-conn-transaction-read-preference replacement))
  (setf (mongodb-conn-transaction-read-concern conn)
        (mongodb-conn-transaction-read-concern replacement))
  (setf (mongodb-conn-transaction-write-concern conn)
        (mongodb-conn-transaction-write-concern replacement))
  (setf (mongodb-conn-transaction-max-commit-time-ms conn)
        (mongodb-conn-transaction-max-commit-time-ms replacement))
  (setf (mongodb-conn-transaction-recovery-token conn)
        (mongodb-conn-transaction-recovery-token replacement))
  (setf (mongodb-conn-transaction-pinned-address conn)
        (mongodb-conn-transaction-pinned-address replacement))
  (setf (mongodb-conn-transaction-pinned-service-id conn)
        (mongodb-conn-transaction-pinned-service-id replacement))
  (setf (mongodb-conn-transaction-commit-sent conn)
        (mongodb-conn-transaction-commit-sent replacement))
  (setf (mongodb-conn-closed conn) nil)
  conn)

(defun mongodb--close-transport (conn)
  "Close CONN's socket and buffer without ending logical sessions."
  (mongodb-stop-monitor conn)
  (when-let* ((proc (mongodb-conn-process conn)))
    (when (process-live-p proc)
      (delete-process proc)))
  (when-let* ((buffer (mongodb-conn-buffer conn)))
    (when (buffer-live-p buffer)
      (kill-buffer buffer))))

(defun mongodb--reconnect-current-server (conn)
  "Reconnect CONN to its current endpoint and return CONN."
  (let* ((old-session-id (mongodb-conn-session-id conn))
         (params (or (mongodb-conn-params conn)
                     `(:host ,(mongodb-conn-host conn)
                       :port ,(mongodb-conn-port conn)
                       :database ,(mongodb-conn-database conn))))
         (credential (mongodb-conn-credential conn))
         (authenticate (mongodb-conn-authenticate conn))
         (host (mongodb-conn-host conn))
         (port (mongodb-conn-port conn))
         (database (mongodb-conn-database conn))
         replacement)
    (mongodb--close-transport conn)
    (setf (mongodb-conn-closed conn) t)
    (setq replacement
          (car (mongodb--connect-endpoint
                params host port database credential authenticate)))
    (setf (mongodb-conn-params replacement)
          params)
    (setf (mongodb-conn-credential replacement)
          credential)
    (setf (mongodb-conn-authenticate replacement)
          authenticate)
    (setf (mongodb-conn-retry-reads replacement)
          (mongodb-conn-retry-reads conn))
    (setf (mongodb-conn-retry-writes replacement)
          (mongodb-conn-retry-writes conn))
    (mongodb--replace-conn-transport
     conn replacement old-session-id)))

(defun mongodb--retry-read-once (conn err)
  "Prepare CONN for one retryable read retry after ERR."
  (mongodb--mark-current-server-unknown conn err)
  (mongodb--reconnect-current-server conn))

(defun mongodb--retry-write-once (conn err)
  "Prepare CONN for one retryable write retry after ERR."
  (mongodb--mark-current-server-unknown conn err)
  (mongodb--reconnect-current-server conn))

(defun mongodb--retry-transaction-control-once (conn err)
  "Reconnect CONN for a transaction control retry after ERR.
The reconnect path replaces transport state from a new connection, so preserve
the active transaction metadata that commitTransaction/abortTransaction must
reuse."
  (let ((state (mongodb-conn-transaction-state conn))
        (txn-number (mongodb-conn-transaction-number conn))
        (read-preference (mongodb-conn-transaction-read-preference conn))
        (read-concern (mongodb-conn-transaction-read-concern conn))
        (write-concern (mongodb-conn-transaction-write-concern conn))
        (max-commit-time-ms
         (mongodb-conn-transaction-max-commit-time-ms conn))
        (recovery-token (mongodb-conn-transaction-recovery-token conn))
        (commit-sent (mongodb-conn-transaction-commit-sent conn)))
    (mongodb--unpin-transaction conn)
    (mongodb--retry-write-once conn err)
    (setf (mongodb-conn-transaction-state conn) state)
    (setf (mongodb-conn-transaction-number conn) txn-number)
    (setf (mongodb-conn-transaction-read-preference conn) read-preference)
    (setf (mongodb-conn-transaction-read-concern conn) read-concern)
    (setf (mongodb-conn-transaction-write-concern conn) write-concern)
    (setf (mongodb-conn-transaction-max-commit-time-ms conn)
          max-commit-time-ms)
    (setf (mongodb-conn-transaction-recovery-token conn) recovery-token)
    (setf (mongodb-conn-transaction-commit-sent conn) commit-sent)
    conn))

(defun mongodb-in-transaction-p (conn)
  "Return non-nil when CONN has an active transaction."
  (and (mongodb-conn-p conn)
       (mongodb--transaction-active-state-p
        (mongodb-conn-transaction-state conn))))

(defun mongodb--conn-session-supported-p (conn)
  "Return non-nil when CONN reports logical session support."
  (and (mongodb-conn-p conn)
       (or (mongodb-conn-session-id conn)
           (mongodb-conn-load-balanced conn)
           (and (mongodb-conn-last-hello conn)
                (mongodb--session-supported-p (mongodb-conn-last-hello conn)))
           (let ((topology (mongodb-conn-topology conn)))
             (and topology
                  (numberp
                   (mongodb-topology-description-logical-session-timeout-minutes
                    topology)))))))

(defun mongodb--ensure-session (conn)
  "Ensure CONN has an implicit logical session and return it."
  (unless (mongodb--conn-session-supported-p conn)
    (signal 'mongodb-error
            (list "MongoDB transactions require logical session support")))
  (or (mongodb-conn-session-id conn)
      (let ((session-id (mongodb--make-session-id)))
        (setf (mongodb-conn-session-id conn) session-id)
        session-id)))

(defun mongodb--transaction-write-concern (conn option-pairs)
  "Return effective transaction writeConcern for CONN and OPTION-PAIRS."
  (or (cdr (assoc "writeConcern" option-pairs))
      (mongodb--write-concern-document
       (and conn (mongodb-conn-write-concern conn)))))

(defun mongodb--read-preference-value (value)
  "Return VALUE as a `mongodb--read-preference'."
  (cond
   ((null value) nil)
   ((mongodb--read-preference-p value) value)
   ((or (stringp value)
        (symbolp value))
    (mongodb--params-read-preference
     (list :read-preference value)))
   ((or (mongodb-document-p value)
        (hash-table-p value)
        (and (consp value)
             (consp (car value))))
    (let* ((pairs (mongodb--document-pairs value))
           (mode (or (cdr (assoc "mode" pairs))
                     (cdr (assoc "readPreference" pairs))))
           (tags (cdr (assoc "tags" pairs)))
           (max-staleness (cdr (assoc "maxStalenessSeconds" pairs)))
           (params (list :read-preference (or mode "primary"))))
      (when tags
        (setq params
              (plist-put params :read-preference-tags tags)))
      (when max-staleness
        (setq params
              (plist-put params :maxStalenessSeconds max-staleness)))
      (mongodb--params-read-preference params)))
   (t
    (signal 'mongodb-error
            (list (format "Invalid MongoDB readPreference value: %S"
                          value))))))

(defun mongodb--transaction-read-preference (conn option-pairs)
  "Return effective transaction readPreference for CONN and OPTION-PAIRS."
  (if-let* ((pair (assoc "readPreference" option-pairs)))
      (or (mongodb--read-preference-value (cdr pair))
          (mongodb-conn-read-preference conn))
    (mongodb-conn-read-preference conn)))

(defun mongodb--validate-transaction-write-concern (write-concern)
  "Signal when WRITE-CONCERN cannot be used in a MongoDB transaction."
  (when (mongodb--unacknowledged-write-concern-p write-concern)
    (signal 'mongodb-error
            (list "MongoDB transactions do not support unacknowledged write concerns")))
  write-concern)

(defun mongodb--transaction-max-commit-time-ms (option-pairs)
  "Return maxCommitTimeMS from transaction OPTION-PAIRS, or nil."
  (mongodb--parse-integer-option
   (cdr (assoc "maxCommitTimeMS" option-pairs))
   "maxCommitTimeMS"))

(defun mongodb--validate-nonnegative-time-ms (value name)
  "Return VALUE parsed as a non-negative integer for MongoDB option NAME."
  (when-let* ((number (mongodb--parse-integer-option value name)))
    (when (< number 0)
      (signal 'mongodb-error
              (list (format "MongoDB %s must be non-negative" name))))
    number))

(defun mongodb-start-transaction (conn &optional options)
  "Start a MongoDB transaction on CONN.
OPTIONS is an optional MongoDB document containing readConcern and
writeConcern transaction options.  The server transaction begins when the next
command is sent."
  (unless (mongodb-live-p conn)
    (signal 'mongodb-error
            (list "MongoDB connection is closed")))
  (when (mongodb-in-transaction-p conn)
    (signal 'mongodb-error
            (list "Transaction already in progress")))
  (when (mongodb--transaction-ended-state-p
         (mongodb-conn-transaction-state conn))
    (mongodb--clear-transaction conn))
  (mongodb--ensure-session conn)
  (let* ((pairs (mongodb--document-pairs options))
         (read-preference (mongodb--transaction-read-preference conn pairs))
         (read-concern (cdr (assoc "readConcern" pairs)))
         (write-concern
          (mongodb--validate-transaction-write-concern
           (mongodb--transaction-write-concern conn pairs)))
         (max-commit-time-ms
          (mongodb--validate-nonnegative-time-ms
           (mongodb--transaction-max-commit-time-ms pairs)
           "maxCommitTimeMS"))
         (txn-number (mongodb--next-transaction-number conn)))
    (setf (mongodb-conn-transaction-state conn) 'starting)
    (setf (mongodb-conn-transaction-number conn) txn-number)
    (setf (mongodb-conn-transaction-read-preference conn) read-preference)
    (setf (mongodb-conn-transaction-read-concern conn) read-concern)
    (setf (mongodb-conn-transaction-write-concern conn) write-concern)
    (setf (mongodb-conn-transaction-max-commit-time-ms conn)
          max-commit-time-ms)
    (setf (mongodb-conn-transaction-recovery-token conn) nil)
    (setf (mongodb-conn-transaction-pinned-address conn) nil)
    (setf (mongodb-conn-transaction-pinned-service-id conn) nil)
    (setf (mongodb-conn-transaction-commit-sent conn) nil)
    conn))

(defun mongodb--clear-transaction (conn)
  "Clear CONN transaction state."
  (setf (mongodb-conn-transaction-state conn) nil)
  (setf (mongodb-conn-transaction-number conn) nil)
  (setf (mongodb-conn-transaction-read-preference conn) nil)
  (setf (mongodb-conn-transaction-read-concern conn) nil)
  (setf (mongodb-conn-transaction-write-concern conn) nil)
  (setf (mongodb-conn-transaction-max-commit-time-ms conn) nil)
  (setf (mongodb-conn-transaction-recovery-token conn) nil)
  (mongodb--unpin-transaction conn)
  (setf (mongodb-conn-transaction-commit-sent conn) nil)
  conn)

(defun mongodb--document-set-field (pairs field value)
  "Return PAIRS with FIELD set to VALUE."
  (let ((updated nil)
        result)
    (dolist (pair pairs)
      (if (equal (car pair) field)
          (progn
            (push (cons field value) result)
            (setq updated t))
        (push pair result)))
    (unless updated
      (push (cons field value) result))
    (nreverse result)))

(defun mongodb--commit-retry-write-concern (write-concern)
  "Return commitTransaction retry writeConcern from WRITE-CONCERN.
Retries and explicit subsequent commit attempts must use majority write
concern and a finite wtimeout when no wtimeout is already present."
  (let ((pairs (copy-sequence (mongodb--document-pairs write-concern))))
    (setq pairs (mongodb--document-set-field pairs "w" "majority"))
    (unless (assoc "wtimeout" pairs)
      (setq pairs
            (append pairs '(("wtimeout" . 10000)))))
    pairs))

(defun mongodb--transaction-commit-command
    (conn max-time-ms retry-attempt)
  "Return commitTransaction command for CONN.
MAX-TIME-MS is included when non-nil.  RETRY-ATTEMPT means apply commit retry
writeConcern rules."
  (let* ((write-concern (mongodb-conn-transaction-write-concern conn))
         (recovery-token (mongodb-conn-transaction-recovery-token conn))
         (effective-write-concern
          (if retry-attempt
              (mongodb--commit-retry-write-concern write-concern)
            write-concern)))
    `(("commitTransaction" . 1)
      ,@(when effective-write-concern
          `(("writeConcern" . ,effective-write-concern)))
      ,@(when max-time-ms
          `(("maxTimeMS" . ,max-time-ms)))
      ,@(when recovery-token
          `(("recoveryToken" . ,recovery-token))))))

(defun mongodb--effective-commit-max-time-ms (conn max-time-ms)
  "Return effective commitTransaction maxTimeMS for CONN.

Arguments: CONN, MAX-TIME-MS."
  (or (mongodb--validate-nonnegative-time-ms max-time-ms "maxTimeMS")
      (mongodb-conn-transaction-max-commit-time-ms conn)))

(defun mongodb--commit-write-concern-unknown-result-p (response)
  "Return non-nil if RESPONSE writeConcernError means unknown commit result."
  (when-let* ((write-concern-error (cdr (assoc "writeConcernError" response))))
    (let ((code (cdr (assoc "code" write-concern-error)))
          (code-name (cdr (assoc "codeName" write-concern-error))))
      (not (or (member code mongodb--commit-non-unknown-write-concern-error-codes)
               (member code-name
                       '("UnknownReplWriteConcern"
                         "CannotSatisfyWriteConcern"
                         "UnsatisfiableWriteConcern")))))))

(defun mongodb--commit-response-unknown-result-p (conn response)
  "Return non-nil when commitTransaction RESPONSE should be labeled unknown.

Arguments: CONN, RESPONSE."
  (or (mongodb--retryable-write-server-error-p conn response)
      (= (or (cdr (assoc "code" response)) -1) 50)
      (mongodb--commit-write-concern-unknown-result-p response)))

(defun mongodb--commit-response-labels (conn response)
  "Return error labels for commitTransaction RESPONSE.

Arguments: CONN, RESPONSE."
  (let ((labels (mongodb--response-error-labels response)))
    (when (mongodb--commit-response-unknown-result-p conn response)
      (setq labels
            (mongodb--add-error-labels
             labels mongodb--unknown-transaction-commit-result-label)))
    (when (mongodb--retryable-write-server-error-p conn response)
      (setq labels
            (mongodb--add-error-labels
             labels mongodb--retryable-write-error-label)))
    labels))

(defun mongodb--commit-condition-message (condition)
  "Return primary message from CONDITION."
  (let ((data (and (consp condition)
                   (cdr condition))))
    (if (and (eq (car condition) 'mongodb-error)
             (stringp (car data)))
        (car data)
      (error-message-string condition))))

(defun mongodb--commit-condition-labels (condition)
  "Return MongoDB labels for a failed commitTransaction CONDITION."
  (mongodb--add-error-labels
   (mongodb-error-labels condition)
   mongodb--unknown-transaction-commit-result-label))

(defun mongodb--commit-response-retryable-p (conn response)
  "Return non-nil when commitTransaction RESPONSE should be retried once.

Arguments: CONN, RESPONSE."
  (or (mongodb--retryable-write-server-error-p conn response)
      (mongodb--retryable-write-concern-error-p conn response)))

(defun mongodb--transaction-abort-command (conn)
  "Return abortTransaction command for CONN."
  (let ((write-concern (mongodb-conn-transaction-write-concern conn))
        (recovery-token (mongodb-conn-transaction-recovery-token conn)))
    `(("abortTransaction" . 1)
      ,@(when write-concern
          `(("writeConcern" . ,write-concern)))
      ,@(when recovery-token
          `(("recoveryToken" . ,recovery-token))))))

(defun mongodb--abort-response-retryable-p (conn response)
  "Return non-nil when abortTransaction RESPONSE should be retried once.

Arguments: CONN, RESPONSE."
  (or (mongodb--retryable-write-server-error-p conn response)
      (mongodb--retryable-write-concern-error-p conn response)))

(defun mongodb--abort-ignored-response (response)
  "Return abortTransaction RESPONSE without surfacing command failure."
  (or response '(("ok" . 1))))

(defun mongodb--finish-transaction (conn state)
  "Move CONN transaction to terminal STATE and return CONN."
  (setf (mongodb-conn-transaction-state conn) state)
  (when (eq state 'aborted)
    (mongodb--unpin-transaction conn))
  conn)

(defun mongodb--run-commit-transaction
    (conn max-time-ms retry-attempt)
  "Run commitTransaction for CONN and return the response.
RETRY-ATTEMPT means apply commit retry writeConcern rules to the first attempt.

Arguments: CONN, MAX-TIME-MS, RETRY-ATTEMPT."
  (let ((retries 1)
        response)
    (condition-case final-error
        (catch 'done
          (while t
            (catch 'retry
              (let ((command
                     (mongodb--transaction-commit-command
                      conn max-time-ms retry-attempt)))
                (condition-case err
                    (progn
                      (setf (mongodb-conn-transaction-commit-sent conn) t)
                      (setq response
                            (mongodb--send-command-and-receive
                             conn "admin" command nil nil nil))
                      (unless (mongodb--ok-p response)
                        (if (and (> retries 0)
                                 (mongodb--commit-response-retryable-p
                                  conn response))
                            (progn
                              (setq retries (1- retries))
                              (setq retry-attempt t)
                              (condition-case _reconnect-err
                                  (mongodb--retry-transaction-control-once
                                   conn
                                   (list 'mongodb-error
                                         (mongodb--response-message response)))
                                (error
                                 (mongodb--signal-transaction-error-with-labels
                                  conn
                                  (mongodb--response-message response)
                                  (mongodb--commit-response-labels
                                   conn response))))
                              (throw 'retry nil))
                          (mongodb--signal-transaction-error-with-labels
                           conn
                           (mongodb--response-message response)
                           (mongodb--commit-response-labels conn response))))
                      (when-let* ((message
                                   (mongodb--write-error-message response)))
                        (if (and (> retries 0)
                                 (mongodb--commit-response-retryable-p
                                  conn response))
                            (progn
                              (setq retries (1- retries))
                              (setq retry-attempt t)
                              (condition-case _reconnect-err
                                  (mongodb--retry-transaction-control-once
                                   conn
                                   (list 'mongodb-error message))
                                (error
                                 (mongodb--signal-transaction-error-with-labels
                                  conn
                                  message
                                  (mongodb--commit-response-labels
                                   conn response))))
                              (throw 'retry nil))
                          (mongodb--signal-transaction-error-with-labels
                           conn
                           message
                           (mongodb--commit-response-labels conn response))))
                      (throw 'done response))
                  (error
                   (if (and (> retries 0)
                            (mongodb--network-error-p err))
                       (progn
                         (setq retries (1- retries))
                         (setq retry-attempt t)
                         (condition-case _reconnect-err
                             (mongodb--retry-transaction-control-once
                              conn err)
                           (error
                            (mongodb--signal-transaction-error-with-labels
                             conn
                             (mongodb--commit-condition-message err)
                             (mongodb--commit-condition-labels err))))
                         (throw 'retry nil))
                     (mongodb--signal-transaction-error-with-labels
                      conn
                      (mongodb--commit-condition-message err)
                      (mongodb--commit-condition-labels err)))))))))
      (error
       (mongodb--finish-transaction conn 'committed)
       (signal (car final-error) (cdr final-error))))
    (mongodb--finish-transaction conn 'committed)
    response))

(defun mongodb-commit-transaction (conn &optional max-time-ms)
  "Commit the active MongoDB transaction on CONN.
When MAX-TIME-MS is non-nil, include it in the commit command."
  (pcase (mongodb-conn-transaction-state conn)
    ('nil
     (signal 'mongodb-error
             (list "No transaction started")))
    ('aborted
     (signal 'mongodb-error
             (list "Cannot call commitTransaction after calling abortTransaction")))
    ('starting
     (mongodb--finish-transaction conn 'committed)
     '(("ok" . 1)))
    ('committed
     (if (mongodb-conn-transaction-commit-sent conn)
         (mongodb--run-commit-transaction
          conn
          (mongodb--effective-commit-max-time-ms conn max-time-ms)
          t)
       '(("ok" . 1))))
    ('in-progress
     (mongodb--run-commit-transaction
      conn
      (mongodb--effective-commit-max-time-ms conn max-time-ms)
      nil))
    (_
     (signal 'mongodb-error
             (list "No transaction started")))))

(defun mongodb-abort-transaction (conn)
  "Abort the active MongoDB transaction on CONN."
  (pcase (mongodb-conn-transaction-state conn)
    ('nil
     (signal 'mongodb-error
             (list "No transaction started")))
    ('committed
     (signal 'mongodb-error
             (list "Cannot call abortTransaction after calling commitTransaction")))
    ('aborted
     (signal 'mongodb-error
             (list "Cannot call abortTransaction twice")))
    ('starting
     (mongodb--finish-transaction conn 'aborted)
     '(("ok" . 1)))
    ('in-progress
     (let ((retries 1)
           response)
       (unwind-protect
           (catch 'done
             (while t
               (catch 'retry
                 (let ((command (mongodb--transaction-abort-command conn)))
                   (condition-case err
                       (progn
                         (setq response
                               (mongodb--send-command-and-receive
                                conn "admin" command nil nil nil))
                         (cond
                          ((and (or (not (mongodb--ok-p response))
                                    (mongodb--write-error-message response))
                                (> retries 0)
                                (mongodb--abort-response-retryable-p
                                 conn response))
                           (setq retries (1- retries))
                           (condition-case _reconnect-err
                               (mongodb--retry-transaction-control-once
                                conn
                                (list 'mongodb-error
                                      (or (mongodb--write-error-message response)
                                          (mongodb--response-message response))))
                             (error nil))
                           (throw 'retry nil))
                          (t
                           (throw 'done
                                  (mongodb--abort-ignored-response response)))))
                     (error
                      (if (and (> retries 0)
                               (mongodb--network-error-p err))
                          (progn
                            (setq retries (1- retries))
                            (condition-case _reconnect-err
                                (mongodb--retry-transaction-control-once
                                 conn err)
                              (error nil))
                            (throw 'retry nil))
                        (throw 'done
                               (mongodb--abort-ignored-response response)))))))))
         (mongodb--finish-transaction conn 'aborted))))
    (_
     (signal 'mongodb-error
             (list "No transaction started")))))

(defun mongodb-command (conn database command &optional timeout sequences)
  "Run MongoDB COMMAND on DATABASE over CONN and return the response alist.
SEQUENCES, when non-nil, is sent as OP_MSG document sequence sections."
  (when conn
    (mongodb--clear-ended-transaction-for-command conn command))
  (let* ((timeout (and conn (mongodb--command-timeout conn timeout)))
         (retryable-read (and conn
                              (mongodb--retryable-read-enabled-p conn command)))
         (retryable-write (and conn
                               (mongodb--retryable-write-enabled-p
                                conn command sequences)))
         (retries (if (or retryable-read retryable-write) 1 0))
         (txn-number (and retryable-write
                          (mongodb--next-transaction-number conn)))
        response)
    (catch 'done
      (while t
        (catch 'retry
          (condition-case err
              (progn
                (setq response
                      (mongodb--send-command-and-receive
                       conn database command timeout sequences txn-number))
                (unless (mongodb--ok-p response)
                  (let ((state-change
                         (mongodb--handle-state-change-error conn response)))
                    (when (and (mongodb--write-command-p command)
                               (eq state-change 'marked))
                      (ignore-errors
                        (mongodb-hello conn timeout)))
                    (when (eq state-change 'stale)
                      (setq retries 0))
                    (when (and (mongodb--write-command-p command)
                               (mongodb--not-writable-error-p response)
                               (not (mongodb--state-change-error-p response)))
                      (ignore-errors
                        (mongodb-hello conn timeout)))
                    (if (and (> retries 0)
                             (or (and retryable-read
                                      (mongodb--retryable-server-error-p
                                       response))
                                 (and retryable-write
                                      (mongodb--retryable-write-server-error-p
                                       conn response))))
                        (progn
                          (setq retries (1- retries))
                          (if (eq state-change 'marked)
                              (mongodb--reconnect-current-server conn)
                            (if retryable-read
                                (mongodb--retry-read-once
                                 conn
                                 (list 'mongodb-error
                                       (mongodb--response-message response)))
                              (mongodb--retry-write-once
                               conn
                               (list 'mongodb-error
                                     (mongodb--response-message response)))))
                          (throw 'retry nil))
                      (let ((labels (mongodb--response-error-labels response)))
                        (mongodb--transaction-unpin-for-labels conn labels)
                        (mongodb--signal-error-with-labels
                         (mongodb--response-message response)
                         labels)))))
                (when (and retryable-write
                           (> retries 0)
                           (mongodb--retryable-write-concern-error-p
                            conn response))
                  (setq retries (1- retries))
                  (mongodb--retry-write-once
                   conn
                   (list 'mongodb-error
                         (or (mongodb--write-error-message response)
                             (mongodb--response-message response))))
                  (throw 'retry nil))
                (when-let* ((message (and mongodb--operation-command-context
                                          (mongodb--write-command-p command)
                                          (mongodb--write-error-message response))))
                  (let ((labels (mongodb--response-error-labels response)))
                    (mongodb--transaction-unpin-for-labels conn labels)
                    (mongodb--signal-error-with-labels message labels)))
                (throw 'done response))
            (error
             (if (and (> retries 0)
                      (mongodb--network-error-p err)
                      (or retryable-read retryable-write))
                 (progn
                   (setq retries (1- retries))
                   (condition-case _reconnect-err
                       (if retryable-read
                           (mongodb--retry-read-once conn err)
                         (mongodb--retry-write-once conn err))
                     (error
                      (signal (car err) (cdr err))))
                   (throw 'retry nil))
               (if (mongodb--transaction-transient-condition-p
                    conn command err)
                   (mongodb--signal-transaction-transient-error err conn)
                 (signal (car err) (cdr err)))))))))))

(defun mongodb-command-exhaust (conn database command &optional timeout sequences)
  "Run MongoDB COMMAND with OP_MSG exhaustAllowed and return response alists.
SEQUENCES, when non-nil, is sent as OP_MSG document sequence sections.  This is
a low-level protocol helper; callers must only use it with MongoDB commands
that can legally return exhaust-style replies.

Arguments: CONN, DATABASE, COMMAND, TIMEOUT, SEQUENCES."
  (when conn
    (mongodb--clear-ended-transaction-for-command conn command))
  (mongodb--send-command-exhaust-and-receive
   conn database command
   (and conn (mongodb--command-timeout conn timeout))
   sequences))

(defun mongodb--operation-command
    (conn database command &optional timeout sequences)
  "Run COMMAND as a typed helper operation on DATABASE over CONN."
  (let ((mongodb--operation-command-context t))
    (cond
     (sequences
      (mongodb-command conn database command timeout sequences))
     (timeout
      (mongodb-command conn database command timeout))
     (t
      (mongodb-command conn database command)))))

(defun mongodb--session-supported-p (hello)
  "Return non-nil when HELLO reports logical session support."
  (numberp (cdr (assoc "logicalSessionTimeoutMinutes" hello))))

(defun mongodb--mark-connection-authenticated (conn)
  "Record that CONN has completed authentication when it is a real connection."
  (when (mongodb-conn-p conn)
    (setf (mongodb-conn-authenticate conn) t)))

(defun mongodb--initialize-session (conn hello)
  "Initialize an implicit logical session on CONN if HELLO supports sessions."
  (when (and (mongodb-conn-p conn)
             (or (mongodb-conn-load-balanced conn)
                 (mongodb--session-supported-p hello))
             (not (mongodb-conn-session-id conn)))
    (setf (mongodb-conn-session-id conn)
          (mongodb--make-session-id))))

(defun mongodb--cursor-batch (cursor key)
  "Return cursor KEY batch from CURSOR."
  (or (cdr (assoc key cursor)) nil))

(defun mongodb--cursor-id (cursor)
  "Return cursor id from CURSOR."
  (or (cdr (assoc "id" cursor)) 0))

(defun mongodb--cursor-namespace-collection (cursor database fallback)
  "Return getMore collection name for CURSOR in DATABASE.
FALLBACK is used when the server reply omits cursor namespace metadata."
  (let ((namespace (cdr (assoc "ns" cursor))))
    (if (and (stringp namespace)
             (string-prefix-p (concat database ".") namespace))
        (substring namespace (1+ (length database)))
      fallback)))

(defun mongodb--cursor-get-more-options (options)
  "Return getMore option pairs derived from cursor OPTIONS."
  (let ((pairs (mongodb--option-pairs options)))
    (delq nil
          (list
           (let ((pair (assoc "batchSize" pairs)))
             (when pair
               (cons "batchSize" (cdr pair))))
           (let ((pair (assoc "maxAwaitTimeMS" pairs)))
             (when pair
               (cons "maxAwaitTimeMS" (cdr pair))))
           (when (or (mongodb--wire-truthy-p (cdr (assoc "awaitData" pairs)))
                     (mongodb--wire-truthy-p (cdr (assoc "tailable" pairs)))
                     (mongodb--wire-truthy-p (cdr (assoc "_stopOnEmptyBatch"
                                                       pairs))))
             (cons "_stopOnEmptyBatch" t))))))

(defun mongodb-kill-cursors (conn database collection cursor-ids)
  "Kill CURSOR-IDS for COLLECTION in DATABASE on CONN."
  (when cursor-ids
    (mongodb-command
     conn database
     `(("killCursors" . ,collection)
       ("cursors" . ,(vconcat cursor-ids))))))

(defun mongodb--cursor-results
    (conn database collection response first-key
          &optional get-more-options suppress-network-error-kill)
  "Return all cursor results from RESPONSE, fetching more as needed.
GET-MORE-OPTIONS may include batchSize and maxAwaitTimeMS.  If it includes
_stopOnEmptyBatch, stop when an awaitable cursor returns an empty non-terminal
batch and close that server-side cursor.  When SUPPRESS-NETWORK-ERROR-KILL is
non-nil, do not issue killCursors after a getMore network error.

Arguments: CONN, DATABASE, COLLECTION, RESPONSE, FIRST-KEY, GET-MORE-OPTIONS,
SUPPRESS-NETWORK-ERROR-KILL."
  (let* ((get-more-options (mongodb--option-pairs get-more-options))
         (get-more-batch-size (or (cdr (assoc "batchSize" get-more-options))
                                  1000))
         (max-await-time-ms (cdr (assoc "maxAwaitTimeMS" get-more-options)))
         (stop-on-empty-batch
          (mongodb--wire-truthy-p
           (cdr (assoc "_stopOnEmptyBatch" get-more-options))))
         (cursor (cdr (assoc "cursor" response)))
         (rows (copy-sequence
                (mongodb--cursor-batch cursor first-key)))
         (cursor-id (mongodb--cursor-id cursor))
         (cursor-collection
          (mongodb--cursor-namespace-collection cursor database collection))
         close-cursor-id)
    (condition-case err
        (progn
          (while (and (integerp cursor-id)
                      (not (zerop cursor-id)))
            (setq response
                  (mongodb-command
                   conn database
                   `(("getMore" . ,cursor-id)
                     ("collection" . ,cursor-collection)
                     ("batchSize" . ,get-more-batch-size)
                     ,@(when max-await-time-ms
                         `(("maxTimeMS" . ,max-await-time-ms))))))
            (let ((batch (mongodb--cursor-batch
                          (cdr (assoc "cursor" response))
                          "nextBatch")))
              (setq cursor (cdr (assoc "cursor" response))
                    rows (append rows batch)
                    cursor-id (mongodb--cursor-id cursor)
                    cursor-collection
                    (mongodb--cursor-namespace-collection
                     cursor database cursor-collection))
              (when (and stop-on-empty-batch
                         (null batch)
                         (integerp cursor-id)
                         (not (zerop cursor-id)))
                (setq close-cursor-id cursor-id
                      cursor-id 0))))
          (when close-cursor-id
            (ignore-errors
              (mongodb-kill-cursors
               conn database cursor-collection (list close-cursor-id))))
          rows)
      (error
       (when (and (integerp cursor-id)
                  (not (zerop cursor-id))
                  (not (and suppress-network-error-kill
                            (mongodb--network-error-p err))))
         (ignore-errors
           (mongodb-kill-cursors
            conn database cursor-collection (list cursor-id))))
       (signal (car err) (cdr err))))))

(defun mongodb-list-databases (conn)
  "Return database names visible to CONN."
  (let ((response (mongodb--operation-command
                   conn "admin"
                   '(("listDatabases" . 1)))))
    (mapcar (lambda (db) (cdr (assoc "name" db)))
            (cdr (assoc "databases" response)))))

(defun mongodb-list-collection-docs
    (conn database &optional filter)
  "Return collection metadata documents for DATABASE on CONN."
  (let ((response (mongodb--operation-command
                   conn database
                   `(("listCollections" . 1)
                     ("cursor" . ,(mongodb-document nil))
                     ,@(when filter `(("filter" . ,filter)))))))
    (mongodb--cursor-results
     conn database "$cmd.listCollections" response "firstBatch")))

(defun mongodb-list-collections (conn database)
  "Return collection names for DATABASE on CONN."
  (mapcar (lambda (doc) (cdr (assoc "name" doc)))
          (mongodb-list-collection-docs conn database)))

(defun mongodb-create-collection
    (conn database collection &optional options)
  "Create COLLECTION in DATABASE on CONN.
OPTIONS is an alist or document of additional create command fields."
  (mongodb--operation-command
   conn database
   `(("create" . ,collection)
     ,@(mongodb--option-pairs options))))

(defun mongodb-list-indexes (conn database collection)
  "Return index documents for COLLECTION in DATABASE on CONN."
  (let ((response
         (mongodb--operation-command
          conn database
          `(("listIndexes" . ,collection)
            ("cursor" . ,(mongodb-document nil))))))
    (mongodb--cursor-results
     conn database collection response "firstBatch")))

(defun mongodb-find-command
    (collection &optional filter projection limit skip options)
  "Return a MongoDB find command document for COLLECTION.

Arguments: COLLECTION, FILTER, PROJECTION, LIMIT, SKIP, OPTIONS."
  (let ((option-pairs (mongodb--option-pairs options)))
    `(("find" . ,collection)
      ("filter" . ,(or filter (mongodb-document nil)))
      ("batchSize" . ,(or (cdr (assoc "batchSize" option-pairs))
                          1000))
      ,@(when projection `(("projection" . ,projection)))
      ,@(when limit `(("limit" . ,limit)))
      ,@(when skip `(("skip" . ,skip)))
      ,@(cl-remove-if (lambda (pair)
                        (member (car pair) '("batchSize" "maxAwaitTimeMS")))
                      option-pairs))))

(defun mongodb-find
    (conn database collection &optional filter projection limit skip options)
  "Return documents from COLLECTION in DATABASE on CONN.
OPTIONS is an alist of additional MongoDB find command fields."
  (let* ((option-pairs (mongodb--option-pairs options))
         (response
          (mongodb--operation-command
           conn database
           (mongodb-find-command collection filter projection limit skip
                               option-pairs))))
    (mongodb--cursor-results
     conn database collection response "firstBatch"
     (mongodb--cursor-get-more-options option-pairs))))

(defun mongodb-count-documents
    (conn database collection &optional filter options)
  "Return count for COLLECTION in DATABASE on CONN."
  (let ((response
         (mongodb--operation-command
          conn database
          `(("count" . ,collection)
            ,@(when filter `(("query" . ,filter)))
            ,@(mongodb--option-pairs options)))))
    (cdr (assoc "n" response))))

(defun mongodb-distinct
    (conn database collection field &optional filter options)
  "Return distinct FIELD values for COLLECTION in DATABASE on CONN."
  (let ((response
         (mongodb--operation-command
          conn database
          `(("distinct" . ,collection)
            ("key" . ,field)
            ,@(when filter `(("query" . ,filter)))
            ,@(mongodb--option-pairs options)))))
    (cdr (assoc "values" response))))

(defun mongodb--cursor-option (options)
  "Return the MongoDB cursor option document from OPTIONS."
  (let* ((option-pairs (mongodb--option-pairs options))
         (cursor (cdr (assoc "cursor" option-pairs)))
         (batch-size (cdr (assoc "batchSize" option-pairs))))
    (or cursor
        (and batch-size
             (mongodb-document `(("batchSize" . ,batch-size))))
        (mongodb-document nil))))

(defun mongodb-aggregate-command (collection pipeline &optional options)
  "Return a MongoDB aggregate command document for COLLECTION and PIPELINE.
OPTIONS is an alist or document of additional aggregate command fields.
The convenience option field batchSize is translated into cursor.batchSize."
  (let* ((option-pairs (mongodb--option-pairs options))
         (extra (mongodb--remove-option-pairs '("cursor" "batchSize")
                                            option-pairs)))
    `(("aggregate" . ,collection)
      ("pipeline" . ,pipeline)
      ("cursor" . ,(mongodb--cursor-option options))
      ,@extra)))

(defun mongodb-aggregate
    (conn database collection pipeline &optional options)
  "Return aggregation results for COLLECTION in DATABASE on CONN.
OPTIONS is an alist or document of additional aggregate command fields.
The convenience option field batchSize is translated into cursor.batchSize."
  (let* ((option-pairs (mongodb--option-pairs options))
         (response
          (mongodb--operation-command
           conn database
           (mongodb-aggregate-command collection pipeline option-pairs))))
    (mongodb--cursor-results
     conn database collection response "firstBatch"
     (mongodb--cursor-get-more-options option-pairs))))

(defun mongodb-aggregate-database (conn database pipeline &optional options)
  "Return database-level aggregation results for DATABASE on CONN.
This is the protocol equivalent of mongosh `db.aggregate'.  PIPELINE should
start with a stage that does not require an underlying collection."
  (let* ((option-pairs (mongodb--option-pairs options))
         (response
          (mongodb--operation-command
           conn database
           (mongodb-aggregate-command 1 pipeline option-pairs))))
    (mongodb--cursor-results
     conn database "$cmd.aggregate" response "firstBatch"
     (mongodb--cursor-get-more-options option-pairs))))

(defconst mongodb--change-stream-option-keys
  '("resumeAfter" "startAfter" "fullDocument" "fullDocumentBeforeChange"
    "showExpandedEvents" "startAtOperationTime")
  "MongoDB watch() option names that belong in the $changeStream stage.")

(defconst mongodb--watch-command-option-keys
  '("batchSize" "collation" "comment" "maxTimeMS")
  "MongoDB watch() option names that belong on the aggregate command.")

(defun mongodb--change-stream-stage-options (options)
  "Return the $changeStream stage option document from OPTIONS."
  (mongodb-document
   (cl-remove-if-not
    (lambda (pair)
      (member (car pair) mongodb--change-stream-option-keys))
    (mongodb--option-pairs options))))

(defun mongodb--watch-command-options (options)
  "Return aggregate command options derived from watch OPTIONS."
  (cl-remove-if-not
   (lambda (pair)
     (member (car pair) mongodb--watch-command-option-keys))
   (mongodb--option-pairs options)))

(defun mongodb--watch-get-more-options (options)
  "Return getMore options derived from watch OPTIONS."
  (append (mongodb--cursor-get-more-options options)
          '(("_stopOnEmptyBatch" . t))))

(defun mongodb--watch-pipeline (pipeline options)
  "Return a change-stream aggregate pipeline from PIPELINE and OPTIONS."
  (vconcat
   (vector (mongodb-document
            (list (cons "$changeStream"
                        (mongodb--change-stream-stage-options options)))))
   (or pipeline [])))

(defun mongodb-watch-command (collection &optional pipeline options)
  "Return a MongoDB aggregate command that opens a change stream.
COLLECTION may be a collection name or 1 for database-level watches.

Arguments: COLLECTION, PIPELINE, OPTIONS."
  (mongodb-aggregate-command
   collection
   (mongodb--watch-pipeline pipeline options)
   (mongodb--watch-command-options options)))

(defun mongodb-watch
    (conn database collection &optional pipeline options)
  "Open a collection change stream and return available events.
Clutch consumes a finite batch rather than returning a live cursor object: once
an empty await batch is observed, the server cursor is closed.

Arguments: CONN, DATABASE, COLLECTION, PIPELINE, OPTIONS."
  (let* ((option-pairs (mongodb--option-pairs options))
         (response
          (mongodb--operation-command
           conn database
           (mongodb-watch-command collection pipeline option-pairs))))
    (mongodb--cursor-results
     conn database collection response "firstBatch"
     (mongodb--watch-get-more-options option-pairs))))

(defun mongodb-watch-database
    (conn database &optional pipeline options)
  "Open a database-level change stream and return available events.
This is the protocol equivalent of mongosh `db.watch'.

Arguments: CONN, DATABASE, PIPELINE, OPTIONS."
  (let* ((option-pairs (mongodb--option-pairs options))
         (response
          (mongodb--operation-command
           conn database
           (mongodb-watch-command 1 pipeline option-pairs))))
    (mongodb--cursor-results
     conn database "$cmd.aggregate" response "firstBatch"
     (mongodb--watch-get-more-options option-pairs))))

(defun mongodb--explain-verbosity (verbosity)
  "Return MongoDB explain VERBOSITY normalized from shell-style values."
  (cond
   ((null verbosity) nil)
   ((eq verbosity t) "allPlansExecution")
   ((eq verbosity :false) "queryPlanner")
   (t verbosity)))

(defun mongodb-explain (conn database command &optional verbosity)
  "Explain MongoDB COMMAND on DATABASE over CONN.
VERBOSITY may be nil, a MongoDB verbosity string, t, or :false.  Boolean
values follow mongosh compatibility rules."
  (let ((verbosity (mongodb--explain-verbosity verbosity)))
    (mongodb--operation-command
     conn database
     `(("explain" . ,(mongodb-document command))
       ,@(when verbosity
           `(("verbosity" . ,verbosity)))))))

(defun mongodb-insert
    (conn database collection documents &optional ordered)
  "Insert DOCUMENTS into COLLECTION in DATABASE on CONN."
  (let ((docs (mongodb--insert-documents-with-generated-ids documents))
        (command `(("insert" . ,collection)
                   ("ordered" . ,(if (eq ordered :false) :false t))))
        (response nil))
    (let ((mongodb--retryable-write-context t))
      (dolist (batch (mongodb--insert-document-batches
                      conn database command docs))
        (setq response
              (mongodb--operation-command
               conn database
               command
               nil
               `(("documents" . ,batch))))))
    response))

(defun mongodb-delete
    (conn database collection filter &optional limit)
  "Delete documents from COLLECTION in DATABASE on CONN."
  (let ((deletes (vector
                  `(("q" . ,(or filter
                                (mongodb-document nil)))
                    ("limit" . ,(or limit 0))))))
    (let ((mongodb--retryable-write-context t))
      (mongodb--operation-command
       conn database
       `(("delete" . ,collection))
       nil
       `(("deletes" . ,deletes))))))

(defun mongodb--bulk-write-operation-p (value)
  "Return non-nil when VALUE is one bulkWrite operation document."
  (and (mongodb--document-value-p value)
       (let ((pairs (mongodb--document-pairs value)))
         (or (assoc "insert" pairs)
             (assoc "update" pairs)
             (assoc "delete" pairs)))))

(defun mongodb--bulk-write-operations-list (operations)
  "Return MongoDB bulkWrite OPERATIONS as a non-empty list."
  (let ((ops (cond
              ((null operations) nil)
              ((vectorp operations) (append operations nil))
              ((mongodb--bulk-write-operation-p operations)
               (list operations))
              ((listp operations) operations)
              (t (list operations)))))
    (unless ops
      (signal 'mongodb-error
              (list "MongoDB bulkWrite requires at least one operation")))
    ops))

(defun mongodb--bulk-write-namespace (operation)
  "Return the namespace string from bulkWrite OPERATION."
  (let* ((pairs (mongodb--document-pairs operation))
         (value (or (cdr (assoc "insert" pairs))
                    (cdr (assoc "update" pairs))
                    (cdr (assoc "delete" pairs)))))
    (unless (and (stringp value)
                 (string-match-p "\\`[^.]+\\..+\\'" value))
      (signal 'mongodb-error
              (list (format "MongoDB bulkWrite operation requires a namespace like database.collection, got %S"
                            value))))
    value))

(defun mongodb--bulk-write-op-kind (operation)
  "Return the bulkWrite operation kind for OPERATION."
  (let* ((pairs (mongodb--document-pairs operation))
         (kinds (delq nil
                      (list (and (assoc "insert" pairs) "insert")
                            (and (assoc "update" pairs) "update")
                            (and (assoc "delete" pairs) "delete")))))
    (unless (= (length kinds) 1)
      (signal 'mongodb-error
              (list "MongoDB bulkWrite operation must contain exactly one of insert, update, or delete")))
    (car kinds)))

(defun mongodb--bulk-write-namespace-index (namespace namespaces)
  "Return zero-based index for NAMESPACE, adding it to NAMESPACES if needed."
  (let ((existing (assoc namespace (cdr namespaces))))
    (if existing
        (cdr existing)
      (let ((index (length (cdr namespaces))))
        (setcdr namespaces
                (append (cdr namespaces)
                        (list (cons namespace index))))
        index))))

(defun mongodb--bulk-write-op-document (operation namespaces)
  "Return one server-format bulkWrite op from OPERATION and NAMESPACES."
  (let* ((pairs (mongodb--document-pairs operation))
         (kind (mongodb--bulk-write-op-kind operation))
         (namespace (mongodb--bulk-write-namespace operation))
         (namespace-index
          (mongodb--bulk-write-namespace-index namespace namespaces))
         (extra (cl-remove-if (lambda (pair)
                                (member (car pair)
                                        '("insert" "update" "delete")))
                              pairs)))
    (when (and (equal kind "insert")
               (not (assoc "document" extra)))
      (signal 'mongodb-error
              (list "MongoDB bulkWrite insert operation requires document")))
    (append (list (cons kind namespace-index))
            (if (and (equal kind "insert")
                     (assoc "document" extra))
                (mongodb--document-set-field
                 extra
                 "document"
                 (mongodb--document-with-generated-id
                  (cdr (assoc "document" extra))))
              extra))))

(defun mongodb--bulk-write-ns-info (namespaces)
  "Return bulkWrite nsInfo sequence from NAMESPACES."
  (vconcat
   (mapcar (lambda (entry)
             `(("ns" . ,(car entry))))
           (cdr namespaces))))

(defun mongodb--bulk-write-option (pairs name)
  "Return option NAME from PAIRS."
  (cdr (assoc name pairs)))

(defun mongodb--bulk-write-command-document (options)
  "Return the MongoDB bulkWrite command document for OPTIONS."
  (let* ((pairs (mongodb--option-pairs options))
         (ordered-pair (assoc "ordered" pairs))
         (verbose-pair (assoc "verboseResults" pairs))
         (ordered (if ordered-pair
                      (if (mongodb--wire-truthy-p (cdr ordered-pair)) t :false)
                    t))
         (verbose (and verbose-pair
                       (mongodb--wire-truthy-p (cdr verbose-pair))))
         (errors-only (if verbose :false t))
         (extra (mongodb--remove-option-pairs
                 '("ordered" "verboseResults" "errorsOnly")
                 pairs)))
    (append `(("bulkWrite" . 1)
              ("ordered" . ,ordered)
              ("errorsOnly" . ,errors-only))
            extra)))

(defun mongodb--bulk-write-count-fields ()
  "Return numeric bulkWrite response counter field names."
  '("nErrors" "nInserted" "nMatched" "nModified" "nDeleted" "nUpserted"))

(defun mongodb--bulk-write-ordered-p (command)
  "Return non-nil when bulkWrite COMMAND is ordered."
  (mongodb--wire-truthy-p (mongodb--document-field command "ordered")))

(defun mongodb--bulk-write-validate-write-concern
    (conn command verbose-results)
  "Signal when bulkWrite COMMAND uses invalid unacknowledged write concern.

Arguments: CONN, COMMAND, VERBOSE-RESULTS."
  (let ((write-concern (mongodb--write-concern-value conn command))
        (ordered (mongodb--wire-truthy-p
                  (mongodb--document-field command "ordered"))))
    (when (and (mongodb--unacknowledged-write-concern-p write-concern)
               (or ordered verbose-results))
      (signal 'mongodb-error
              (list "MongoDB bulkWrite with unacknowledged write concern requires ordered=false and verboseResults=false")))))

(defun mongodb--bulk-write-batch-command (operations options)
  "Return one bulkWrite (COMMAND . SEQUENCES) batch for OPERATIONS.

Arguments: OPERATIONS, OPTIONS."
  (let ((namespaces (list nil))
        (ops nil))
    (dolist (operation operations)
      (push (mongodb--bulk-write-op-document operation namespaces)
            ops))
    (cons (mongodb--bulk-write-command-document options)
          `(("ops" . ,(vconcat (nreverse ops)))
            ("nsInfo" . ,(mongodb--bulk-write-ns-info namespaces))))))

(defun mongodb--bulk-write-message-size (conn command sequences)
  "Return bulkWrite COMMAND and SEQUENCES OP_MSG size for CONN.
The size is measured without later command-agnostic fields such as $db or lsid,
matching the bulkWrite batching rule."
  (let ((max-message (mongodb--max-message-size-bytes conn)))
    (cl-letf (((symbol-function 'mongodb--max-message-size-bytes)
               (lambda (_conn) max-message)))
      (mongodb--validate-op-msg-size conn command sequences))))

(defun mongodb--bulk-write-batch-within-budget-p
    (conn command sequences)
  "Return non-nil when bulkWrite COMMAND and SEQUENCES fit one batch.

Arguments: CONN, COMMAND, SEQUENCES."
  (<= (mongodb--bulk-write-message-size conn command sequences)
      (- (mongodb--max-message-size-bytes conn)
         mongodb--write-batch-message-safety-bytes)))

(defun mongodb--bulk-write-batch-entry
    (start operations options)
  "Return one bulkWrite batch entry from START, OPERATIONS, and OPTIONS."
  (let ((command-and-sequences
         (mongodb--bulk-write-batch-command operations options)))
    (list :start start
          :count (length operations)
          :command (car command-and-sequences)
          :sequences (cdr command-and-sequences))))

(defun mongodb--bulk-write-batches (conn operations options)
  "Return bulkWrite batches for OPERATIONS respecting CONN limits."
  (let* ((max-count (mongodb--max-write-batch-size conn))
         (remaining operations)
         (start 0)
         batches)
    (while remaining
      (let ((current nil)
            (current-count 0))
        (catch 'batch-full
          (while (and remaining
                      (< current-count max-count))
            (let* ((candidate (append current (list (car remaining))))
                   (command-and-sequences
                    (mongodb--bulk-write-batch-command candidate options))
                   (command (car command-and-sequences))
                   (sequences (cdr command-and-sequences))
                   (fits (mongodb--bulk-write-batch-within-budget-p
                          conn command sequences)))
              (cond
               (fits
                (setq current candidate)
                (setq current-count (1+ current-count))
                (setq remaining (cdr remaining)))
               ((null current)
                (signal 'mongodb-error
                        (list "MongoDB bulkWrite operation exceeds maxMessageSizeBytes batch budget")))
               (t
                (throw 'batch-full nil))))))
        (push (mongodb--bulk-write-batch-entry
               start current options)
              batches)
        (setq start (+ start (length current)))))
    (nreverse batches)))

(defun mongodb-bulk-write-command (operations &optional options)
  "Return (COMMAND . SEQUENCES) for MongoDB client-level bulkWrite.
OPERATIONS is a list or vector of operation documents.  Each operation names an
insert, update, or delete namespace plus the command fields for that operation.
OPTIONS is a MongoDB command option document."
  (mongodb--bulk-write-batch-command
   (mongodb--bulk-write-operations-list operations)
   options))

(defun mongodb--bulk-write-adjust-result-index (result offset)
  "Return bulkWrite RESULT with idx adjusted by OFFSET."
  (if (and offset
           (not (zerop offset))
           (assoc "idx" (mongodb--document-pairs result)))
      (mongodb--document-set-field
       (copy-sequence (mongodb--document-pairs result))
       "idx"
       (+ offset (cdr (assoc "idx" (mongodb--document-pairs result)))))
    result))

(defun mongodb--bulk-write-accumulate-counts (counts response)
  "Accumulate bulkWrite numeric counters from RESPONSE into COUNTS."
  (dolist (field (mongodb--bulk-write-count-fields))
    (when-let* ((value (cdr (assoc field response))))
      (setf (alist-get field counts nil nil #'equal)
            (+ (or (alist-get field counts nil nil #'equal) 0)
               value))))
  counts)

(defun mongodb-bulk-write
    (conn operations &optional options timeout)
  "Run a MongoDB client-level bulkWrite on CONN.
The command is sent to admin using OP_MSG document sequences for ops and
nsInfo.  The returned response includes a \"results\" vector containing all
cursor result documents.

Arguments: CONN, OPERATIONS, OPTIONS, TIMEOUT."
  (let* ((operations (mongodb--bulk-write-operations-list operations))
         (command (mongodb--bulk-write-command-document options))
         (verbose-results
          (mongodb--wire-truthy-p
           (mongodb--bulk-write-option
            (mongodb--option-pairs options)
            "verboseResults")))
         (ordered (mongodb--bulk-write-ordered-p command))
	 (batches (mongodb--bulk-write-batches conn operations options))
	 counts
	 results
	 last-response
	 stop
	 (operation-id (mongodb--next-command-operation-id)))
    (mongodb--bulk-write-validate-write-concern
     conn command verbose-results)
    (let ((mongodb--command-operation-id operation-id))
      (dolist (batch batches)
	(unless stop
	  (let* ((batch-start (plist-get batch :start))
		 (batch-command (plist-get batch :command))
		 (batch-sequences (plist-get batch :sequences))
		 (response
		  (mongodb--operation-command
		   conn "admin" batch-command timeout batch-sequences))
		 (batch-results
		  (mongodb--cursor-results
		   conn "admin" "$cmd.bulkWrite" response "firstBatch")))
	    (setq last-response response)
	    (setq counts (mongodb--bulk-write-accumulate-counts counts response))
	    (setq results
		  (append results
			  (mapcar (lambda (result)
				    (mongodb--bulk-write-adjust-result-index
				     result batch-start))
				  batch-results)))
	    (when (and ordered
		       (> (or (cdr (assoc "nErrors" response)) 0) 0))
	      (setq stop t))))))
    (append (cl-remove-if
	     (lambda (pair)
	       (member (car pair) (mongodb--bulk-write-count-fields)))
             (or last-response '(("ok" . 1))))
            counts
            `(("results" . ,(vconcat results))))))

(defun mongodb--option-pairs (options)
  "Return MongoDB command option pairs from OPTIONS."
  (if options
      (mongodb--document-pairs options)
    nil))

(defun mongodb--remove-option-pairs (keys pairs)
  "Return PAIRS without any entry whose car is in KEYS."
  (cl-remove-if (lambda (pair)
                  (member (car pair) keys))
                pairs))

(defun mongodb--index-name (keys)
  "Return a MongoDB index name for key document KEYS."
  (mapconcat
   (lambda (pair)
     (format "%s_%s" (car pair) (cdr pair)))
   (mongodb--document-pairs keys)
   "_"))

(defun mongodb-create-index
    (conn database collection keys &optional options)
  "Create one index with KEYS on COLLECTION in DATABASE on CONN."
  (let* ((option-pairs (mongodb--option-pairs options))
         (name (or (cdr (assoc "name" option-pairs))
                   (mongodb--index-name keys)))
         (extra (mongodb--remove-option-pairs '("key" "name")
                                            option-pairs)))
    (mongodb--operation-command
     conn database
     `(("createIndexes" . ,collection)
       ("indexes" . ,(vector
                      (append
                       `(("key" . ,keys)
                         ("name" . ,name))
                       extra)))))))

(defun mongodb-drop-index (conn database collection index)
  "Drop INDEX from COLLECTION in DATABASE on CONN."
  (mongodb--operation-command
   conn database
   `(("dropIndexes" . ,collection)
     ("index" . ,index))))

(defun mongodb-update
    (conn database collection filter update &optional multi options)
  "Update documents in COLLECTION in DATABASE on CONN.
FILTER is the update query, UPDATE is an update document or pipeline, MULTI
controls whether more than one document may be updated, and OPTIONS is a
MongoDB options document."
  (let* ((option-pairs (mongodb--option-pairs options))
         (upsert (cdr (assoc "upsert" option-pairs)))
         (extra (mongodb--remove-option-pairs '("upsert" "multi")
                                            option-pairs)))
    (let ((updates
           (vector
            (append
             `(("q" . ,(or filter (mongodb-document nil)))
               ("u" . ,update)
               ("multi" . ,(if multi t :false)))
             (when upsert
               `(("upsert" . ,upsert)))
             extra))))
      (let ((mongodb--retryable-write-context t))
        (mongodb--operation-command
         conn database
         `(("update" . ,collection))
         nil
         `(("updates" . ,updates)))))))

(defun mongodb--find-and-modify-new-value (options)
  "Return the findAndModify `new' value derived from OPTIONS."
  (cond
   ((assoc "new" options)
    (cdr (assoc "new" options)))
   ((assoc "returnNewDocument" options)
    (cdr (assoc "returnNewDocument" options)))
   ((assoc "returnDocument" options)
    (let ((value (cdr (assoc "returnDocument" options))))
      (if (and (stringp value)
               (string= (downcase value) "after"))
          t
        :false)))
   (t nil)))

(defun mongodb-find-and-modify
    (conn database collection filter &optional update remove options)
  "Run findAndModify on COLLECTION in DATABASE on CONN.
FILTER is the query document.  UPDATE is an update/replacement value unless
REMOVE is non-nil.  OPTIONS is a MongoDB options document."
  (let* ((option-pairs (mongodb--option-pairs options))
         (projection (or (cdr (assoc "projection" option-pairs))
                         (cdr (assoc "fields" option-pairs))))
         (new (mongodb--find-and-modify-new-value option-pairs))
         (extra (mongodb--remove-option-pairs
                 '("projection" "fields" "new" "returnNewDocument"
                   "returnDocument")
                 option-pairs)))
    (let ((mongodb--retryable-write-context t))
      (mongodb--operation-command
       conn database
       (append
        `(("findAndModify" . ,collection)
          ("query" . ,(or filter (mongodb-document nil))))
        (if remove
            '(("remove" . t))
          `(("update" . ,update)))
        (when projection
          `(("fields" . ,projection)))
        (when new
          `(("new" . ,new)))
        extra)))))

(defun mongodb-drop-collection (conn database collection)
  "Drop COLLECTION in DATABASE on CONN."
  (mongodb--operation-command
   conn database
   `(("drop" . ,collection))))

(defun mongodb-drop-database (conn database)
  "Drop DATABASE on CONN."
  (mongodb--operation-command
   conn database
   '(("dropDatabase" . 1))))

;;;; Lifecycle

(defun mongodb--tls-available-p ()
  "Return non-nil when GnuTLS is available."
  (and (fboundp 'gnutls-available-p)
       (gnutls-available-p)))

(defun mongodb--upgrade-to-tls (proc host params timeout)
  "Upgrade PROC to TLS for HOST using PARAMS within TIMEOUT seconds."
  (unless (mongodb--tls-available-p)
    (signal 'mongodb-error
            (list "Native MongoDB TLS requires GnuTLS support in Emacs")))
  (let ((spec (mongodb--params-tls-spec params host)))
    (when spec
      (condition-case err
          (with-timeout (timeout
                         (signal 'mongodb-error
                                 (list "Timed out negotiating MongoDB TLS")))
            (apply #'gnutls-negotiate
                   (append (list :process proc
                                 :type 'gnutls-x509pki)
                           spec)))
        (gnutls-error
         (signal 'mongodb-error
                 (list (format "MongoDB TLS negotiation failed: %s"
                               (error-message-string err)))))))))

(defun mongodb--local-socket-endpoint-p (host port)
  "Return non-nil when HOST and PORT name a UNIX-domain socket endpoint."
  (and (null port)
       (stringp host)
       (file-name-absolute-p host)))

(defun mongodb--make-network-process (buffer host port)
  "Open a MongoDB network process for BUFFER, HOST, and PORT."
  (if (mongodb--local-socket-endpoint-p host port)
      (make-network-process
       :name "mongodb"
       :buffer buffer
       :family 'local
       :service host
       :coding 'binary
       :filter-multibyte nil
       :noquery t)
    (make-network-process
     :name "mongodb"
     :buffer buffer
     :host host
     :service port
     :coding 'binary
     :filter-multibyte nil
     :noquery t)))

(defun mongodb--process-read-bytes (proc buffer count timeout context)
  "Read COUNT bytes from PROC BUFFER within TIMEOUT for CONTEXT."
  (let ((conn (make-mongodb-conn :process proc
                               :buffer buffer
                               :socket-timeout timeout
                               :closed nil)))
    (condition-case err
        (progn
          (mongodb--wait-for-bytes conn count timeout)
          (with-current-buffer buffer
            (prog1 (buffer-substring-no-properties
                    (point-min)
                    (+ (point-min) count))
              (delete-region (point-min) (+ (point-min) count)))))
      (mongodb-error
       (signal 'mongodb-error
               (list (format "%s: %s"
                             context
                             (error-message-string err))))))))

(defun mongodb--socks5-reply-message (code)
  "Return a readable SOCKS5 reply message for CODE."
  (cdr (assoc code
              '((0 . "succeeded")
                (1 . "general failure")
                (2 . "connection not allowed by ruleset")
                (3 . "network unreachable")
                (4 . "host unreachable")
                (5 . "connection refused")
                (6 . "TTL expired")
                (7 . "command not supported")
                (8 . "address type not supported")))))

(defun mongodb--socks5-send (proc data)
  "Send SOCKS5 DATA to PROC."
  (process-send-string proc (mongodb--byte-string data)))

(defun mongodb--socks5-auth-methods (proxy)
  "Return SOCKS5 auth method bytes for PROXY."
  (if (plist-get proxy :username)
      (unibyte-string #x00 #x02)
    (unibyte-string #x00)))

(defun mongodb--socks5-username-password-auth (proc buffer proxy timeout)
  "Authenticate SOCKS5 PROC with username/password PROXY credentials.

Arguments: PROC, BUFFER, PROXY, TIMEOUT."
  (let* ((username (mongodb--utf8-bytes (plist-get proxy :username)))
         (password (mongodb--utf8-bytes (plist-get proxy :password)))
         (reply nil))
    (mongodb--socks5-send
     proc
     (concat (unibyte-string #x01
                             (length username))
             username
             (unibyte-string (length password))
             password))
    (setq reply
          (mongodb--process-read-bytes
           proc buffer 2 timeout "MongoDB SOCKS5 username/password auth"))
    (unless (= (aref reply 0) #x01)
      (signal 'mongodb-error
              (list (format "MongoDB SOCKS5 auth returned unexpected version: %s"
                            (aref reply 0)))))
    (unless (= (aref reply 1) #x00)
      (signal 'mongodb-error
              (list "MongoDB SOCKS5 username/password authentication failed")))))

(defun mongodb--socks5-connect-request (host port)
  "Return SOCKS5 CONNECT request bytes for MongoDB HOST and PORT."
  (let ((host-bytes (mongodb--utf8-bytes host)))
    (unless (and (integerp port)
                 (> port 0)
                 (<= port 65535))
      (signal 'mongodb-error
              (list "MongoDB SOCKS5 target port must be between 1 and 65535")))
    (when (> (length host-bytes) 255)
      (signal 'mongodb-error
              (list "MongoDB SOCKS5 target host cannot exceed 255 UTF-8 bytes")))
    (concat (unibyte-string #x05 #x01 #x00 #x03
                            (length host-bytes))
            host-bytes
            (mongodb--pack-uint16-be port))))

(defun mongodb--socks5-read-reply (proc buffer timeout)
  "Read and validate a SOCKS5 CONNECT reply from PROC BUFFER.

Arguments: PROC, BUFFER, TIMEOUT."
  (let* ((header (mongodb--process-read-bytes
                  proc buffer 4 timeout "MongoDB SOCKS5 CONNECT reply"))
         (version (aref header 0))
         (reply-code (aref header 1))
         (reserved (aref header 2))
         (address-type (aref header 3)))
    (unless (= version #x05)
      (signal 'mongodb-error
              (list (format "MongoDB SOCKS5 CONNECT returned unexpected version: %s"
                            version))))
    (unless (= reserved #x00)
      (signal 'mongodb-error
              (list "MongoDB SOCKS5 CONNECT reply reserved byte is invalid")))
    (pcase address-type
      (#x01
       (mongodb--process-read-bytes
        proc buffer 6 timeout "MongoDB SOCKS5 IPv4 bind address"))
      (#x03
       (let* ((length-byte (mongodb--process-read-bytes
                            proc buffer 1 timeout
                            "MongoDB SOCKS5 domain bind address length"))
              (length (aref length-byte 0)))
         (mongodb--process-read-bytes
          proc buffer (+ length 2) timeout
          "MongoDB SOCKS5 domain bind address")))
      (#x04
       (mongodb--process-read-bytes
        proc buffer 18 timeout "MongoDB SOCKS5 IPv6 bind address"))
      (_
       (signal 'mongodb-error
               (list (format "MongoDB SOCKS5 CONNECT returned unknown address type: %s"
                             address-type)))))
    (unless (= reply-code #x00)
      (signal 'mongodb-error
              (list (format "MongoDB SOCKS5 CONNECT failed: %s"
                            (or (mongodb--socks5-reply-message reply-code)
                                (format "reply code %s" reply-code))))))))

(defun mongodb--socks5-connect (proc buffer host port proxy timeout)
  "Open a SOCKS5 tunnel over PROC to MongoDB HOST and PORT using PROXY.

Arguments: PROC, BUFFER, HOST, PORT, PROXY, TIMEOUT."
  (let* ((methods (mongodb--socks5-auth-methods proxy))
         (reply nil))
    (mongodb--socks5-send
     proc
     (concat (unibyte-string #x05 (length methods))
             methods))
    (setq reply
          (mongodb--process-read-bytes
           proc buffer 2 timeout "MongoDB SOCKS5 greeting"))
    (unless (= (aref reply 0) #x05)
      (signal 'mongodb-error
              (list (format "MongoDB SOCKS5 greeting returned unexpected version: %s"
                            (aref reply 0)))))
    (pcase (aref reply 1)
      (#x00 nil)
      (#x02
       (unless (plist-get proxy :username)
         (signal 'mongodb-error
                 (list "MongoDB SOCKS5 proxy requested username/password authentication but no proxyUsername was configured")))
       (mongodb--socks5-username-password-auth proc buffer proxy timeout))
      (#xff
       (signal 'mongodb-error
               (list "MongoDB SOCKS5 proxy has no acceptable authentication method")))
      (method
       (signal 'mongodb-error
               (list (format "MongoDB SOCKS5 proxy selected unsupported authentication method: %s"
                             method)))))
    (mongodb--socks5-send
     proc
     (mongodb--socks5-connect-request host port))
    (mongodb--socks5-read-reply proc buffer timeout)))

(defun mongodb--send-initial-handshake
    (conn credential compressors server-api load-balanced speculative-auth
          app-name)
  "Send the initial MongoDB handshake and return the hello response.

Arguments: CONN, CREDENTIAL, COMPRESSORS, SERVER-API, LOAD-BALANCED,
SPECULATIVE-AUTH, APP-NAME."
  (let ((command (mongodb--initial-handshake-command
                  credential compressors server-api load-balanced
                  speculative-auth app-name)))
    (if (or server-api load-balanced)
        (let ((request-id
               (mongodb--send-document
                conn
                (mongodb--command-with-db command "admin" server-api))))
          (mongodb--recv-message conn nil request-id))
      (let ((request-id (mongodb--send-handshake conn command)))
        (mongodb--recv-handshake-message conn nil request-id)))))

(defun mongodb--connect-endpoint (params host port database credential
                                       &optional authenticate)
  "Open one MongoDB endpoint from PARAMS and return (CONN . HELLO).
HOST, PORT, and DATABASE identify the endpoint.  CREDENTIAL is used for
handshake negotiation.  When AUTHENTICATE is non-nil, authenticate CONN before
returning."
  (let ((buffer (generate-new-buffer " *mongodb*"))
        (timeout (mongodb--params-connect-timeout params))
        (compressors (mongodb--params-compressors params))
        (server-api (mongodb--params-server-api params))
        (read-preference (mongodb--params-read-preference params))
        (read-concern (mongodb--params-read-concern params))
        (write-concern (mongodb--params-write-concern params))
        (load-balanced (mongodb--params-load-balanced-p params))
        (app-name (mongodb--params-app-name params))
        (socket-timeout (mongodb--params-socket-timeout params))
        (operation-timeout (mongodb--params-operation-timeout params))
        (local-threshold (mongodb--params-local-threshold params))
        (heartbeat-frequency (mongodb--params-heartbeat-frequency params))
        (server-monitoring-mode
         (mongodb--params-server-monitoring-mode params))
        (proxy (mongodb--params-proxy params))
        (speculative-auth (and authenticate
                               (mongodb--speculative-auth-state credential)))
        (phase 'preflight)
        proc conn)
    (with-current-buffer buffer
      (set-buffer-multibyte nil))
    (condition-case err
        (progn
          (when (and (mongodb--local-socket-endpoint-p host port)
                     (mongodb--params-tls-enabled-p params))
            (signal 'mongodb-error
                    (list "Native MongoDB TLS is not supported over UNIX-domain sockets")))
          (when (and proxy
                     (mongodb--local-socket-endpoint-p host port))
            (signal 'mongodb-error
                    (list "Native MongoDB SOCKS5 proxy is not supported over UNIX-domain sockets")))
          (setq phase 'socket)
          (setq proc
                (with-timeout (timeout
                               (signal 'mongodb-error
                                       (list "Timed out connecting to MongoDB")))
                  (if proxy
                      (mongodb--make-network-process
                       buffer
                       (plist-get proxy :host)
                       (plist-get proxy :port))
                    (mongodb--make-network-process buffer host port))))
          (set-process-coding-system proc 'binary 'binary)
          (when proxy
            (setq phase 'socks5)
            (mongodb--socks5-connect proc buffer host port proxy timeout))
          (when (mongodb--params-tls-enabled-p params)
            (setq phase 'tls)
            (mongodb--upgrade-to-tls proc host params timeout)
            (set-process-coding-system proc 'binary 'binary))
          (setq conn
                (make-mongodb-conn
                 :params (copy-sequence params)
                 :credential credential
                 :authenticate authenticate
                 :process proc
                 :buffer buffer
                 :host host
                 :port port
                 :database database
                 :socket-timeout socket-timeout
                 :operation-timeout operation-timeout
                 :local-threshold local-threshold
                 :heartbeat-frequency heartbeat-frequency
                 :server-monitoring-mode server-monitoring-mode
                 :retry-reads (mongodb--params-retry-reads-p params)
                 :retry-writes (mongodb--params-retry-writes-p params)
                 :request-id 0
                 :txn-number 0
                 :closed nil))
          (let* ((handshake-start (float-time))
                 (hello (progn
                          (setq phase 'hello)
                          (mongodb--send-initial-handshake
                           conn credential compressors server-api
                           load-balanced speculative-auth app-name)))
                 (handshake-rtt (- (float-time) handshake-start))
                 (max-wire (or (cdr (assoc "maxWireVersion" hello)) 0))
                 (negotiated-compressors
                  (mongodb--negotiated-compressors
                   compressors
                   (cdr (assoc "compression" hello))))
                 (service-id (cdr (assoc "serviceId" hello))))
            (setq phase 'post-hello)
            (setf (mongodb-conn-max-wire-version conn)
                  max-wire)
            (mongodb--apply-hello-limits conn hello)
            (setf (mongodb-conn-compressors conn)
                  negotiated-compressors)
            (setf (mongodb-conn-server-api conn)
                  server-api)
            (setf (mongodb-conn-read-preference conn)
                  read-preference)
            (setf (mongodb-conn-read-concern conn)
                  read-concern)
            (setf (mongodb-conn-write-concern conn)
                  write-concern)
            (setf (mongodb-conn-load-balanced conn)
                  load-balanced)
            (setf (mongodb-conn-service-id conn)
                  service-id)
            (setf (mongodb-conn-hello-command conn)
                  (mongodb--post-handshake-hello-command
                   hello
                   (or server-api load-balanced)))
            (setf (mongodb-conn-last-hello conn)
                  hello)
            (setf (mongodb-conn-topology conn)
                  (mongodb--topology-description-from-hello
                   conn hello handshake-rtt))
            (mongodb--ensure-topology-compatible
             (mongodb-conn-topology conn))
            (when (and load-balanced
                       (not service-id))
              (signal 'mongodb-error
                      (list "Driver attempted to initialize in load balancing mode, but the server does not support this mode.")))
            (mongodb--emit-sdam-opening-events
             conn (mongodb-conn-topology conn))
            (setq phase 'auth)
            (when (and authenticate credential)
              (mongodb--authenticate conn credential hello speculative-auth))
            (setq phase 'connected)
            (when authenticate
              (mongodb--initialize-session conn hello))
            (cons conn hello)))
      (error
       (ignore-errors (mongodb-disconnect conn))
       (unless conn
         (when proc
           (ignore-errors
             (delete-process proc)))
         (when (buffer-live-p buffer)
           (kill-buffer buffer)))
       (mongodb--resignal-connect-error phase err)))))

(defun mongodb--wire-truthy-p (value)
  "Return non-nil when MongoDB wire VALUE represents truth."
  (or (eq value t)
      (and (numberp value) (> value 0))
      (equal value "1")
      (equal value "true")))

(defun mongodb--hello-command-document
    (conn &optional topology-version max-await-time-ms)
  "Return a post-handshake hello command document for CONN.

Arguments: CONN, TOPOLOGY-VERSION, MAX-AWAIT-TIME-MS."
  (let ((command-name (or (mongodb-conn-hello-command conn) "hello")))
    `((,command-name . 1)
      ,@(when topology-version
          `(("topologyVersion" .
             ,(mongodb--topology-version-command-value topology-version))
            ("maxAwaitTimeMS" . ,max-await-time-ms))))))

(defun mongodb--run-hello-command (conn command &optional timeout)
  "Run hello COMMAND on CONN and update cached topology state."
  (let* ((hello-start (float-time))
         (hello (mongodb-command conn "admin" command timeout))
         (hello-rtt (- (float-time) hello-start)))
    (setf (mongodb-conn-last-hello conn)
          hello)
    (mongodb--apply-hello-limits conn hello)
    (mongodb--set-conn-topology
     conn
     (mongodb--topology-description-from-hello
      conn hello hello-rtt))
    (when (mongodb--wire-truthy-p (cdr (assoc "helloOk" hello)))
      (setf (mongodb-conn-hello-command conn)
            "hello"))
    hello))

(defun mongodb-hello (conn &optional timeout)
  "Run a post-handshake hello probe on CONN and return the response.
This is the command shape used for topology monitoring: it does not include
initial handshake metadata such as client information, compression, or
speculative authentication.

Arguments: CONN, TIMEOUT."
  (mongodb--run-hello-command
   conn
   (mongodb--hello-command-document conn)
   timeout))

(defun mongodb-awaitable-hello
    (conn max-await-time-ms &optional timeout)
  "Run an awaitable hello probe on CONN and return the response.
When the current server description has a topologyVersion, include both
topologyVersion and MAX-AWAIT-TIME-MS, matching MongoDB's awaitable hello
monitoring protocol.  Older servers without topologyVersion fall back to a
normal post-handshake hello.

Arguments: CONN, MAX-AWAIT-TIME-MS, TIMEOUT."
  (let* ((server (mongodb--current-server-description conn))
         (topology-version
          (and server
               (mongodb-server-description-topology-version server))))
    (mongodb--run-hello-command
     conn
     (mongodb--hello-command-document
      conn
      topology-version
     (and topology-version max-await-time-ms))
     timeout)))

(defun mongodb-monitor-once
    (conn &optional max-await-time-ms timeout)
  "Run one MongoDB monitor heartbeat for CONN.
The heartbeat uses awaitable hello when the server has a topologyVersion,
unless CONN is configured with serverMonitoringMode=poll.
On success, return the hello response and clear `mongodb-conn-monitor-error'.
On failure, record the error, mark the current server Unknown, and signal it.
In load-balanced mode, do not run a monitoring command; return the cached hello
response from the initial connection handshake instead.

Arguments: CONN, MAX-AWAIT-TIME-MS, TIMEOUT."
  (if (mongodb-conn-load-balanced conn)
      (progn
        (setf (mongodb-conn-monitor-error conn) nil)
        (mongodb-conn-last-hello conn))
    (let* ((max-await (or max-await-time-ms
                          mongodb-monitor-max-await-time-ms))
           (timeout (or timeout
                        (+ 1 (/ (float max-await) 1000.0))))
           (awaited (and (mongodb--monitor-awaitable-p conn) t))
           (heartbeat-start (float-time)))
      (apply #'mongodb--emit-sdam-event
             'server-heartbeat-started
             (mongodb--sdam-heartbeat-event-fields conn awaited))
      (condition-case err
          (let ((hello (let ((mongodb--suppress-command-events t))
                         (if (eq (mongodb-conn-server-monitoring-mode conn) 'poll)
                             (mongodb-hello conn timeout)
                           (mongodb-awaitable-hello conn max-await timeout)))))
            (setf (mongodb-conn-monitor-error conn) nil)
            (apply #'mongodb--emit-sdam-event
                   'server-heartbeat-succeeded
                   (append
                    (mongodb--sdam-heartbeat-event-fields conn awaited)
                    (list (cons 'duration-ms
                                (mongodb--pool-duration-ms heartbeat-start))
                          (cons 'reply hello))))
            hello)
        (error
         (setf (mongodb-conn-monitor-error conn) err)
         (mongodb--mark-current-server-unknown conn err)
         (apply #'mongodb--emit-sdam-event
                'server-heartbeat-failed
                (append
                 (mongodb--sdam-heartbeat-event-fields conn awaited)
                 (list (cons 'duration-ms
                             (mongodb--pool-duration-ms heartbeat-start))
                       (cons 'failure err))))
         (signal (car err) (cdr err)))))))

(defun mongodb--monitor-tick (conn max-await-time-ms timeout)
  "Run one scheduled monitor tick for CONN.

Arguments: CONN, MAX-AWAIT-TIME-MS, TIMEOUT."
  (if (not (mongodb-live-p conn))
      (mongodb-stop-monitor conn)
    (ignore-errors
      (mongodb-monitor-once conn max-await-time-ms timeout))))

(defun mongodb-stop-monitor (conn)
  "Stop CONN's MongoDB monitor timer."
  (when-let* ((timer (mongodb-conn-monitor-timer conn)))
    (ignore-errors
      (cancel-timer timer))
    (setf (mongodb-conn-monitor-timer conn) nil))
  conn)

(defun mongodb-start-monitor
    (conn &optional heartbeat-seconds max-await-time-ms timeout)
  "Start an explicit MongoDB monitor timer for CONN.
The monitor is not started automatically by `mongodb-connect'; callers opt in
when background topology refresh is appropriate for their UI/runtime.

Arguments: CONN, HEARTBEAT-SECONDS, MAX-AWAIT-TIME-MS, TIMEOUT."
  (mongodb-stop-monitor conn)
  (unless (mongodb-conn-load-balanced conn)
    (let* ((heartbeat (or heartbeat-seconds
                          (mongodb-conn-heartbeat-frequency conn)
                          mongodb-monitor-heartbeat-seconds))
           (max-await (or max-await-time-ms
                          (and (mongodb-conn-heartbeat-frequency conn)
                               (round (* 1000 heartbeat)))
                          mongodb-monitor-max-await-time-ms))
           (timeout (or timeout
                        (+ 1 (/ (float max-await) 1000.0)))))
      (setf (mongodb-conn-monitor-timer conn)
            (run-at-time 0 heartbeat
                         #'mongodb--monitor-tick
                         conn max-await timeout))))
  conn)

(defun mongodb--hello-primary-p (hello)
  "Return non-nil when HELLO identifies a writable primary."
  (or (mongodb--wire-truthy-p
       (cdr (assoc "isWritablePrimary" hello)))
      (mongodb--wire-truthy-p
       (cdr (assoc "ismaster" hello)))))

(defun mongodb--hello-hidden-p (hello)
  "Return non-nil when HELLO identifies a hidden replica-set member."
  (mongodb--wire-truthy-p (cdr (assoc "hidden" hello))))

(defun mongodb--hello-secondary-p (hello)
  "Return non-nil when HELLO identifies a selectable secondary."
  (and (mongodb--wire-truthy-p (cdr (assoc "secondary" hello)))
       (not (mongodb--hello-hidden-p hello))))

(defun mongodb--hello-mongos-p (hello)
  "Return non-nil when HELLO identifies a mongos router."
  (equal (cdr (assoc "msg" hello)) "isdbgrid"))

(defun mongodb--hello-replica-set-name (hello)
  "Return the replica set name from HELLO, or nil."
  (cdr (assoc "setName" hello)))

(defun mongodb--hello-announced-hosts (hello)
  "Return replica-set member host strings announced by HELLO."
  (let ((primary (cdr (assoc "primary" hello))))
    (delete-dups
     (delq nil
           (append (and (stringp primary) (list primary))
                   (cdr (assoc "hosts" hello))
                   (cdr (assoc "passives" hello))
                   (cdr (assoc "arbiters" hello)))))))

(defun mongodb--endpoint-key (host port)
  "Return a stable key for HOST and PORT."
  (if (mongodb--local-socket-endpoint-p host port)
      (format "local:%s" host)
    (format "%s:%s" (downcase host) port)))

(defun mongodb--endpoint-entry-key (endpoint)
  "Return the address key for ENDPOINT."
  (mongodb--endpoint-key (nth 0 endpoint) (nth 1 endpoint)))

(defun mongodb--endpoints-append-unique
    (endpoints additions &optional excluded-keys)
  "Return ENDPOINTS with ADDITIONS appended by address.
Endpoints whose keys already appear in ENDPOINTS or EXCLUDED-KEYS are skipped."
  (let ((keys (append excluded-keys
                      (mapcar #'mongodb--endpoint-entry-key endpoints)))
        (result endpoints))
    (dolist (endpoint additions)
      (let ((key (mongodb--endpoint-entry-key endpoint)))
        (unless (member key keys)
          (push key keys)
          (setq result (append result (list endpoint))))))
    result))

(defun mongodb--hello-announced-endpoints (hello database)
  "Return ENDPOINT entries announced by HELLO for DATABASE."
  (mapcar
   (lambda (hostspec)
     (pcase-let ((`(,host ,port) (mongodb--host-port hostspec)))
       (list host port database)))
   (mongodb--hello-announced-hosts hello)))

(defun mongodb--normalize-hostspec (hostspec)
  "Return HOSTSPEC normalized as a MongoDB address key."
  (pcase-let ((`(,host ,port) (mongodb--host-port hostspec 27017)))
    (mongodb--endpoint-key host port)))

(defun mongodb--hello-member-hosts (hello)
  "Return all replica-set member host strings announced by HELLO."
  (let ((primary (cdr (assoc "primary" hello))))
    (delete-dups
     (delq nil
           (append (and (stringp primary) (list primary))
                   (cdr (assoc "hosts" hello))
                   (cdr (assoc "passives" hello))
                   (cdr (assoc "arbiters" hello)))))))

(defun mongodb--hello-server-type (hello &optional load-balanced)
  "Return an SDAM-style server type symbol for HELLO.

Arguments: HELLO, LOAD-BALANCED."
  (cond
   (load-balanced 'load-balanced)
   ((not (mongodb--ok-p hello)) 'unknown)
   ((mongodb--hello-mongos-p hello) 'mongos)
   ((mongodb--hello-replica-set-name hello)
    (cond
     ((mongodb--hello-hidden-p hello) 'rs-other)
     ((mongodb--hello-primary-p hello) 'rs-primary)
     ((mongodb--hello-secondary-p hello) 'rs-secondary)
     ((mongodb--wire-truthy-p (cdr (assoc "arbiterOnly" hello))) 'rs-arbiter)
     (t 'rs-other)))
   ((mongodb--wire-truthy-p (cdr (assoc "isreplicaset" hello)))
    'rs-ghost)
   (t 'standalone)))

(defun mongodb--unknown-server-description
    (address &optional error topology-version)
  "Return an Unknown server description for ADDRESS.

Arguments: ADDRESS, ERROR, TOPOLOGY-VERSION."
  (make-mongodb-server-description
   :address address
   :type 'unknown
   :topology-version topology-version
   :last-update-time (float-time)
   :error error))

(defun mongodb--average-round-trip-time (previous measurement)
  "Return MongoDB average RTT from PREVIOUS and MEASUREMENT.
MEASUREMENT is the latest hello round trip time in seconds."
  (cond
   ((not measurement) previous)
   ((not previous) measurement)
   (t
    (+ (* mongodb--round-trip-time-alpha measurement)
       (* (- 1 mongodb--round-trip-time-alpha) previous)))))

(defun mongodb--server-description-from-hello
    (address hello &optional load-balanced round-trip-time)
  "Return a server description for ADDRESS from HELLO.

Arguments: ADDRESS, HELLO, LOAD-BALANCED, ROUND-TRIP-TIME."
  (make-mongodb-server-description
   :address address
   :type (mongodb--hello-server-type hello load-balanced)
   :set-name (cdr (assoc "setName" hello))
   :hosts (cdr (assoc "hosts" hello))
   :passives (cdr (assoc "passives" hello))
   :arbiters (cdr (assoc "arbiters" hello))
   :primary (cdr (assoc "primary" hello))
   :me (cdr (assoc "me" hello))
   :min-wire-version (cdr (assoc "minWireVersion" hello))
   :max-wire-version (cdr (assoc "maxWireVersion" hello))
   :logical-session-timeout-minutes
   (cdr (assoc "logicalSessionTimeoutMinutes" hello))
   :service-id (cdr (assoc "serviceId" hello))
   :topology-version (cdr (assoc "topologyVersion" hello))
   :election-id (cdr (assoc "electionId" hello))
   :set-version (cdr (assoc "setVersion" hello))
   :tags (cdr (assoc "tags" hello))
   :last-write-date (mongodb--hello-last-write-date hello)
   :last-update-time (float-time)
   :round-trip-time round-trip-time))

(defun mongodb--topology-version-process-id (topology-version)
  "Return TOPOLOGY-VERSION's processId as a comparable value."
  (when-let* ((value (cdr (assoc "processId"
                                 (mongodb--document-pairs topology-version)))))
    (cond
     ((mongodb-object-id-p value)
      (mongodb-object-id-hex value))
     ((and (mongodb--document-value-p value)
           (assoc "$oid" (mongodb--document-pairs value)))
      (cdr (assoc "$oid" (mongodb--document-pairs value))))
     ((and (consp value)
           (assoc "$oid" value))
      (cdr (assoc "$oid" value)))
     (t value))))

(defun mongodb--topology-version-counter (topology-version)
  "Return TOPOLOGY-VERSION's counter as a comparable integer."
  (let ((value (cdr (assoc "counter"
                           (mongodb--document-pairs topology-version)))))
    (cond
     ((mongodb-int64-p value)
      (mongodb-int64-value value))
     ((mongodb-int32-p value)
      (mongodb-int32-value value))
     (t value))))

(defun mongodb--topology-version-newer-or-equal-p (new current)
  "Return non-nil when NEW topologyVersion may replace CURRENT.
This follows SDAM freshness rules: missing values, missing current values, or
different processId values are treated as fresh; matching processId values
compare by counter."
  (cond
   ((not new) t)
   ((not current) t)
   ((not (equal (mongodb--topology-version-process-id new)
                (mongodb--topology-version-process-id current)))
    t)
   (t
    (let ((new-counter (mongodb--topology-version-counter new))
          (current-counter (mongodb--topology-version-counter current)))
      (or (not (integerp new-counter))
          (not (integerp current-counter))
          (>= new-counter current-counter))))))

(defun mongodb--topology-version-newer-p (new current)
  "Return non-nil when NEW topologyVersion is fresh for app error handling.
Application state-change errors only replace a server description when the
error's topologyVersion is newer than the current description.  Missing
topologyVersion values are treated as fresh for older servers.

Arguments: NEW, CURRENT."
  (cond
   ((not new) t)
   ((not current) t)
   ((not (equal (mongodb--topology-version-process-id new)
                (mongodb--topology-version-process-id current)))
    t)
   (t
    (let ((new-counter (mongodb--topology-version-counter new))
          (current-counter (mongodb--topology-version-counter current)))
      (or (not (integerp new-counter))
          (not (integerp current-counter))
          (> new-counter current-counter))))))

(defun mongodb--topology-version-from-response (response)
  "Return RESPONSE topologyVersion, or nil."
  (cdr (assoc "topologyVersion" response)))

(defun mongodb--object-id-hex-value (value)
  "Return VALUE as a lower-case ObjectId hex string, or nil."
  (cond
   ((mongodb-object-id-p value)
    (downcase (mongodb-object-id-hex value)))
   ((and (mongodb--document-value-p value)
         (assoc "$oid" (mongodb--document-pairs value)))
    (downcase (cdr (assoc "$oid" (mongodb--document-pairs value)))))
   ((and (consp value)
         (assoc "$oid" value))
    (downcase (cdr (assoc "$oid" value))))
   ((stringp value)
    (downcase value))
   (t nil)))

(defun mongodb--server-election-id-value (server)
  "Return SERVER's electionId as a comparable ObjectId hex string."
  (mongodb--object-id-hex-value
   (and server
        (mongodb-server-description-election-id server))))

(defun mongodb--server-set-version-value (server)
  "Return SERVER's setVersion as an integer, or nil."
  (let ((value (and server
                    (mongodb-server-description-set-version server))))
    (cond
     ((integerp value) value)
     ((mongodb-int32-p value) (mongodb-int32-value value))
     ((mongodb-int64-p value) (mongodb-int64-value value))
     (t nil))))

(defun mongodb--compare-election-ids (a b)
  "Compare ObjectId hex strings A and B bytewise.
Return -1, 0, or 1."
  (cond
   ((equal a b) 0)
   ((string< a b) -1)
   (t 1)))

(defun mongodb--compare-set-versions (a b)
  "Compare setVersion integers A and B.
Return -1, 0, or 1."
  (cond
   ((= a b) 0)
   ((< a b) -1)
   (t 1)))

(defun mongodb--primary-version-compare
    (election-a set-a election-b set-b max-wire-version)
  "Compare primary version tuple A with B for MAX-WIRE-VERSION.
Return -1, 0, or 1, or nil when either tuple is incomplete.  MongoDB 6.0+
uses electionId before setVersion; older wire versions keep the historical
driver ordering for compatibility.

Arguments: ELECTION-A, SET-A, ELECTION-B, SET-B, MAX-WIRE-VERSION."
  (when (and election-a set-a election-b set-b)
    (let* ((modern (>= (or max-wire-version 0) 17))
           (first (if modern
                      (mongodb--compare-election-ids election-a election-b)
                    (mongodb--compare-set-versions set-a set-b))))
      (if (/= first 0)
          first
        (if modern
            (mongodb--compare-set-versions set-a set-b)
          (mongodb--compare-election-ids election-a election-b))))))

(defun mongodb--topology-stale-primary-p (server topology)
  "Return non-nil when SERVER is an older primary than TOPOLOGY has seen."
  (and topology
       (eq (mongodb-server-description-type server) 'rs-primary)
       (let ((comparison
              (mongodb--primary-version-compare
               (mongodb--server-election-id-value server)
               (mongodb--server-set-version-value server)
               (mongodb-topology-description-max-election-id topology)
               (mongodb-topology-description-max-set-version topology)
               (mongodb-server-description-max-wire-version server))))
         (and comparison
              (< comparison 0)))))

(defun mongodb--stale-primary-server-description (address server)
  "Return an Unknown description for stale primary SERVER at ADDRESS."
  (mongodb--unknown-server-description
   address
   (format "Stale primary detected: electionId=%s setVersion=%s"
           (or (mongodb--server-election-id-value server) "unknown")
           (or (mongodb--server-set-version-value server) "unknown"))))

(defun mongodb--topology-primary-version-values (server topology)
  "Return (ELECTION-ID . SET-VERSION) after considering primary SERVER.

Arguments: SERVER, TOPOLOGY."
  (let ((max-election
         (and topology
              (mongodb-topology-description-max-election-id topology)))
        (max-set
         (and topology
              (mongodb-topology-description-max-set-version topology))))
    (if (eq (mongodb-server-description-type server) 'rs-primary)
        (let* ((election (mongodb--server-election-id-value server))
               (set-version (mongodb--server-set-version-value server))
               (comparison
                (mongodb--primary-version-compare
                 election set-version
                 max-election max-set
                 (mongodb-server-description-max-wire-version server))))
          (cond
           ((not (and election set-version))
            (cons max-election max-set))
           ((or (not comparison)
                (>= comparison 0))
            (cons election set-version))
           (t
            (cons max-election max-set))))
      (cons max-election max-set))))

(defun mongodb--topology-member-addresses (hello)
  "Return normalized hosts/passives/arbiters addresses from HELLO."
  (delete-dups
   (mapcar #'mongodb--normalize-hostspec
           (mongodb--hello-member-hosts hello))))

(defun mongodb--topology-add-unknown-servers (servers addresses)
  "Return SERVERS with Unknown descriptions for missing ADDRESSES."
  (let ((result (copy-sequence servers)))
    (dolist (address addresses)
      (unless (assoc address result)
        (setq result
              (append result
                      (list
                       (cons address
                             (mongodb--unknown-server-description address)))))))
    result))

(defun mongodb--topology-prune-to-addresses
    (servers addresses &optional keep-address)
  "Return SERVERS whose addresses are in ADDRESSES or KEEP-ADDRESS."
  (seq-filter
   (lambda (entry)
     (or (member (car entry) addresses)
         (and keep-address
              (equal (car entry) keep-address))))
   servers))

(defun mongodb--topology-remove-server (servers address)
  "Return SERVERS without the server at ADDRESS."
  (seq-remove (lambda (entry)
                (equal (car entry) address))
              servers))

(defun mongodb--topology-primary-address-from-servers (servers)
  "Return the address of the known RSPrimary in SERVERS, or nil."
  (catch 'primary
    (dolist (entry servers)
      (when (eq (mongodb-server-description-type (cdr entry)) 'rs-primary)
        (throw 'primary (car entry))))
    nil))

(defun mongodb--stale-primary-discovery-description
    (old-address new-primary-address)
  "Return an Unknown description for OLD-ADDRESS after NEW-PRIMARY-ADDRESS."
  (mongodb--unknown-server-description
   old-address
   (format "primary marked stale due to discovery of newer primary %s"
           new-primary-address)))

(defun mongodb--topology-mark-other-primaries-unknown
    (servers primary-address)
  "Return SERVERS with all primaries except PRIMARY-ADDRESS marked Unknown."
  (mapcar
   (lambda (entry)
     (let ((address (car entry))
           (server (cdr entry)))
       (if (and (not (equal address primary-address))
                (eq (mongodb-server-description-type server) 'rs-primary))
           (cons address
                 (mongodb--stale-primary-discovery-description
                  address primary-address))
         entry)))
   servers))

(defun mongodb--topology-servers-after-hello
    (address server hello old-servers)
  "Return updated server map after processing SERVER at ADDRESS.
Primary hello responses add current replica-set members and prune removed
members.  Non-primary replica-set responses add discovered members but leave
existing members in place until a primary becomes authoritative."
  (let* ((server-type (mongodb-server-description-type server))
         (member-addresses (mongodb--topology-member-addresses hello))
         (servers (mongodb--replace-server-description
                   old-servers address server)))
    (pcase server-type
      ('rs-primary
       (setq servers
             (mongodb--topology-add-unknown-servers
              servers member-addresses))
       (setq servers
             (if member-addresses
                 (mongodb--topology-prune-to-addresses
                  servers member-addresses address)
               servers))
       (mongodb--topology-mark-other-primaries-unknown
        servers address))
      ((or 'rs-secondary 'rs-arbiter 'rs-other)
       (mongodb--topology-add-unknown-servers
        servers member-addresses))
      (_ servers))))

(defun mongodb--topology-has-replica-set-server-p (servers)
  "Return non-nil when SERVERS contains any replica-set server description."
  (seq-some
   (lambda (entry)
     (memq (mongodb-server-description-type (cdr entry))
           '(rs-primary rs-secondary rs-arbiter rs-other)))
   servers))

(defun mongodb--replica-set-topology-type-p (type)
  "Return non-nil when TYPE is a replica-set topology type."
  (memq type '(replica-set-with-primary replica-set-no-primary)))

(defun mongodb--replica-set-server-type-p (server)
  "Return non-nil when SERVER is a named replica-set member."
  (memq (mongodb-server-description-type server)
        '(rs-primary rs-secondary rs-arbiter rs-other)))

(defun mongodb--replica-set-non-primary-server-type-p (server)
  "Return non-nil when SERVER is a non-primary replica-set member."
  (memq (mongodb-server-description-type server)
        '(rs-secondary rs-arbiter rs-other)))

(defun mongodb--topology-expected-set-name (conn old-topology)
  "Return expected replica-set name from CONN params or OLD-TOPOLOGY."
  (or (and old-topology
           (mongodb-topology-description-set-name old-topology))
      (and (mongodb-conn-p conn)
           (mongodb-conn-params conn)
           (mongodb--params-replica-set-name
            (mongodb-conn-params conn)))))

(defun mongodb--replica-set-set-name-mismatch-p
    (conn old-topology server)
  "Return non-nil when SERVER has the wrong replica-set name.

Arguments: CONN, OLD-TOPOLOGY, SERVER."
  (and (not (mongodb--conn-direct-connection-p conn))
       (not (mongodb-conn-load-balanced conn))
       (mongodb--replica-set-server-type-p server)
       (when-let* ((expected
                    (mongodb--topology-expected-set-name conn old-topology)))
         (not (equal expected
                     (mongodb-server-description-set-name server))))))

(defun mongodb--server-me-mismatch-p (address server)
  "Return non-nil when SERVER's `me' field disagrees with ADDRESS."
  (when-let* ((me (mongodb-server-description-me server)))
    (condition-case nil
        (not (equal (mongodb--normalize-hostspec me) address))
      (error nil))))

(defun mongodb--replica-set-me-mismatch-p (conn old-topology address server)
  "Return non-nil when SERVER should be removed for a `me' mismatch.

Arguments: CONN, OLD-TOPOLOGY, ADDRESS, SERVER."
  (and old-topology
       (not (mongodb--conn-direct-connection-p conn))
       (not (mongodb-conn-load-balanced conn))
       (mongodb--replica-set-non-primary-server-type-p server)
       (mongodb--server-me-mismatch-p address server)))

(defun mongodb--topology-type-after-hello
    (conn server servers &optional old-topology)
  "Return topology type after processing SERVER and SERVERS for CONN."
  (cond
   ((mongodb--conn-direct-connection-p conn)
    'single)
   ((mongodb-conn-load-balanced conn)
    'load-balanced)
   ((eq (mongodb-server-description-type server) 'mongos)
    'sharded)
   ((eq (mongodb-server-description-type server) 'standalone)
    'single)
   ((eq (mongodb-server-description-type server) 'rs-ghost)
    (cond
     ((mongodb--topology-primary-address-from-servers servers)
      'replica-set-with-primary)
     ((and old-topology
           (mongodb--replica-set-topology-type-p
            (mongodb-topology-description-type old-topology)))
      'replica-set-no-primary)
     (t 'unknown)))
   ((memq (mongodb-server-description-type server)
          '(rs-primary rs-secondary rs-arbiter rs-other))
    (if (mongodb--topology-primary-address-from-servers servers)
        'replica-set-with-primary
      'replica-set-no-primary))
   ((mongodb--topology-primary-address-from-servers servers)
    'replica-set-with-primary)
   ((or (mongodb--topology-has-replica-set-server-p servers)
        (and old-topology
             (mongodb--replica-set-topology-type-p
              (mongodb-topology-description-type old-topology))))
    'replica-set-no-primary)
   (t 'unknown)))

(defun mongodb--wire-version-number (value default)
  "Return VALUE as an integer wire version, or DEFAULT."
  (cond
   ((integerp value) value)
   ((mongodb-int32-p value) (mongodb-int32-value value))
   ((mongodb-int64-p value) (mongodb-int64-value value))
   (t default)))

(defun mongodb--server-wire-compatibility-error (address server)
  "Return SERVER wire compatibility error at ADDRESS, or nil."
  (unless (eq (mongodb-server-description-type server) 'unknown)
    (let ((min-wire
           (mongodb--wire-version-number
            (mongodb-server-description-min-wire-version server)
            0))
          (max-wire
           (mongodb--wire-version-number
            (mongodb-server-description-max-wire-version server)
            0)))
      (cond
       ((> min-wire mongodb--client-max-wire-version)
        (format
         "Server at %s requires wire version %s, but mongodb.el only supports up to %s"
         address min-wire mongodb--client-max-wire-version))
       ((< max-wire mongodb--client-min-wire-version)
        (format
         "Server at %s reports wire version %s, but mongodb.el requires at least %s (%s)"
         address
         max-wire
         mongodb--client-min-wire-version
         mongodb--client-min-wire-version-release))))))

(defun mongodb--server-wire-compatible-p (address server)
  "Return non-nil when SERVER at ADDRESS is compatible with this client."
  (not (mongodb--server-wire-compatibility-error address server)))

(defun mongodb--topology-compatible-p (servers)
  "Return non-nil when all non-Unknown SERVERS are wire-compatible."
  (seq-every-p
   (lambda (entry)
     (mongodb--server-wire-compatible-p (car entry) (cdr entry)))
   servers))

(defun mongodb--topology-compatibility-error (servers)
  "Return compatibility error for SERVERS, or nil."
  (catch 'error
    (dolist (entry servers)
      (when-let* ((error (mongodb--server-wire-compatibility-error
                          (car entry)
                          (cdr entry))))
        (throw 'error error)))
    nil))

(defun mongodb--ensure-topology-compatible (topology)
  "Signal when TOPOLOGY contains an incompatible server description."
  (when topology
    (let ((error
           (or (mongodb-topology-description-compatibility-error topology)
               (mongodb--topology-compatibility-error
                (mongodb-topology-description-servers topology)))))
      (if error
          (progn
            (setf (mongodb-topology-description-compatible topology) nil)
            (setf (mongodb-topology-description-compatibility-error topology)
                  error)
            (signal 'mongodb-error (list error)))
        (setf (mongodb-topology-description-compatible topology) t)
        (setf (mongodb-topology-description-compatibility-error topology) nil))))
  topology)

(defun mongodb--topology-type-from-server (server)
  "Return a topology type symbol implied by SERVER."
  (pcase (mongodb-server-description-type server)
    ('load-balanced 'load-balanced)
    ('mongos 'sharded)
    ('rs-primary 'replica-set-with-primary)
    ((or 'rs-secondary 'rs-arbiter 'rs-other)
     'replica-set-no-primary)
    ('rs-ghost 'unknown)
    ('standalone 'single)
    (_ 'unknown)))

(defun mongodb--conn-direct-connection-p (conn)
  "Return non-nil when CONN was opened as directConnection=true."
  (and (mongodb-conn-p conn)
       (ignore-errors
         (mongodb--params-direct-connection-p
          (mongodb-conn-params conn)))))

(defun mongodb--single-set-name-mismatch-error (conn server)
  "Return a Single-topology setName mismatch message for SERVER, or nil.

Arguments: CONN, SERVER."
  (when (and (mongodb--conn-direct-connection-p conn)
             (not (eq (mongodb-server-description-type server) 'unknown)))
    (when-let* ((expected
                 (mongodb--params-replica-set-name
                  (mongodb-conn-params conn))))
      (let ((actual (mongodb-server-description-set-name server)))
        (cond
         ((not actual)
          (format "MongoDB direct connection did not report replica set %s"
                  expected))
         ((not (equal expected actual))
          (format "MongoDB direct connection belongs to replica set %s, not %s"
                  actual expected)))))))

(defun mongodb--verify-single-set-name (conn address server)
  "Return SERVER or an Unknown description for Single setName mismatch.

Arguments: CONN, ADDRESS, SERVER."
  (if-let* ((error (mongodb--single-set-name-mismatch-error conn server)))
      (mongodb--unknown-server-description address error)
    server))

(defun mongodb--topology-description-from-hello
    (conn hello &optional round-trip-time)
  "Return a topology description for CONN from HELLO.

Arguments: CONN, HELLO, ROUND-TRIP-TIME."
  (let* ((address (mongodb--endpoint-key
                   (mongodb-conn-host conn)
                   (mongodb-conn-port conn)))
         (old-topology (mongodb-conn-topology conn))
         (old-server (and old-topology
                          (cdr (assoc address
                                      (mongodb-topology-description-servers
                                       old-topology)))))
         (average-round-trip-time
          (mongodb--average-round-trip-time
           (and old-server
                (mongodb-server-description-round-trip-time old-server))
           round-trip-time))
         (server (mongodb--server-description-from-hello
                  address hello (mongodb-conn-load-balanced conn)
                  average-round-trip-time))
         (old-topology-version
          (and old-server
               (mongodb-server-description-topology-version old-server))))
    (if (and old-topology
             old-server
             (not (mongodb--topology-version-newer-or-equal-p
                   (mongodb-server-description-topology-version server)
                   old-topology-version)))
        old-topology
      (when (mongodb--topology-stale-primary-p server old-topology)
        (setq server
              (mongodb--stale-primary-server-description
               address server)))
      (setq server
            (mongodb--verify-single-set-name conn address server))
      (let* ((old-servers
              (and old-topology
                   (mongodb-topology-description-servers old-topology)))
             (expected-set-name
              (mongodb--topology-expected-set-name conn old-topology))
             (set-name-mismatch
              (mongodb--replica-set-set-name-mismatch-p
               conn old-topology server))
             (me-mismatch
              (mongodb--replica-set-me-mismatch-p
               conn old-topology address server))
             (servers
              (cond
               ((or set-name-mismatch me-mismatch)
                (mongodb--topology-remove-server old-servers address))
               ((or (mongodb--conn-direct-connection-p conn)
                    (mongodb-conn-load-balanced conn)
                    (eq (mongodb-server-description-type server)
                        'standalone))
                (list (cons address server)))
               (t
                (mongodb--topology-servers-after-hello
                 address server hello old-servers))))
             (topology-type
              (mongodb--topology-type-after-hello
               conn server servers old-topology))
             (primary-address
              (mongodb--topology-primary-address-from-servers servers))
             (primary-version
              (mongodb--topology-primary-version-values
               server old-topology))
             (compatible
              (mongodb--topology-compatible-p servers)))
        (make-mongodb-topology-description
         :type topology-type
         :set-name (or expected-set-name
                       (mongodb-server-description-set-name server)
                       (and old-topology
                            (mongodb-topology-description-set-name
                             old-topology)))
         :servers servers
         :primary-address primary-address
         :max-election-id (car primary-version)
         :max-set-version (cdr primary-version)
         :logical-session-timeout-minutes
         (or (mongodb-server-description-logical-session-timeout-minutes server)
             (and old-topology
                  (mongodb-topology-description-logical-session-timeout-minutes
                   old-topology)))
         :compatible compatible
         :compatibility-error
         (unless compatible
           (mongodb--topology-compatibility-error servers)))))))

(defun mongodb--replica-set-hello-ok-p (expected-set hello)
  "Return non-nil when HELLO belongs to EXPECTED-SET, or no set was requested."
  (let ((actual-set (mongodb--hello-replica-set-name hello)))
    (or (not expected-set)
        (equal expected-set actual-set))))

(defun mongodb--replica-set-error-message (expected-set hello)
  "Return a replica-set mismatch message for EXPECTED-SET and HELLO."
  (let ((actual-set (mongodb--hello-replica-set-name hello)))
    (cond
     ((and expected-set actual-set)
      (format "MongoDB seed belongs to replica set %s, not %s"
              actual-set expected-set))
     (expected-set
      (format "MongoDB seed did not report replica set %s"
              expected-set))
     (t
      "MongoDB seed did not report a writable primary"))))

(defun mongodb--replica-set-canonical-address-ok-p (host port hello)
  "Return non-nil when HELLO's canonical `me' matches HOST and PORT.
Replica-set discovery must not select a seed alias that the server reports as
a different canonical address; directConnection bypasses this discovery path."
  (let ((me (cdr (assoc "me" hello))))
    (or (not me)
        (condition-case nil
            (equal (mongodb--normalize-hostspec me)
                   (mongodb--endpoint-key host port))
          (error nil)))))

(defun mongodb--replica-set-canonical-error-message (host port hello)
  "Return an error message for HELLO `me' mismatch at HOST and PORT."
  (format "MongoDB seed %s is known as canonical replica-set member %s"
          (mongodb--endpoint-key host port)
          (cdr (assoc "me" hello))))

(defun mongodb--hello-announces-me-p (hello)
  "Return non-nil when HELLO's canonical `me' appears in announced hosts."
  (when-let* ((me (cdr (assoc "me" hello))))
    (member (mongodb--normalize-hostspec me)
            (mapcar #'mongodb--normalize-hostspec
                    (mongodb--hello-announced-hosts hello)))))

(defun mongodb--canonical-alias-fallback-candidate-p
    (mode constraints-ok hello)
  "Return non-nil when a `me' mismatch seed may remain a fallback.
The fallback is only used if canonical hosts cannot be selected, preserving
local port-forwarded development deployments without preferring aliases.

Arguments: MODE, CONSTRAINTS-OK, HELLO."
  (and (mongodb--hello-announces-me-p hello)
       (cond
        ((mongodb--hello-primary-p hello)
         (or (member mode '("primary" "primaryPreferred"
                            "secondaryPreferred"))
             (and (equal mode "nearest")
                  constraints-ok)))
        ((mongodb--hello-secondary-p hello)
         (and constraints-ok
              (member mode '("secondary" "secondaryPreferred"
                             "primaryPreferred" "nearest")))))))

(defun mongodb--replica-read-preference-mode (params)
  "Return read preference mode for replica-set connection PARAMS."
  (mongodb--read-preference-mode
   (mongodb--params-read-preference params)))

(defun mongodb--queue-announced-replica-hosts (hello seen queue database)
  "Return QUEUE with unvisited replica-set hosts announced by HELLO appended.

Arguments: HELLO, SEEN, QUEUE, DATABASE."
  (mongodb--endpoints-append-unique
   queue
   (mongodb--hello-announced-endpoints hello database)
   seen))

(defun mongodb--hello-read-preference-constraints-p
    (params host port hello read-preference)
  "Return non-nil when HELLO matches READ-PREFERENCE constraints.

Arguments: PARAMS, HOST, PORT, HELLO, READ-PREFERENCE."
  (let* ((probe (make-mongodb-conn
                 :host host
                 :port port
                 :load-balanced (mongodb--params-load-balanced-p params)))
         (topology (mongodb--topology-description-from-hello probe hello))
         (address (mongodb--endpoint-key host port))
         (server (cdr (assoc address
                             (mongodb-topology-description-servers topology)))))
    (and server
         (mongodb--server-matches-read-preference-constraints-p
          server
          read-preference
          topology
          (or (mongodb--params-heartbeat-frequency params)
              mongodb-monitor-heartbeat-seconds)))))

(defun mongodb--endpoint-result-server-description (conn host port hello)
  "Return the server description for an endpoint RESULT.

Arguments: CONN, HOST, PORT, HELLO."
  (let* ((address (mongodb--endpoint-key host port))
         (topology (and (mongodb-conn-p conn)
                        (mongodb-conn-topology conn)))
         (server (and topology
                      (cdr (assoc address
                                  (mongodb-topology-description-servers
                                   topology))))))
    (or server
        (mongodb--server-description-from-hello
         address hello
         (and (mongodb-conn-p conn)
              (mongodb-conn-load-balanced conn))))))

(defun mongodb--endpoint-result-candidate (conn host port hello)
  "Return a connected server candidate from CONN, HOST, PORT, and HELLO."
  (make-mongodb--server-candidate
   :conn conn
   :hello hello
   :server (mongodb--endpoint-result-server-description
            conn host port hello)))

(defun mongodb--candidate-round-trip-time (candidate)
  "Return CANDIDATE average RTT in seconds, or nil."
  (when-let* ((server (mongodb--server-candidate-server candidate)))
    (mongodb-server-description-round-trip-time server)))

(defun mongodb--candidates-within-latency-window
    (candidates local-threshold)
  "Return CANDIDATES whose RTT is inside the local-threshold latency window.

Arguments: CANDIDATES, LOCAL-THRESHOLD."
  (let ((rtts (delq nil
                    (mapcar #'mongodb--candidate-round-trip-time
                            candidates))))
    (if rtts
        (let ((upper (+ (apply #'min rtts) local-threshold)))
          (seq-filter
           (lambda (candidate)
             (when-let* ((rtt (mongodb--candidate-round-trip-time candidate)))
               (<= rtt upper)))
           candidates))
      candidates)))

(defun mongodb--select-candidate-within-latency-window
    (candidates local-threshold)
  "Select one candidate from CANDIDATES within the latency window.

Arguments: CANDIDATES, LOCAL-THRESHOLD."
  (when candidates
    (let* ((window (or (mongodb--candidates-within-latency-window
                       candidates local-threshold)
                      candidates))
           (count (length window)))
      (nth (random count) window))))

(defun mongodb--disconnect-candidates-except (candidates selected)
  "Disconnect all CANDIDATES except SELECTED."
  (dolist (candidate candidates)
    (unless (eq candidate selected)
      (ignore-errors
        (mongodb-disconnect
         (mongodb--server-candidate-conn candidate))))))

(defun mongodb--finalize-selected-candidate (candidate credential)
  "Authenticate and initialize CANDIDATE, then return its connection.

Arguments: CANDIDATE, CREDENTIAL."
  (let ((conn (mongodb--server-candidate-conn candidate))
        (hello (mongodb--server-candidate-hello candidate)))
    (when credential
      (mongodb--authenticate conn credential hello)
      (mongodb--mark-connection-authenticated conn))
    (mongodb--initialize-session conn hello)
    conn))

(defun mongodb--connect-replica-server (params endpoints credential)
  "Connect to a replica-set server selected from ENDPOINTS.

Arguments: PARAMS, ENDPOINTS, CREDENTIAL."
  (let* ((expected-set (mongodb--params-replica-set-name params))
         (read-preference (mongodb--params-read-preference params))
         (mode (mongodb--read-preference-mode read-preference))
         (local-threshold (mongodb--params-local-threshold params))
         (selection-timeout (mongodb--params-server-selection-timeout params))
         (try-once (mongodb--params-server-selection-try-once-p params))
         (deadline (and selection-timeout
                        (+ (float-time) selection-timeout)))
         (database (nth 2 (car endpoints)))
         (known-endpoints (copy-sequence endpoints))
         (last-error nil)
         selected
         done)
    (while (not done)
      (let ((queue (copy-sequence known-endpoints))
            (seen nil)
            primary-candidate
            fallback-primary
            secondary-candidates
            nearest-candidates
            canonical-alias-fallback-candidates
            mongos-candidates)
        (while (and queue
                    (not selected)
                    (or (not deadline)
                        (> deadline (float-time))))
          (pcase-let* ((`(,host ,port ,_database) (pop queue))
                       (key (mongodb--endpoint-key host port)))
            (unless (member key seen)
              (push key seen)
              (condition-case err
                  (let* ((remaining (and deadline
                                          (max 0.001
                                               (- deadline (float-time)))))
                         (connect-params
                          (if remaining
                              (mongodb--params-with-connect-timeout-limit
                               params remaining)
                            params))
                         (result (mongodb--connect-endpoint
                                  connect-params host port database credential nil))
                         (conn (car result))
                         (hello (cdr result))
                         (candidate
                          (mongodb--endpoint-result-candidate
                           conn host port hello))
                         (constraints-ok
                          (mongodb--hello-read-preference-constraints-p
                           params host port hello read-preference)))
                    (cond
                     ((and (mongodb--hello-mongos-p hello)
                           (not expected-set))
                      (push candidate mongos-candidates))
                     ((not (mongodb--replica-set-hello-ok-p expected-set hello))
                      (setq last-error
                            (mongodb--replica-set-error-message
                             expected-set hello))
                      (mongodb-disconnect conn))
                     ((not (mongodb--replica-set-canonical-address-ok-p
                            host port hello))
                      (setq known-endpoints
                            (mongodb--endpoints-append-unique
                             known-endpoints
                             (mongodb--hello-announced-endpoints
                              hello database)))
                      (setq queue (mongodb--queue-announced-replica-hosts
                                   hello seen queue database))
                      (let ((fallback
                             (mongodb--canonical-alias-fallback-candidate-p
                              mode constraints-ok hello)))
                        (when fallback
                          (push candidate canonical-alias-fallback-candidates))
                        (unless fallback
                          (mongodb-disconnect conn)))
                      (setq last-error
                            (mongodb--replica-set-canonical-error-message
                             host port hello)))
                     ((mongodb--hello-primary-p hello)
                      (setq known-endpoints
                            (mongodb--endpoints-append-unique
                             known-endpoints
                             (mongodb--hello-announced-endpoints
                              hello database)))
                      (setq queue (mongodb--queue-announced-replica-hosts
                                   hello seen queue database))
                      (cond
                       ((member mode '("primary" "primaryPreferred"))
                        (setq primary-candidate candidate
                              selected candidate))
                       ((equal mode "secondaryPreferred")
                        (when fallback-primary
                          (mongodb-disconnect
                           (mongodb--server-candidate-conn fallback-primary)))
                        (setq fallback-primary candidate))
                       ((and (equal mode "nearest")
                             constraints-ok)
                        (push candidate nearest-candidates))
                       ((equal mode "nearest")
                        (setq last-error
                              "readPreference tags/maxStalenessSeconds did not match primary")
                        (mongodb-disconnect conn))
                       (t
                        (setq last-error
                              "readPreference=secondary did not find a secondary yet")
                        (mongodb-disconnect conn))))
                     ((mongodb--hello-secondary-p hello)
                      (setq known-endpoints
                            (mongodb--endpoints-append-unique
                             known-endpoints
                             (mongodb--hello-announced-endpoints
                              hello database)))
                      (setq queue (mongodb--queue-announced-replica-hosts
                                   hello seen queue database))
                      (cond
                       ((and (member mode '("secondary" "secondaryPreferred"
                                            "primaryPreferred"))
                             constraints-ok)
                        (push candidate secondary-candidates))
                       ((and (equal mode "nearest")
                             constraints-ok)
                        (push candidate nearest-candidates))
                       (t
                        (setq last-error
                              (if constraints-ok
                                  "replica-set discovery did not find a primary yet"
                                "readPreference tags/maxStalenessSeconds did not match secondary"))
                        (mongodb-disconnect conn))))
                     (t
                      (setq last-error
                            (mongodb--replica-set-error-message
                             expected-set hello))
                      (setq known-endpoints
                            (mongodb--endpoints-append-unique
                             known-endpoints
                             (mongodb--hello-announced-endpoints
                              hello database)))
                      (setq queue (mongodb--queue-announced-replica-hosts
                                  hello seen queue database))
                      (mongodb-disconnect conn))))
                (error
                 (setq last-error (error-message-string err)))))))
        (unless selected
          (setq selected
                (cond
                 (mongos-candidates
                  (mongodb--select-candidate-within-latency-window
                   mongos-candidates local-threshold))
                 ((equal mode "nearest")
                  (mongodb--select-candidate-within-latency-window
                   nearest-candidates local-threshold))
                 ((member mode '("secondary" "primaryPreferred"))
                  (mongodb--select-candidate-within-latency-window
                   secondary-candidates local-threshold))
                 ((equal mode "secondaryPreferred")
                  (or (mongodb--select-candidate-within-latency-window
                       secondary-candidates local-threshold)
                      fallback-primary))
                 (canonical-alias-fallback-candidates
                  (mongodb--select-candidate-within-latency-window
                   canonical-alias-fallback-candidates local-threshold)))))
        (let ((all-candidates
               (delq nil
                     (append (list primary-candidate fallback-primary)
                             secondary-candidates
                             nearest-candidates
                             canonical-alias-fallback-candidates
                             mongos-candidates))))
          (if selected
              (progn
                (mongodb--disconnect-candidates-except all-candidates selected)
                (setq done t))
            (mongodb--disconnect-candidates-except all-candidates nil)
            (if (or try-once
                    (and deadline
                         (<= deadline (float-time))))
                (setq done t)
              (let ((remaining (and deadline
                                    (- deadline (float-time)))))
                (when (and remaining
                           (> remaining 0))
                  (sleep-for (min 0.5 remaining)))))))))
    (if selected
        (mongodb--finalize-selected-candidate selected credential)
      (when (and deadline
                 (<= deadline (float-time)))
        (setq last-error
              "serverSelectionTimeoutMS expired before a matching server was selected"))
      (signal 'mongodb-error
              (list (if last-error
                        (format "Native MongoDB replica-set discovery did not find a server matching readPreference=%s: %s"
                                mode
                                last-error)
                      (format "Native MongoDB replica-set discovery did not find a server matching readPreference=%s"
                              mode)))))))

(defun mongodb--validate-load-balanced-params (params endpoints)
  "Validate load-balanced PARAMS and ENDPOINTS."
  (when (mongodb--params-load-balanced-p params)
    (when (> (length endpoints) 1)
      (signal 'mongodb-error
              (list "MongoDB loadBalanced=true requires exactly one host")))
    (when (mongodb--params-replica-set-name params)
      (signal 'mongodb-error
              (list "MongoDB loadBalanced=true cannot be combined with replicaSet")))
    (when (mongodb--params-direct-connection-p params)
      (signal 'mongodb-error
              (list "MongoDB loadBalanced=true cannot be combined with directConnection=true")))
    (when (mongodb--params-srv-max-hosts params)
      (signal 'mongodb-error
              (list "MongoDB loadBalanced=true cannot be combined with srvMaxHosts")))))

(defun mongodb--validate-srv-max-hosts-params (params)
  "Validate SRV max-host constraints after effective URL options are known.

Arguments: PARAMS."
  (when (and (mongodb--params-srv-max-hosts params)
             (mongodb--params-replica-set-name params))
    (signal 'mongodb-error
            (list "MongoDB srvMaxHosts cannot be combined with replicaSet"))))

(defun mongodb-connect (params)
  "Open a MongoDB wire protocol connection using PARAMS."
  (let ((mongodb--srv-resolution-cache nil))
    (mongodb--reject-unsupported-params params)
    (let* ((selection-timeout (mongodb--params-server-selection-timeout params))
           (connect-params (if selection-timeout
                               (mongodb--params-with-connect-timeout-limit
                                params selection-timeout)
                             params))
           (credential (mongodb--params-credential params))
           (endpoints (mongodb--params-endpoints params)))
      (mongodb--validate-load-balanced-params params endpoints)
      (mongodb--validate-srv-max-hosts-params params)
      (when (and (mongodb--params-direct-connection-p params)
                 (> (length endpoints) 1))
        (signal 'mongodb-error
                (list "Native MongoDB directConnection=true requires exactly one host")))
      (if (mongodb--params-replica-discovery-p params endpoints)
          (mongodb--connect-replica-server params endpoints credential)
        (pcase-let ((`(,host ,port ,database) (car endpoints)))
          (car (mongodb--connect-endpoint
                connect-params host port database credential t)))))))

(defun mongodb-disconnect (conn)
  "Close MongoDB wire CONN."
  (when conn
    (mongodb-stop-monitor conn)
    (when-let* ((session-id (mongodb-conn-session-id conn)))
      (when (mongodb-live-p conn)
        (when (mongodb-in-transaction-p conn)
          (ignore-errors
            (mongodb-abort-transaction conn)))
        (setf (mongodb-conn-session-id conn) nil)
        (ignore-errors
          (mongodb-command
           conn "admin"
           `(("endSessions" . ,(vector session-id)))))))
    (mongodb--emit-sdam-closing-events conn)
    (setf (mongodb-conn-closed conn) t)
    (when-let* ((proc (mongodb-conn-process conn)))
      (when (process-live-p proc)
        (delete-process proc)))
    (when-let* ((buffer (mongodb-conn-buffer conn)))
      (when (buffer-live-p buffer)
        (kill-buffer buffer)))))

(defun mongodb-live-p (conn)
  "Return non-nil when CONN is open."
  (and conn
       (not (mongodb-conn-closed conn))
       (process-live-p (mongodb-conn-process conn))))

(defun mongodb--pool-total-size (pool)
  "Return total available, in-use, and connecting count for POOL."
  (+ (length (mongodb-pool-available pool))
     (length (mongodb-pool-in-use pool))
     (or (mongodb-pool-connecting pool) 0)))

(defun mongodb--pool-address (pool)
  "Return a display address for MongoDB POOL events."
  (let ((params (mongodb-pool-params pool)))
    (or (when-let* ((parts (mongodb--params-url-parts params)))
          (plist-get parts :hosts))
        (format "%s:%s"
                (or (plist-get params :host) "127.0.0.1")
                (or (plist-get params :port) 27017)))))

(defun mongodb--pool-emit-event (pool type &rest fields)
  "Emit MongoDB pool event TYPE for POOL with alist FIELDS."
  (let ((event `((type . ,type)
                 (address . ,(mongodb--pool-address pool))
                 (pool . ,pool)
                 ,@fields)))
    (run-hook-with-args 'mongodb-pool-event-hook event)
    event))

(defun mongodb--pool-duration-ms (start)
  "Return milliseconds elapsed since START."
  (* 1000.0 (- (float-time) start)))

(defun mongodb--pool-millis-option (seconds)
  "Return SECONDS as a MongoDB millisecond pool option value."
  (round (* seconds 1000)))

(defun mongodb--pool-reason-string (reason)
  "Return REASON as the CMAP string value."
  (pcase reason
    ('connection-error "connectionError")
    ('pool-closed "poolClosed")
    ('timeout "timeout")
    ('stale "stale")
    ('idle "idle")
    ('error "error")
    (_ (symbol-name reason))))

(defun mongodb--pool-created-options (pool)
  "Return non-default CMAP pool-created options for POOL."
  (let (options)
    (unless (equal (mongodb-pool-max-size pool)
                   mongodb--default-max-pool-size)
      (push (cons 'max-pool-size
                  (or (mongodb-pool-max-size pool) 0))
            options))
    (unless (equal (mongodb-pool-min-size pool)
                   mongodb--default-min-pool-size)
      (push (cons 'min-pool-size (mongodb-pool-min-size pool)) options))
    (when-let* ((max-idle (mongodb-pool-max-idle-time pool)))
      (push (cons 'max-idle-time-ms
                  (mongodb--pool-millis-option max-idle))
            options))
    (when-let* ((wait-timeout (mongodb-pool-wait-queue-timeout pool)))
      (unless (zerop wait-timeout)
        (push (cons 'wait-queue-timeout-ms
                    (mongodb--pool-millis-option wait-timeout))
              options)))
    (unless (equal (mongodb-pool-max-connecting pool)
                   mongodb--default-max-connecting)
      (push (cons 'max-connecting (mongodb-pool-max-connecting pool))
            options))
    (nreverse options)))

(defun mongodb--pool-emit-checkout-failed
    (pool checkout-start reason &optional error)
  "Emit POOL checkout failure REASON using CHECKOUT-START."
  (let ((fields (list (cons 'reason reason)
                      (cons 'reason-string
                            (mongodb--pool-reason-string reason))
                      (cons 'duration-ms
                            (mongodb--pool-duration-ms checkout-start)))))
    (when error
      (setq fields (append fields (list (cons 'error error)))))
    (apply #'mongodb--pool-emit-event
           pool 'connection-check-out-failed fields)))

(defun mongodb--pool-emit-checked-out (pool checkout-start conn)
  "Emit POOL checked-out event for CONN using CHECKOUT-START."
  (mongodb--pool-emit-event
   pool 'connection-checked-out
   (cons 'connection conn)
   (cons 'connection-id
         (mongodb--pool-connection-id pool conn))
   (cons 'duration-ms
         (mongodb--pool-duration-ms checkout-start))))

(defun mongodb--pool-service-id-field (service-id)
  "Return a service-id event field when SERVICE-ID is non-nil."
  (and service-id
       (list (cons 'service-id service-id))))

(defun mongodb--pool-normalize-purpose (purpose)
  "Return POOL checkout PURPOSE normalized to a CMAP tracking symbol."
  (pcase purpose
    ((or 'cursor :cursor) 'cursor)
    ((or 'transaction :transaction) 'transaction)
    (_ 'other)))

(defun mongodb--pool-set-connection-purpose (pool conn purpose)
  "Record CONN's checked-out PURPOSE in POOL."
  (setf (mongodb-pool-conn-purposes pool)
        (cons (cons conn (mongodb--pool-normalize-purpose purpose))
              (cl-remove conn
                         (mongodb-pool-conn-purposes pool)
                         :key #'car
                         :test #'eq)))
  conn)

(defun mongodb--pool-forget-connection-purpose (pool conn)
  "Forget CONN's checked-out purpose in POOL."
  (setf (mongodb-pool-conn-purposes pool)
        (cl-remove conn
                   (mongodb-pool-conn-purposes pool)
                   :key #'car
                   :test #'eq)))

(defun mongodb--pool-connection-purpose (pool conn)
  "Return CONN's checked-out purpose in POOL."
  (or (cdr (cl-assoc conn
                     (mongodb-pool-conn-purposes pool)
                     :test #'eq))
      'other))

(defun mongodb--pool-purpose-count (pool purpose)
  "Return how many checked-out POOL connections have PURPOSE."
  (let ((purpose (mongodb--pool-normalize-purpose purpose)))
    (cl-count purpose
              (mongodb-pool-in-use pool)
              :key (lambda (conn)
                     (mongodb--pool-connection-purpose pool conn)))))

(defun mongodb--pool-checkout-timeout-message (pool)
  "Return the wait queue timeout message for POOL."
  (if (mongodb--params-load-balanced-p (mongodb-pool-params pool))
      (format
       "Timeout waiting for connection from the connection pool. maxPoolSize: %s, connections in use by cursors: %d, connections in use by transactions: %d, connections in use by other operations: %d"
       (or (mongodb-pool-max-size pool) 0)
       (mongodb--pool-purpose-count pool 'cursor)
       (mongodb--pool-purpose-count pool 'transaction)
       (mongodb--pool-purpose-count pool 'other))
    "Timed out waiting for a MongoDB pooled connection"))

(defun mongodb--pool-checkout-succeed (pool checkout-start conn purpose)
  "Record CONN as checked out from POOL with PURPOSE and return CONN.

Arguments: POOL, CHECKOUT-START, CONN, PURPOSE."
  (push conn (mongodb-pool-in-use pool))
  (mongodb--pool-set-connection-purpose pool conn purpose)
  (mongodb--pool-maintain-min-size pool)
  (mongodb--pool-emit-checked-out pool checkout-start conn)
  conn)

(defun mongodb--pool-signal-cleared-checkout-error (pool checkout-start)
  "Signal a retryable checkout error because POOL is cleared or paused.

Arguments: POOL, CHECKOUT-START."
  (let ((err `(mongodb-error
               "MongoDB connection pool was cleared before checkout completed"
               :error-labels (,mongodb--retryable-error-label))))
    (mongodb--pool-emit-checkout-failed
     pool checkout-start 'connection-error err)
    (mongodb--signal-error-with-labels
     (cadr err) (mongodb-error-labels err))))

(defun mongodb--pool-checkout-signal-unavailable (pool checkout-start)
  "Signal when POOL cannot service checkout at CHECKOUT-START."
  (cond
   ((mongodb-pool-closed pool)
    (mongodb--pool-emit-checkout-failed pool checkout-start 'pool-closed)
    (signal 'mongodb-error
            (list "MongoDB connection pool is closed")))
   ((mongodb-pool-paused pool)
    (mongodb--pool-signal-cleared-checkout-error pool checkout-start))))

(defun mongodb--pool-next-connection-id (pool)
  "Reserve and return the next monotonically increasing POOL connection id."
  (let ((id (or (mongodb-pool-next-connection-id pool) 1)))
    (setf (mongodb-pool-next-connection-id pool) (1+ id))
    id))

(defun mongodb--pool-record-connection-id (pool conn connection-id)
  "Record CONNECTION-ID for CONN in POOL."
  (setf (mongodb-pool-conn-ids pool)
        (cons (cons conn connection-id)
              (cl-remove conn
                         (mongodb-pool-conn-ids pool)
                         :key #'car
                         :test #'eq)))
  (when (mongodb-conn-p conn)
    (setf (mongodb-conn-pool-connection-id conn) connection-id))
  connection-id)

(defun mongodb--pool-connection-id (pool conn)
  "Return POOL's id for CONN, or nil."
  (or (cdr (cl-assoc conn
                     (mongodb-pool-conn-ids pool)
                     :test #'eq))
      (and (mongodb-conn-p conn)
           (mongodb-conn-pool-connection-id conn))))

(defun mongodb--pool-forget-connection-id (pool conn)
  "Forget POOL's id for CONN."
  (setf (mongodb-pool-conn-ids pool)
        (cl-remove conn
                   (mongodb-pool-conn-ids pool)
                   :key #'car
                   :test #'eq))
  (when (mongodb-conn-p conn)
    (setf (mongodb-conn-pool-connection-id conn) nil)))

(defun mongodb--pool-close-connection (pool conn reason &optional connection-id)
  "Close CONN from POOL and emit a connection closed event with REASON."
  (let ((connection-id (or connection-id
                           (mongodb--pool-connection-id pool conn))))
    (when conn
      (mongodb--pool-untrack-connection pool conn))
    (when connection-id
      (mongodb--pool-emit-event
       pool 'connection-closed
       (cons 'connection conn)
       (cons 'connection-id connection-id)
       (cons 'reason reason)
       (cons 'reason-string
             (mongodb--pool-reason-string reason))))
    (when conn
      (mongodb--pool-forget-connection-id pool conn)
      (unless (and (mongodb-conn-p conn)
                   (mongodb-conn-closed conn))
        (ignore-errors
          (mongodb-disconnect conn))
        (when (mongodb-conn-p conn)
          (setf (mongodb-conn-closed conn) t))))))

(defun mongodb--pool-at-capacity-p (pool)
  "Return non-nil when POOL cannot open another connection."
  (let ((max-size (mongodb-pool-max-size pool)))
    (and max-size
         (>= (mongodb--pool-total-size pool) max-size))))

(defun mongodb--pool-connecting-at-capacity-p (pool)
  "Return non-nil when POOL has reached maxConnecting."
  (>= (or (mongodb-pool-connecting pool) 0)
      (or (mongodb-pool-max-connecting pool)
          mongodb--default-max-connecting)))

(defun mongodb--pool-generation (pool)
  "Return POOL's current CMAP generation."
  (or (mongodb-pool-generation pool) 0))

(defun mongodb--pool-service-generation (pool service-id)
  "Return POOL's current CMAP generation for SERVICE-ID."
  (if service-id
      (or (cdr (assoc service-id
                      (mongodb-pool-service-generations pool)))
          0)
    0))

(defun mongodb--pool-set-service-generation (pool service-id generation)
  "Set POOL's SERVICE-ID generation to GENERATION."
  (setf (mongodb-pool-service-generations pool)
        (cons (cons service-id generation)
              (cl-remove service-id
                         (mongodb-pool-service-generations pool)
                         :key #'car
                         :test #'equal)))
  generation)

(defun mongodb--pool-service-count (pool service-id)
  "Return POOL's connection count for SERVICE-ID."
  (if service-id
      (or (cdr (assoc service-id
                      (mongodb-pool-service-counts pool)))
          0)
    0))

(defun mongodb--pool-remove-service-id (pool service-id)
  "Remove SERVICE-ID accounting entries from POOL."
  (setf (mongodb-pool-service-counts pool)
        (cl-remove service-id
                   (mongodb-pool-service-counts pool)
                   :key #'car
                   :test #'equal))
  (setf (mongodb-pool-service-generations pool)
        (cl-remove service-id
                   (mongodb-pool-service-generations pool)
                   :key #'car
                   :test #'equal))
  service-id)

(defun mongodb--pool-set-service-count (pool service-id count)
  "Set POOL's SERVICE-ID connection count to COUNT."
  (cond
   ((not service-id) nil)
   ((<= count 0)
    (mongodb--pool-remove-service-id pool service-id)
    0)
   (t
    (setf (mongodb-pool-service-counts pool)
          (cons (cons service-id count)
                (cl-remove service-id
                           (mongodb-pool-service-counts pool)
                           :key #'car
                           :test #'equal)))
    count)))

(defun mongodb--pool-increment-service-count (pool service-id)
  "Increment POOL's connection count for SERVICE-ID."
  (when service-id
    (mongodb--pool-set-service-count
     pool service-id
     (1+ (mongodb--pool-service-count pool service-id)))))

(defun mongodb--pool-decrement-service-count (pool service-id)
  "Decrement POOL's connection count for SERVICE-ID."
  (when service-id
    (mongodb--pool-set-service-count
     pool service-id
     (1- (mongodb--pool-service-count pool service-id)))))

(defun mongodb--pool-connection-service-id (conn)
  "Return CONN's load-balanced serviceId, or nil."
  (and (mongodb-conn-p conn)
       (mongodb-conn-service-id conn)))

(defun mongodb--pool-connection-service-id-equal-p (conn service-id)
  "Return non-nil when CONN belongs to SERVICE-ID."
  (equal (mongodb--pool-connection-service-id conn) service-id))

(defun mongodb--pool-generation-state (pool conn)
  "Return POOL generation state for CONN."
  (let ((service-id (mongodb--pool-connection-service-id conn)))
    (cons (mongodb--pool-generation pool)
          (and service-id
               (mongodb--pool-service-generation pool service-id)))))

(defun mongodb--pool-track-connection (pool conn &optional generation)
  "Record CONN as belonging to POOL GENERATION."
  (let ((generation (or generation
                        (mongodb--pool-generation-state pool conn)))
        (existing (cl-assoc conn
                            (mongodb-pool-conn-generations pool)
                            :test #'eq))
        (service-id (mongodb--pool-connection-service-id conn)))
    (when existing
      (mongodb--pool-decrement-service-count
       pool
       (cdr (cl-assoc conn
                      (mongodb-pool-conn-service-ids pool)
                      :test #'eq))))
    (mongodb--pool-increment-service-count pool service-id)
    (setf (mongodb-pool-conn-generations pool)
          (cons (cons conn generation)
                (cl-remove conn
                           (mongodb-pool-conn-generations pool)
                           :key #'car
                           :test #'eq)))
    (setf (mongodb-pool-conn-service-ids pool)
          (cons (cons conn service-id)
                (cl-remove conn
                           (mongodb-pool-conn-service-ids pool)
                           :key #'car
                           :test #'eq))))
  conn)

(defun mongodb--pool-untrack-connection (pool conn)
  "Forget CONN's generation in POOL."
  (when (cl-assoc conn (mongodb-pool-conn-generations pool) :test #'eq)
    (mongodb--pool-decrement-service-count
     pool
     (cdr (cl-assoc conn
                    (mongodb-pool-conn-service-ids pool)
                    :test #'eq)))
    (setf (mongodb-pool-conn-generations pool)
          (cl-remove conn
                     (mongodb-pool-conn-generations pool)
                     :key #'car
                     :test #'eq))
    (setf (mongodb-pool-conn-service-ids pool)
          (cl-remove conn
                     (mongodb-pool-conn-service-ids pool)
                     :key #'car
                     :test #'eq)))
  conn)

(defun mongodb--pool-connection-generation (pool conn)
  "Return CONN's generation in POOL, or nil."
  (cdr (cl-assoc conn
                 (mongodb-pool-conn-generations pool)
                 :test #'eq)))

(defun mongodb--pool-current-generation-connection-p (pool conn)
  "Return non-nil when CONN belongs to POOL's current generation."
  (equal (mongodb--pool-connection-generation pool conn)
         (mongodb--pool-generation-state pool conn)))

(defun mongodb--pool-clear-generation-connection-p
    (pool conn service-id generation service-generation)
  "Return non-nil when CONN is affected by a pool clear.

Arguments: POOL, CONN, SERVICE-ID, GENERATION, SERVICE-GENERATION."
  (let ((conn-generation (mongodb--pool-connection-generation pool conn)))
    (and (or (not service-id)
             (mongodb--pool-connection-service-id-equal-p conn service-id))
         (if service-id
             (<= (or (cdr-safe conn-generation) 0)
                 service-generation)
           (<= (or (car-safe conn-generation) 0)
               generation)))))

(defun mongodb--pool-entry-current-generation-p (pool entry)
  "Return non-nil when ENTRY belongs to POOL's current generation."
  (equal (mongodb--pool-entry-generation entry)
         (mongodb--pool-generation-state
          pool (mongodb--pool-entry-conn entry))))

(defun mongodb--pool-entry-stale-p (pool entry)
  "Return non-nil when POOL ENTRY exceeded maxIdleTimeMS."
  (when-let* ((max-idle (mongodb-pool-max-idle-time pool)))
    (> (- (float-time) (mongodb--pool-entry-idle-since entry))
       max-idle)))

(defun mongodb--pool-prune-available (pool)
  "Close stale or dead available connections from POOL."
  (let ((kept nil)
        (min-size (mongodb-pool-min-size pool))
        (total-size (mongodb--pool-total-size pool)))
    (dolist (entry (mongodb-pool-available pool))
      (let ((conn (mongodb--pool-entry-conn entry)))
        (cond
         ((and (mongodb--pool-entry-generation entry)
               (not (mongodb--pool-entry-current-generation-p pool entry)))
          (setq total-size (1- total-size))
          (mongodb--pool-close-connection pool conn 'stale))
         ((not (mongodb-live-p conn))
          (setq total-size (1- total-size))
          (mongodb--pool-close-connection pool conn 'error))
         ((and (mongodb--pool-entry-stale-p pool entry)
               (> total-size min-size))
          (setq total-size (1- total-size))
          (mongodb--pool-close-connection pool conn 'idle))
         (t
          (push entry kept)))))
    (setf (mongodb-pool-available pool) (nreverse kept)))
  pool)

(defun mongodb--pool-pop-available (pool)
  "Return one live available connection from POOL, or nil."
  (mongodb--pool-prune-available pool)
  (let (conn)
    (while (and (not conn)
                (mongodb-pool-available pool))
      (let* ((entry (pop (mongodb-pool-available pool)))
             (candidate (mongodb--pool-entry-conn entry)))
        (if (mongodb-live-p candidate)
            (setq conn candidate)
          (mongodb--pool-close-connection pool candidate 'error))))
    conn))

(defun mongodb--pool-add-available-connection (pool conn)
  "Add CONN to POOL's available list."
  (push (make-mongodb--pool-entry
         :conn conn
         :idle-since (float-time)
         :generation (mongodb--pool-connection-generation pool conn))
        (mongodb-pool-available pool))
  conn)

(defun mongodb--pool-maintain-min-size (pool)
  "Populate POOL until minPoolSize is satisfied when ready."
  (unless (or (mongodb-pool-closed pool)
              (mongodb-pool-paused pool))
    (let ((min-size (or (mongodb-pool-min-size pool) 0)))
      (while (and (< (mongodb--pool-total-size pool) min-size)
                  (not (mongodb--pool-at-capacity-p pool))
                  (not (mongodb--pool-connecting-at-capacity-p pool)))
        (mongodb--pool-add-available-connection
         pool (mongodb--pool-open-connection pool)))))
  pool)

(defun mongodb--pool-open-connection (pool)
  "Open one MongoDB connection for POOL."
  (let ((connection-id (mongodb--pool-next-connection-id pool))
        (connection-start (float-time)))
    (setf (mongodb-pool-connecting pool)
          (1+ (or (mongodb-pool-connecting pool) 0)))
    (mongodb--pool-emit-event
     pool 'connection-created
     (cons 'connection-id connection-id))
    (unwind-protect
        (condition-case err
            (let ((conn (mongodb-connect (copy-sequence (mongodb-pool-params pool)))))
              (mongodb--pool-record-connection-id pool conn connection-id)
              (mongodb--pool-track-connection pool conn)
              (apply #'mongodb--pool-emit-event
                     pool 'connection-ready
                     (append
                      (list
                       (cons 'connection conn)
                       (cons 'connection-id connection-id))
                      (mongodb--pool-service-id-field
                       (mongodb--pool-connection-service-id conn))
                      (list
                       (cons 'duration-ms
                             (mongodb--pool-duration-ms connection-start)))))
              conn)
          (error
           (mongodb--pool-close-connection pool nil 'error connection-id)
           (signal (car err) (cdr err))))
      (setf (mongodb-pool-connecting pool)
            (max 0 (1- (or (mongodb-pool-connecting pool) 0)))))))

(defun mongodb-pool-open (params)
  "Open a MongoDB connection pool using PARAMS.
Pool options are read from PARAMS or MongoDB URI options, including
maxPoolSize, minPoolSize, maxIdleTimeMS, waitQueueTimeoutMS, and
maxConnecting.  Connections are still ordinary native `mongodb-conn' values."
  (mongodb--params-validate-pool-options params)
  (let* ((pool (make-mongodb-pool
                :params (copy-sequence params)
                :max-size (mongodb--params-max-pool-size params)
                :min-size (mongodb--params-min-pool-size params)
                :max-idle-time (mongodb--params-max-idle-time params)
                :wait-queue-timeout (mongodb--params-wait-queue-timeout params)
                :max-connecting (mongodb--params-max-connecting params)
                :paused t)))
    (mongodb--pool-emit-event
     pool 'connection-pool-created
     (cons 'options (mongodb--pool-created-options pool)))
    (mongodb-pool-ready pool)
    pool))

(defun mongodb-pool-checkout (pool &optional timeout purpose)
  "Check out and return one live MongoDB connection from POOL.
TIMEOUT overrides waitQueueTimeoutMS and is measured in seconds.
A nil pool wait queue timeout has no deadline.  A numeric TIMEOUT of 0 waits
no time.  PURPOSE is one of `cursor', `transaction', or `other' and is used for
load-balanced wait queue diagnostics."
  (let* ((checkout-start (float-time))
         (wait-timeout (or timeout
                           (mongodb-pool-wait-queue-timeout pool)))
         (deadline (and wait-timeout
                        (+ checkout-start wait-timeout)))
         conn)
    (mongodb--pool-emit-event pool 'connection-check-out-started)
    (mongodb--pool-checkout-signal-unavailable pool checkout-start)
    (catch 'done
      (while t
        (mongodb--pool-checkout-signal-unavailable pool checkout-start)
        (setq conn (mongodb--pool-pop-available pool))
        (when conn
          (throw 'done
                 (mongodb--pool-checkout-succeed
                  pool checkout-start conn purpose)))
        (unless (or (mongodb--pool-at-capacity-p pool)
                    (mongodb--pool-connecting-at-capacity-p pool))
          (condition-case err
              (progn
                (setq conn (mongodb--pool-open-connection pool))
                (throw 'done
                       (mongodb--pool-checkout-succeed
                        pool checkout-start conn purpose)))
            (error
             (mongodb--pool-emit-checkout-failed
              pool checkout-start 'connection-error err)
             (signal (car err) (cdr err)))))
        (when (and deadline
                   (<= deadline (float-time)))
          (mongodb--pool-emit-checkout-failed pool checkout-start 'timeout)
          (signal 'mongodb-error
                  (list (mongodb--pool-checkout-timeout-message pool))))
        (accept-process-output nil 0.05)
        (sit-for 0 t)))))

(defun mongodb-pool-release (pool conn)
  "Release CONN back to POOL."
  (unless (memq conn (mongodb-pool-in-use pool))
    (signal 'mongodb-error
            (list "MongoDB connection is not checked out from this pool")))
  (setf (mongodb-pool-in-use pool)
        (delq conn (mongodb-pool-in-use pool)))
  (mongodb--pool-forget-connection-purpose pool conn)
  (mongodb--pool-emit-event
   pool 'connection-checked-in
   (cons 'connection conn)
   (cons 'connection-id (mongodb--pool-connection-id pool conn)))
  (cond
   ((mongodb-pool-closed pool)
    (mongodb--pool-close-connection pool conn 'pool-closed))
   ((and (mongodb-conn-p conn)
         (mongodb-conn-closed conn)
         (not (mongodb--pool-connection-generation pool conn)))
    (mongodb--pool-forget-connection-id pool conn))
   ((not (mongodb-live-p conn))
    (mongodb--pool-close-connection pool conn 'error))
   ((not (mongodb--pool-current-generation-connection-p pool conn))
    (mongodb--pool-close-connection pool conn 'stale))
   (t
    (mongodb--pool-add-available-connection pool conn)))
  (mongodb--pool-maintain-min-size pool)
  pool)

(defun mongodb--pool-interrupt-in-use
    (pool service-id generation service-generation)
  "Close checked-out POOL connections affected by a clear.

Arguments: POOL, SERVICE-ID, GENERATION, SERVICE-GENERATION."
  (dolist (conn (copy-sequence (mongodb-pool-in-use pool)))
    (when (mongodb--pool-clear-generation-connection-p
           pool conn service-id generation service-generation)
      (let ((connection-id (mongodb--pool-connection-id pool conn)))
        (mongodb--pool-close-connection pool conn 'stale)
        (when connection-id
          (mongodb--pool-record-connection-id pool conn connection-id)))))
  pool)

(defun mongodb-pool-clear
    (pool &optional service-id interrupt-in-use-connections)
  "Clear POOL and advance its CMAP generation.
When SERVICE-ID is nil, clear all available connections, mark all checked-out
connections stale, and pause POOL until `mongodb-pool-ready' is called.
When SERVICE-ID is non-nil, clear only load-balanced connections for that
serviceId without pausing POOL.
When INTERRUPT-IN-USE-CONNECTIONS is non-nil, immediately close checked-out
connections affected by the clear instead of waiting for release."
  (unless (mongodb-pool-closed pool)
    (let ((emit-cleared-event t)
          (generation (mongodb--pool-generation pool))
          (service-generation
           (mongodb--pool-service-generation pool service-id)))
      (if service-id
          (mongodb--pool-set-service-generation
           pool service-id
           (1+ (mongodb--pool-service-generation pool service-id)))
        (setq emit-cleared-event (not (mongodb-pool-paused pool)))
        (setf (mongodb-pool-generation pool)
              (1+ (mongodb--pool-generation pool)))
        (setf (mongodb-pool-paused pool) t))
      (when emit-cleared-event
        (let ((fields (mongodb--pool-service-id-field service-id)))
          (when interrupt-in-use-connections
            (setq fields
                  (append fields
                          (list (cons 'interrupt-in-use-connections t)))))
          (apply #'mongodb--pool-emit-event
                 pool 'connection-pool-cleared fields))
        (let (kept)
          (dolist (entry (mongodb-pool-available pool))
            (let ((conn (mongodb--pool-entry-conn entry)))
              (if (or (not service-id)
                      (mongodb--pool-connection-service-id-equal-p
                       conn service-id))
                  (mongodb--pool-close-connection pool conn 'stale)
                (push entry kept))))
          (setf (mongodb-pool-available pool) (nreverse kept))))
      (when interrupt-in-use-connections
        (mongodb--pool-interrupt-in-use
         pool service-id generation service-generation))))
  pool)

(defun mongodb-pool-ready (pool)
  "Mark POOL ready after a clear."
  (when (mongodb-pool-closed pool)
    (signal 'mongodb-error
            (list "MongoDB connection pool is closed")))
  (when (mongodb-pool-paused pool)
    (setf (mongodb-pool-paused pool) nil)
    (mongodb--pool-emit-event pool 'connection-pool-ready))
  (mongodb--pool-maintain-min-size pool)
  pool)

(defun mongodb--pool-monitor-disconnect (pool)
  "Close POOL's dedicated monitor connection, if any."
  (when-let* ((conn (mongodb-pool-monitor-conn pool)))
    (setf (mongodb-pool-monitor-conn pool) nil)
    (ignore-errors
      (mongodb-disconnect conn))))

(defun mongodb--pool-monitor-connection (pool)
  "Return a live dedicated monitor connection for POOL."
  (when (mongodb--params-load-balanced-p (mongodb-pool-params pool))
    (signal 'mongodb-error
            (list "MongoDB load-balanced pools do not use monitor connections")))
  (let ((conn (mongodb-pool-monitor-conn pool)))
    (unless (mongodb-live-p conn)
      (mongodb--pool-monitor-disconnect pool)
      (setq conn (mongodb-connect (copy-sequence (mongodb-pool-params pool))))
      (setf (mongodb-pool-monitor-conn pool) conn))
    conn))

(defun mongodb-pool-monitor-once
    (pool &optional max-await-time-ms timeout)
  "Run one SDAM monitor heartbeat for POOL.
On success, mark a cleared pool ready.  On failure, record the error, close the
dedicated monitor connection, clear the pool, and signal the heartbeat error.
In load-balanced mode, do not open a dedicated monitoring connection.

Arguments: POOL, MAX-AWAIT-TIME-MS, TIMEOUT."
  (when (mongodb-pool-closed pool)
    (signal 'mongodb-error
            (list "MongoDB connection pool is closed")))
  (if (mongodb--params-load-balanced-p (mongodb-pool-params pool))
      (progn
        (setf (mongodb-pool-monitor-error pool) nil)
        (mongodb--pool-monitor-disconnect pool)
        nil)
    (condition-case err
        (let* ((conn (mongodb--pool-monitor-connection pool))
               (hello (mongodb-monitor-once conn max-await-time-ms timeout)))
          (setf (mongodb-pool-monitor-error pool) nil)
          (mongodb-pool-ready pool)
          hello)
      (error
       (setf (mongodb-pool-monitor-error pool) err)
       (mongodb--pool-monitor-disconnect pool)
       (unless (mongodb-pool-closed pool)
         (mongodb-pool-clear pool))
       (signal (car err) (cdr err))))))

(defun mongodb--pool-monitor-tick (pool max-await-time-ms timeout)
  "Run one scheduled SDAM monitor tick for POOL.

Arguments: POOL, MAX-AWAIT-TIME-MS, TIMEOUT."
  (if (mongodb-pool-closed pool)
      (mongodb-pool-stop-monitor pool)
    (ignore-errors
      (mongodb-pool-monitor-once pool max-await-time-ms timeout))))

(defun mongodb-pool-stop-monitor (pool)
  "Stop POOL's SDAM monitor timer and close its monitor connection."
  (when-let* ((timer (mongodb-pool-monitor-timer pool)))
    (ignore-errors
      (cancel-timer timer))
    (setf (mongodb-pool-monitor-timer pool) nil))
  (mongodb--pool-monitor-disconnect pool)
  pool)

(defun mongodb-pool-start-monitor
    (pool &optional heartbeat-seconds max-await-time-ms timeout)
  "Start an SDAM-style monitor timer for POOL.
Successful monitor checks mark a cleared pool ready; failed checks clear and
pause the pool so later successful checks can recover it.

Arguments: POOL, HEARTBEAT-SECONDS, MAX-AWAIT-TIME-MS, TIMEOUT."
  (when (mongodb-pool-closed pool)
    (signal 'mongodb-error
            (list "MongoDB connection pool is closed")))
  (mongodb-pool-stop-monitor pool)
  (unless (mongodb--params-load-balanced-p (mongodb-pool-params pool))
    (let* ((params (mongodb-pool-params pool))
           (heartbeat (or heartbeat-seconds
                          (mongodb--params-heartbeat-frequency params)
                          mongodb-monitor-heartbeat-seconds))
           (max-await (or max-await-time-ms
                          (round (* 1000 heartbeat))))
           (timeout (or timeout
                        (+ 1 (/ (float max-await) 1000.0)))))
      (setf (mongodb-pool-monitor-timer pool)
            (run-at-time 0 heartbeat
                         #'mongodb--pool-monitor-tick
                         pool max-await timeout))))
  pool)

(defun mongodb-pool-disconnect (pool)
  "Close MongoDB POOL.
Available connections are closed immediately.  Checked-out connections remain
associated with POOL and are closed with reason `pool-closed' when released."
  (when pool
    (mongodb-pool-stop-monitor pool)
    (unless (mongodb-pool-closed pool)
      (setf (mongodb-pool-closed pool) t)
      (dolist (entry (mongodb-pool-available pool))
        (mongodb--pool-close-connection
         pool (mongodb--pool-entry-conn entry) 'pool-closed))
      (setf (mongodb-pool-available pool) nil)
      (setf (mongodb-pool-paused pool) nil)
      (setf (mongodb-pool-connecting pool) 0)
      (mongodb--pool-emit-event pool 'connection-pool-closed)))
  pool)

(defmacro mongodb-with-pool-connection (binding &rest body)
  "Run BODY with a connection checked out according to BINDING.
BINDING has the form (CONN POOL &optional TIMEOUT PURPOSE)."
  (declare (indent 1))
  (let ((conn (nth 0 binding))
        (pool (nth 1 binding))
        (timeout (nth 2 binding))
        (purpose (nth 3 binding)))
    `(let ((,conn (mongodb-pool-checkout ,pool ,timeout ,purpose)))
       (unwind-protect
           (progn ,@body)
         (mongodb-pool-release ,pool ,conn)))))

(defun mongodb--pool-resignal-command-error (pool conn err)
  "Clear POOL for checked-out CONN when ERR requires it, then signal ERR."
  (when (mongodb--pool-command-clear-error-p err)
    (mongodb-pool-clear
     pool (mongodb--pool-connection-service-id conn)))
  (signal (car err) (cdr err)))

(defun mongodb-pool-command (pool database command &optional timeout sequences)
  "Run MongoDB COMMAND on DATABASE using one connection from POOL."
  (let ((conn (mongodb-pool-checkout pool nil 'other)))
    (unwind-protect
        (condition-case err
            (mongodb-command conn database command timeout sequences)
          (error
           (mongodb--pool-resignal-command-error pool conn err)))
      (mongodb-pool-release pool conn))))

(defun mongodb-pool-cursor-results
    (pool database collection command first-key
          &optional timeout get-more-options sequences)
  "Run cursor COMMAND from POOL and return all result documents.
The same checked-out connection is used for the initial command, getMore, and
killCursors.  This is required for load-balanced cursor operations and is also a
safe default for ordinary pools.

Arguments: POOL, DATABASE, COLLECTION, COMMAND, FIRST-KEY, TIMEOUT,
GET-MORE-OPTIONS, SEQUENCES."
  (let ((conn (mongodb-pool-checkout pool nil 'cursor)))
    (unwind-protect
        (condition-case err
            (let ((response
                   (mongodb--operation-command
                    conn database command timeout sequences)))
              (mongodb--cursor-results
               conn database collection response first-key get-more-options
               (mongodb-conn-load-balanced conn)))
          (error
           (mongodb--pool-resignal-command-error pool conn err)))
      (mongodb-pool-release pool conn))))

(defun mongodb-pool-find
    (pool database collection &optional filter projection limit skip options timeout)
  "Return documents from COLLECTION in DATABASE using one connection from POOL."
  (let ((option-pairs (mongodb--option-pairs options)))
    (mongodb-pool-cursor-results
     pool database collection
     (mongodb-find-command collection filter projection limit skip option-pairs)
     "firstBatch" timeout
     (mongodb--cursor-get-more-options option-pairs))))

(provide 'mongodb)
;;; mongodb.el ends here
