;;; mongo.el --- MongoDB wire protocol client -*- lexical-binding: t; -*-

;; Copyright (C) 2025-2026 Lucius Chen
;; SPDX-License-Identifier: GPL-3.0-or-later

;; Author: Lucius Chen <chenyh572@gmail.com>
;; Maintainer: Lucius Chen <chenyh572@gmail.com>
;; Version: 0.1.0
;; Package-Requires: ((emacs "29.1"))
;; Keywords: data, tools
;; URL: https://github.com/LuciusChen/mongo.el

;; This file is part of mongo.el.

;; mongo.el is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; mongo.el is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with mongo.el.  If not, see <https://www.gnu.org/licenses/>.

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
(require 'mongo-bson)
(require 'mongo-wire)
(require 'mongo-params)
(require 'mongo-auth)
(require 'seq)
(require 'subr-x)
(require 'gnutls)

(defgroup mongo nil
  "MongoDB wire protocol client."
  :group 'applications)

(defcustom mongo-timeout-seconds 30
  "Seconds to wait for MongoDB wire protocol responses."
  :type 'number
  :group 'mongo)

(defcustom mongo-connect-timeout-seconds 10
  "Seconds to wait while opening a MongoDB socket."
  :type 'number
  :group 'mongo)

(defcustom mongo-server-selection-timeout-seconds 30
  "Seconds to wait while selecting a MongoDB server."
  :type 'number
  :group 'mongo)

(defcustom mongo-local-threshold-seconds 0.015
  "MongoDB server selection latency window in seconds.
This maps to the driver's localThresholdMS connection string option."
  :type 'number
  :group 'mongo)

(defcustom mongo-monitor-heartbeat-seconds 10
  "Seconds between explicit MongoDB monitor heartbeat ticks."
  :type 'number
  :group 'mongo)

(defcustom mongo-monitor-max-await-time-ms 10000
  "Maximum await time in milliseconds for MongoDB awaitable hello monitoring."
  :type 'integer
  :group 'mongo)

(defcustom mongo-pool-event-hook nil
  "Abnormal hook run with one argument for MongoDB pool events.
Each EVENT is an alist with at least `type', `address', and `pool' entries.
Event types currently include `connection-pool-created',
`connection-pool-ready', `connection-pool-cleared',
`connection-pool-closed', `connection-created', `connection-ready',
`connection-closed', `connection-check-out-started',
`connection-check-out-failed', `connection-checked-out', and
`connection-checked-in'.  Pool-cleared events may include
`interrupt-in-use-connections' when checked-out connections are interrupted."
  :type 'hook
  :group 'mongo)

(defcustom mongo-command-event-hook nil
  "Abnormal hook run with one argument for MongoDB command events.
Each EVENT is an alist with at least `type', `command-name',
`database-name', `request-id', and `connection-id' entries.  Event types are
`command-started', `command-succeeded', and `command-failed'.  Bulk write
events include `operation-id'; load-balanced events include `service-id'."
  :type 'hook
  :group 'mongo)

(defcustom mongo-sdam-event-hook nil
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
  :group 'mongo)

(defcustom mongo-tls-verify-server t
  "Non-nil means verify MongoDB TLS certificates and hostnames by default."
  :type 'boolean
  :group 'mongo)

(defcustom mongo-tls-trustfiles nil
  "List of PEM certificate authority files for MongoDB TLS verification."
  :type '(repeat file)
  :group 'mongo)

(defcustom mongo-tls-keylist nil
  "Client certificate key list for MongoDB TLS.
Each element has the form (KEY-FILE CERT-FILE), matching `gnutls-negotiate'."
  :type '(repeat (list file file))
  :group 'mongo)

(defconst mongo-version "0.1.0")

(defconst mongo--client-min-wire-version 6
  "Minimum MongoDB wire version supported by this OP_MSG client.")

(defconst mongo--client-max-wire-version 25
  "Maximum MongoDB wire version this client declares compatible.")

(defconst mongo--client-min-wire-version-release "MongoDB 3.6"
  "Server release corresponding to `mongo--client-min-wire-version'.")

(defconst mongo--default-max-bson-object-size (* 16 1024 1024)
  "Default MongoDB max BSON object size when hello omits the field.")

(defconst mongo--default-max-message-size-bytes 48000000
  "Default MongoDB max wire message size when hello omits the field.")

(defconst mongo--default-max-write-batch-size 100000
  "Default MongoDB max write batch size when hello omits the field.")

(defconst mongo--write-batch-message-safety-bytes 1024
  "Conservative byte allowance for driver metadata added to write batches.")

(defconst mongo--round-trip-time-alpha 0.2
  "MongoDB SDAM average RTT EWMA weight.")

(defconst mongo--sensitive-command-names
  '("authenticate" "saslStart" "saslContinue" "getnonce"
    "createUser" "updateUser" "copydbgetnonce" "copydbsaslstart"
    "copydb")
  "MongoDB command names whose monitoring event documents must be redacted.")

(defconst mongo--write-command-names
  '("insert" "update" "delete" "findAndModify" "findandmodify"
    "create" "drop" "dropDatabase" "createIndexes" "dropIndexes"
    "renameCollection" "collMod" "bulkWrite"
    "createUser" "updateUser" "dropUser"
    "grantRolesToUser" "revokeRolesFromUser")
  "MongoDB command names that require a writable server.")

(defconst mongo--read-command-names
  '("aggregate" "collStats" "count" "dbStats" "distinct" "explain" "find"
    "listCollections" "listDatabases" "listIndexes" "mapReduce")
  "MongoDB command names that may carry OP_MSG $readPreference.")

(defconst mongo--retryable-read-command-names
  '("aggregate" "collStats" "count" "dbStats" "distinct" "find"
    "listCollections" "listDatabases" "listIndexes")
  "MongoDB read command names that may be retried once.")

(defconst mongo--retryable-read-error-codes
  '(6 7 89 91 134 189 262 9001 10107 11600 11602 13435 13436)
  "MongoDB server error codes that make a read retryable.")

(defconst mongo--retryable-write-error-codes
  '(6 7 89 91 189 262 9001 10107 11600 11602 13435 13436)
  "MongoDB server error codes that make a write retryable.")

(defconst mongo--state-change-error-code-names
  '("InterruptedAtShutdown" "InterruptedDueToReplStateChange"
    "NotMaster" "NotMasterNoSlaveOk" "NotPrimaryNoSecondaryOk"
    "NotPrimaryOrSecondary" "NotWritablePrimary" "PrimarySteppedDown"
    "ShutdownInProgress")
  "MongoDB command error names that imply a server state change.")

(defconst mongo--unknown-transaction-commit-result-label
  "UnknownTransactionCommitResult")

(defconst mongo--transient-transaction-error-label
  "TransientTransactionError")

(defconst mongo--system-overloaded-error-label "SystemOverloadedError")

(defconst mongo--retryable-error-label "RetryableError")

(defconst mongo--retryable-write-error-label "RetryableWriteError")

(defconst mongo--commit-non-unknown-write-concern-error-codes '(79 100)
  "Commit write concern error codes that do not imply unknown commit result.
79 is UnknownReplWriteConcern and 100 is CannotSatisfyWriteConcern /
UnsatisfiableWriteConcern.")

(defvar mongo--retryable-write-context nil
  "Non-nil when a helper is executing a supported retryable write operation.")

(defvar mongo--command-event-context nil
  "Dynamic context for command monitoring around low-level OP_MSG sends.")

(defvar mongo--command-operation-id nil
  "Dynamic command monitoring operation id for related commands.")

(defvar mongo--next-command-operation-id 0
  "Last allocated command monitoring operation id.")

(defvar mongo--next-topology-id 0
  "Last allocated SDAM topology id.")

(defvar mongo--suppress-command-events nil
  "Non-nil suppresses command monitoring events for internal monitor heartbeats.")

(cl-defstruct mongo-server-description
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

(cl-defstruct mongo-topology-description
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

(cl-defstruct mongo--pool-entry
  conn
  idle-since
  generation)

(cl-defstruct mongo--server-candidate
  "A connected MongoDB server candidate during initial server selection."
  conn
  hello
  server)

(cl-defstruct mongo-pool
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

(cl-defstruct mongo-conn
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
  closed)

;;;; Wire transport

(defun mongo--maybe-compress-request (conn document message)
  "Return MESSAGE, optionally compressed for CONN and DOCUMENT."
  (let ((compressor (car (mongo-conn-compressors conn))))
    (if (and compressor
             (mongo--command-compressible-p document))
        (mongo--make-op-compressed message compressor)
      message)))

(defun mongo--wait-for-bytes (conn count timeout)
  "Wait until CONN buffer contains at least COUNT bytes."
  (let* ((proc (mongo-conn-process conn))
         (buffer (mongo-conn-buffer conn))
         (deadline (+ (float-time) timeout)))
    (while (and (process-live-p proc)
                (< (with-current-buffer buffer (buffer-size)) count)
                (< (float-time) deadline))
      (accept-process-output proc 0.05)
      (sit-for 0 t))
    (unless (process-live-p proc)
      (signal 'mongo-error
              (list "MongoDB connection closed while waiting for response")))
    (when (< (with-current-buffer buffer (buffer-size)) count)
      (signal 'mongo-error
              (list "Timed out waiting for MongoDB response")))))

(defun mongo--recv-message-frame
    (conn &optional timeout expected-response-to allow-more-to-come)
  "Read one OP_MSG wire message frame from CONN."
  (let* ((buffer (mongo-conn-buffer conn))
         (timeout (or timeout
                      (mongo-conn-socket-timeout conn)
                      mongo-timeout-seconds))
         length message)
    (mongo--wait-for-bytes conn 4 timeout)
    (setq length
          (with-current-buffer buffer
            (mongo--read-int32-from-string
             (buffer-substring-no-properties (point-min) (+ (point-min) 4)))))
    (when (< length 16)
      (signal 'mongo-error
              (list (format "Invalid MongoDB wire message length: %s" length))))
    (mongo--wait-for-bytes conn length timeout)
    (setq message
          (with-current-buffer buffer
            (prog1 (buffer-substring-no-properties
                    (point-min)
                    (+ (point-min) length))
              (delete-region (point-min) (+ (point-min) length)))))
    (let ((frame (mongo--decode-message-frame message allow-more-to-come)))
      (mongo--validate-response-to frame expected-response-to)
      frame)))

(defun mongo--recv-message
    (conn &optional timeout expected-response-to allow-more-to-come)
  "Read one OP_MSG wire message from CONN."
  (mongo--decoded-message-document
   (mongo--recv-message-frame
    conn timeout expected-response-to allow-more-to-come)))

(defun mongo--recv-handshake-message (conn &optional timeout expected-response-to)
  "Read one legacy handshake reply from CONN."
  (let* ((buffer (mongo-conn-buffer conn))
         (timeout (or timeout
                      (mongo-conn-socket-timeout conn)
                      mongo-timeout-seconds))
         length message)
    (mongo--wait-for-bytes conn 4 timeout)
    (setq length
          (with-current-buffer buffer
            (mongo--read-int32-from-string
             (buffer-substring-no-properties (point-min) (+ (point-min) 4)))))
    (when (< length 16)
      (signal 'mongo-error
              (list (format "Invalid MongoDB wire message length: %s" length))))
    (mongo--wait-for-bytes conn length timeout)
    (setq message
          (with-current-buffer buffer
            (prog1 (buffer-substring-no-properties
                    (point-min)
                    (+ (point-min) length))
              (delete-region (point-min) (+ (point-min) length)))))
    (let ((frame (mongo--decode-op-reply-frame message)))
      (mongo--validate-response-to frame expected-response-to)
      (mongo--decoded-message-document frame))))

(defun mongo--next-request-id (conn)
  "Return the next request id for CONN."
  (let ((next (1+ (or (mongo-conn-request-id conn) 0))))
    (setf (mongo-conn-request-id conn) next)
    next))

(defun mongo--send-document-with-flags
    (conn document &optional sequences flag-bits)
  "Send DOCUMENT as an OP_MSG request over CONN with FLAG-BITS.
SEQUENCES, when non-nil, is a list of OP_MSG document sequences."
  (mongo--validate-op-msg-size conn document sequences)
  (let* ((request-id (mongo--next-request-id conn))
         (message (mongo--make-op-msg
                   request-id document flag-bits nil sequences))
         (wire-message (mongo--maybe-compress-request conn document message)))
    (mongo--command-event-started conn request-id)
    (condition-case err
        (progn
          (process-send-string
           (mongo-conn-process conn)
           wire-message)
          request-id)
      (error
       (mongo--command-event-failed conn err)
       (signal (car err) (cdr err))))))

(defun mongo--send-document (conn document &optional sequences)
  "Send DOCUMENT as an OP_MSG request over CONN.
SEQUENCES, when non-nil, is a list of OP_MSG document sequences."
  (mongo--send-document-with-flags conn document sequences))

(defun mongo--send-handshake (conn document)
  "Send initial legacy handshake DOCUMENT over CONN."
  (let ((request-id (mongo--next-request-id conn)))
    (process-send-string
     (mongo-conn-process conn)
     (mongo--make-op-query request-id "admin" document))
    request-id))

;;;; Hello limits

(defun mongo--hello-positive-integer (hello field default)
  "Return positive integer FIELD from HELLO, or DEFAULT when omitted."
  (let ((value (cdr (assoc field hello))))
    (cond
     ((null value) default)
     ((and (integerp value)
           (> value 0))
      value)
     (t
      (signal 'mongo-error
              (list (format "MongoDB hello field %s must be a positive integer, got %S"
                            field value)))))))

(defun mongo--apply-hello-limits (conn hello)
  "Cache MongoDB command size and write batch limits from HELLO on CONN."
  (setf (mongo-conn-max-bson-object-size conn)
        (mongo--hello-positive-integer
         hello "maxBsonObjectSize" mongo--default-max-bson-object-size))
  (setf (mongo-conn-max-message-size-bytes conn)
        (mongo--hello-positive-integer
         hello "maxMessageSizeBytes" mongo--default-max-message-size-bytes))
  (setf (mongo-conn-max-write-batch-size conn)
        (mongo--hello-positive-integer
         hello "maxWriteBatchSize" mongo--default-max-write-batch-size))
  conn)

(defun mongo--max-write-batch-size (conn)
  "Return CONN's effective MongoDB max write batch size."
  (or (and (mongo-conn-p conn)
           (mongo-conn-max-write-batch-size conn))
      mongo--default-max-write-batch-size))

(defun mongo--max-bson-object-size (conn)
  "Return CONN's effective MongoDB max BSON object size."
  (or (and (mongo-conn-p conn)
           (mongo-conn-max-bson-object-size conn))
      mongo--default-max-bson-object-size))

(defun mongo--max-message-size-bytes (conn)
  "Return CONN's effective MongoDB max wire message size."
  (or (and (mongo-conn-p conn)
           (mongo-conn-max-message-size-bytes conn))
      mongo--default-max-message-size-bytes))

;;;; Command helpers

(defun mongo--os-type ()
  "Return the MongoDB handshake os.type value for this Emacs."
  (pcase system-type
    ('darwin "Darwin")
    ((or 'gnu 'gnu/linux) "Linux")
    ('windows-nt "Windows")
    ('berkeley-unix "BSD")
    ('cygwin "Cygwin")
    (_ "unknown")))

(defun mongo--client-metadata (&optional app-name)
  "Return MongoDB handshake client metadata.
APP-NAME, when non-nil, is sent as client.application.name."
  `(,@(when (mongo--validate-app-name app-name)
        `(("application" . (("name" . ,app-name)))))
    ("driver" . (("name" . "mongo.el")
                 ("version" . ,mongo-version)))
    ("os" . (("type" . ,(mongo--os-type))))
    ("platform" . ,(format "Emacs %s" emacs-version))))

(defun mongo--initial-handshake-command
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
    ("client" . ,(mongo--client-metadata app-name))
    ,@(when load-balanced
        '(("loadBalanced" . t)))
    ,@(when compressors
        `(("compression" . ,(apply #'vector compressors))))
    ,@(when (mongo--credential-scram-negotiation-p credential)
        `(("saslSupportedMechs" .
           ,(format "%s.%s"
                    (mongo--credential-source credential)
                    (mongo--credential-username credential)))))
    ,@(when speculative-auth
        `(("speculativeAuthenticate" .
           ,(mongo--scram-start-command speculative-auth t))))))

(defun mongo--truthy-handshake-value-p (value)
  "Return non-nil when handshake VALUE represents truth."
  (or (eq value t)
      (and (numberp value) (> value 0))
      (equal value "1")
      (equal value "true")))

(defun mongo--post-handshake-hello-command (hello modern-initial-p)
  "Return the command name to use for subsequent hello probes.
HELLO is the initial handshake response.  MODERN-INITIAL-P is non-nil when
the initial handshake was already sent as OP_MSG hello."
  (if (or modern-initial-p
          (mongo--truthy-handshake-value-p
           (cdr (assoc "helloOk" hello))))
      "hello"
    "isMaster"))

(defun mongo--session-command-p (pairs)
  "Return non-nil when command PAIRS should carry a MongoDB lsid."
  (not (member (caar pairs)
               '("endSessions" "hello" "isMaster" "ismaster"))))

(defun mongo--sdam-command-p (pairs)
  "Return non-nil when command PAIRS are SDAM hello commands."
  (member (caar pairs) '("hello" "isMaster" "ismaster")))

(defun mongo--cluster-time-command-p (pairs)
  "Return non-nil when command PAIRS may carry MongoDB $clusterTime."
  (not (mongo--sdam-command-p pairs)))

(defun mongo--timestamp-components (value)
  "Return (SECONDS . INCREMENT) for MongoDB timestamp VALUE, or nil."
  (cond
   ((mongo-timestamp-p value)
    (cons (mongo-timestamp-seconds value)
          (mongo-timestamp-increment value)))
   ((and (mongo--document-value-p value)
         (assoc "$timestamp" (mongo--document-pairs value)))
    (let* ((timestamp (cdr (assoc "$timestamp"
                                  (mongo--document-pairs value))))
           (pairs (mongo--document-pairs timestamp))
           (seconds (cdr (assoc "t" pairs)))
           (increment (cdr (assoc "i" pairs))))
      (and (integerp seconds)
           (integerp increment)
           (cons seconds increment))))))

(defun mongo--cluster-time-components (cluster-time)
  "Return timestamp components for CLUSTER-TIME, or nil."
  (when cluster-time
    (mongo--timestamp-components
     (cdr (assoc "clusterTime"
                 (mongo--document-pairs cluster-time))))))

(defun mongo--cluster-time-newer-p (left right)
  "Return non-nil when cluster time LEFT is newer than RIGHT."
  (let ((l (mongo--cluster-time-components left))
        (r (mongo--cluster-time-components right)))
    (and l
         (or (not r)
             (> (car l) (car r))
             (and (= (car l) (car r))
                  (> (cdr l) (cdr r)))))))

(defun mongo--max-cluster-time (left right)
  "Return the newest MongoDB cluster time among LEFT and RIGHT."
  (if (mongo--cluster-time-newer-p right left)
      right
    left))

(defun mongo--extended-json-wrapper-p (pairs key)
  "Return non-nil when PAIRS represent a single Extended JSON KEY wrapper."
  (and (= (length pairs) 1)
       (assoc key pairs)))

(defun mongo--extended-json-to-bson-value (value)
  "Return VALUE with Extended JSON wrappers restored to BSON wrappers.
This is used when a server-returned document, such as $clusterTime, must be
sent back to MongoDB without changing BSON types used in signatures."
  (cond
   ((vectorp value)
    (vconcat (mapcar #'mongo--extended-json-to-bson-value
                     (append value nil))))
   ((and (consp value)
         (consp (car value)))
    (let ((pairs (mongo--document-pairs value)))
      (cond
       ((mongo--extended-json-wrapper-p pairs "$timestamp")
        (let* ((timestamp (cdr (assoc "$timestamp" pairs)))
               (timestamp-pairs (mongo--document-pairs timestamp)))
          (mongo-timestamp
           (cdr (assoc "t" timestamp-pairs))
           (cdr (assoc "i" timestamp-pairs)))))
       ((mongo--extended-json-wrapper-p pairs "$binary")
        (let* ((binary (cdr (assoc "$binary" pairs)))
               (binary-pairs (mongo--document-pairs binary))
               (subtype (cdr (assoc "subType" binary-pairs)))
               (bytes (cdr (assoc "bytes" binary-pairs))))
          (mongo-binary
           (string-to-number (or subtype "0") 16)
           (mongo--base64-decode bytes))))
       ((mongo--extended-json-wrapper-p pairs "$oid")
        (mongo-object-id (cdr (assoc "$oid" pairs))))
       ((mongo--extended-json-wrapper-p pairs "$date")
        (mongo-datetime (cdr (assoc "$date" pairs))))
       ((mongo--extended-json-wrapper-p pairs "$numberDecimal")
        (mongo-decimal128 (cdr (assoc "$numberDecimal" pairs))))
       ((mongo--extended-json-wrapper-p pairs "$undefined")
        (mongo-undefined))
       ((mongo--extended-json-wrapper-p pairs "$dbPointer")
        (let* ((db-pointer (cdr (assoc "$dbPointer" pairs)))
               (db-pointer-pairs (mongo--document-pairs db-pointer))
               (object-id (cdr (assoc "$id" db-pointer-pairs))))
          (mongo-db-pointer
           (cdr (assoc "$ref" db-pointer-pairs))
           (if (and (mongo--document-value-p object-id)
                    (assoc "$oid" (mongo--document-pairs object-id)))
               (cdr (assoc "$oid" (mongo--document-pairs object-id)))
             object-id))))
       ((and (assoc "$code" pairs)
             (seq-every-p (lambda (pair)
                            (member (car pair) '("$code" "$scope")))
                          pairs))
        (mongo-code
         (cdr (assoc "$code" pairs))
         (when-let* ((scope (assoc "$scope" pairs)))
           (mongo--extended-json-to-bson-value (cdr scope)))))
       ((mongo--extended-json-wrapper-p pairs "$symbol")
        (mongo-symbol (cdr (assoc "$symbol" pairs))))
       ((mongo--extended-json-wrapper-p pairs "$regularExpression")
        (let* ((regex (cdr (assoc "$regularExpression" pairs)))
               (regex-pairs (mongo--document-pairs regex)))
          (mongo-regex
           (cdr (assoc "pattern" regex-pairs))
           (cdr (assoc "options" regex-pairs)))))
       ((mongo--extended-json-wrapper-p pairs "$minKey")
        (mongo-min-key))
       ((mongo--extended-json-wrapper-p pairs "$maxKey")
        (mongo-max-key))
       (t
        (mongo-document
         (mapcar (lambda (pair)
                   (cons (car pair)
                         (mongo--extended-json-to-bson-value (cdr pair))))
                 pairs))))))
   ((listp value)
    (mapcar #'mongo--extended-json-to-bson-value value))
   (t value)))

(defun mongo-extended-json-to-bson-value (value)
  "Return VALUE with Extended JSON wrappers restored to BSON wrappers.
This is useful for callers that need to feed server-returned Extended JSON
values back into MongoDB command documents without losing BSON wire types."
  (mongo--extended-json-to-bson-value value))

(defun mongo--cluster-time-for-command (cluster-time)
  "Return CLUSTER-TIME normalized for BSON command encoding."
  (and cluster-time
       (mongo--extended-json-to-bson-value cluster-time)))

(defun mongo--cluster-time-to-send (conn)
  "Return the highest MongoDB cluster time CONN should gossip, or nil."
  (when (>= (or (mongo-conn-max-wire-version conn) 0) 6)
    (mongo--max-cluster-time
     (mongo-conn-cluster-time conn)
     (mongo-conn-session-cluster-time conn))))

(defun mongo-advance-cluster-time (conn cluster-time)
  "Advance CONN's session cluster time to CLUSTER-TIME if it is newer.
This mirrors MongoDB driver's `advanceClusterTime' behavior for explicit
session state without advancing the deployment-level cluster time."
  (when (mongo--cluster-time-newer-p
         cluster-time
         (mongo-conn-session-cluster-time conn))
    (setf (mongo-conn-session-cluster-time conn) cluster-time))
  conn)

(defun mongo--advance-cluster-time-from-response (conn command response)
  "Advance CONN cluster time using RESPONSE to COMMAND."
  (let ((pairs (mongo--document-pairs command)))
    (unless (mongo--sdam-command-p pairs)
      (when-let* ((cluster-time (cdr (assoc "$clusterTime" response))))
        (when (mongo--cluster-time-newer-p
               cluster-time
               (mongo-conn-cluster-time conn))
          (setf (mongo-conn-cluster-time conn) cluster-time))
        (mongo-advance-cluster-time conn cluster-time)))))

(defun mongo--advance-transaction-recovery-token-from-response
    (conn transaction-state response)
  "Cache latest transaction recoveryToken from RESPONSE on CONN."
  (when (and transaction-state
             (mongo--ok-p response))
    (when-let* ((token (cdr (assoc "recoveryToken" response))))
      (setf (mongo-conn-transaction-recovery-token conn) token)))
  conn)

(defun mongo--read-preference-command-p (pairs)
  "Return non-nil when command PAIRS may carry $readPreference."
  (member (format "%s" (caar pairs))
          mongo--read-command-names))

(defun mongo--command-with-db
    (command database &optional server-api session-id read-preference
             read-concern write-concern txn-number transaction-state
             transaction-read-concern cluster-time)
  "Return COMMAND with MongoDB driver-level metadata added."
  (let ((pairs (copy-sequence
                (mongo--document-pairs command))))
    (unless (assoc "$db" pairs)
      (setq pairs (append pairs (list (cons "$db" database)))))
    (dolist (field (mongo--server-api-fields server-api))
      (unless (assoc (car field) pairs)
        (setq pairs (append pairs (list field)))))
    (when (and cluster-time
               (mongo--cluster-time-command-p pairs)
               (not (assoc "$clusterTime" pairs)))
      (setq pairs
            (append pairs
                    (list (cons "$clusterTime"
                                (mongo--cluster-time-for-command
                                 cluster-time))))))
    (when (and session-id
               (mongo--session-command-p pairs)
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
                            (mongo--read-concern-command-document
                             transaction-read-concern))))
      (setq pairs
            (append pairs (list (cons "readConcern" value)))))
    (when-let* ((value (and (not transaction-state)
                            (mongo--read-preference-command-p pairs)
                            (not (assoc "$readPreference" pairs))
                            (mongo--read-preference-document
                             read-preference))))
      (setq pairs
            (append pairs (list (cons "$readPreference" value)))))
    (when-let* ((value (and (not transaction-state)
                            (mongo--read-command-p pairs)
                            (not (assoc "readConcern" pairs))
                            (mongo--read-concern-document
                             read-concern))))
      (setq pairs
            (append pairs (list (cons "readConcern" value)))))
    (when-let* ((value (and (not transaction-state)
                            (mongo--write-command-p pairs)
                            (not (assoc "writeConcern" pairs))
                            (mongo--write-concern-document
                             write-concern))))
      (setq pairs
            (append pairs (list (cons "writeConcern" value)))))
    pairs))

(defun mongo--ok-p (response)
  "Return non-nil when RESPONSE is an ok MongoDB command response."
  (let ((ok (cdr (assoc "ok" response))))
    (or (eq ok t)
        (and (numberp ok)
             (> ok 0))
        (equal ok "1"))))

(defun mongo-response-ok-p (response)
  "Return non-nil when RESPONSE is an ok MongoDB command response."
  (mongo--ok-p response))

(defun mongo--response-message (response)
  "Return an error message from MongoDB command RESPONSE."
  (or (cdr (assoc "errmsg" response))
      (cdr (assoc "$err" response))
      (format "MongoDB command failed: %S" response)))

(defun mongo--label-list (labels)
  "Return LABELS as a list of strings."
  (cond
   ((null labels) nil)
   ((vectorp labels) (append labels nil))
   ((and (listp labels)
         (not (stringp labels)))
    labels)
   ((stringp labels) (list labels))
   (t nil)))

(defun mongo--add-error-labels (&rest label-groups)
  "Return de-duplicated error labels from LABEL-GROUPS."
  (let (labels)
    (dolist (group label-groups)
      (dolist (label (mongo--label-list group))
        (unless (member label labels)
          (push label labels))))
    (nreverse labels)))

(defun mongo--response-error-labels (response)
  "Return top-level MongoDB errorLabels from RESPONSE."
  (mongo--label-list (cdr (assoc "errorLabels" response))))

(defun mongo-error-labels (condition)
  "Return MongoDB error labels stored on CONDITION.
CONDITION may be an error object captured by `condition-case' or a raw signal
data list."
  (let ((data (if (and (consp condition)
                       (symbolp (car condition)))
                  (cdr condition)
                condition)))
    (mongo--label-list (plist-get (cdr data) :error-labels))))

(defun mongo-error-has-label-p (condition label)
  "Return non-nil when CONDITION has MongoDB error LABEL."
  (member label (mongo-error-labels condition)))

(defun mongo--transaction-unpin-for-labels (conn labels)
  "Unpin CONN's transaction when LABELS require it."
  (when (and (mongo-conn-p conn)
             (mongo--label-list labels)
             (or (member mongo--transient-transaction-error-label
                         (mongo--label-list labels))
                 (member mongo--unknown-transaction-commit-result-label
                         (mongo--label-list labels))))
    (mongo--unpin-transaction conn))
  conn)

(defun mongo--condition-message (condition)
  "Return the primary error message from CONDITION."
  (if (and (consp condition)
           (eq (car condition) 'mongo-error)
           (stringp (cadr condition)))
      (cadr condition)
    (error-message-string condition)))

(defun mongo--signal-error-with-labels (message labels)
  "Signal `mongo-error' with MESSAGE and MongoDB error LABELS."
  (let ((labels (mongo--add-error-labels labels)))
    (if labels
        (signal 'mongo-error (list message :error-labels labels))
      (signal 'mongo-error (list message)))))

(defun mongo--signal-transaction-error-with-labels (conn message labels)
  "Signal MongoDB transaction error MESSAGE after applying LABELS side effects."
  (mongo--transaction-unpin-for-labels conn labels)
  (mongo--signal-error-with-labels message labels))

(defun mongo--write-error-message (response)
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

(defun mongo--command-name (command)
  "Return the command name from MongoDB COMMAND."
  (let ((pairs (mongo--document-pairs command)))
    (when pairs
      (format "%s" (caar pairs)))))

(defun mongo--sensitive-command-p (command)
  "Return non-nil when COMMAND must be redacted in monitoring events."
  (let ((name (mongo--command-name command))
        (pairs (mongo--document-pairs command)))
    (or (member name mongo--sensitive-command-names)
        (and (member name '("hello" "isMaster" "ismaster"))
             (assoc "speculativeAuthenticate" pairs)))))

(defun mongo--command-event-document (document sequences)
  "Return DOCUMENT as it should appear in command-started events.
OP_MSG SEQUENCES are exposed as BSON array fields on the command event
document, matching MongoDB command monitoring semantics."
  (let ((pairs (copy-sequence (mongo--document-pairs document))))
    (dolist (sequence sequences)
      (setq pairs
            (append
             (cl-remove (car sequence) pairs :key #'car :test #'equal)
             (list sequence))))
    pairs))

(defun mongo--redact-command-event-document (document sensitive)
  "Return command monitoring DOCUMENT, redacted when SENSITIVE is non-nil."
  (if sensitive nil document))

(defun mongo--redact-command-event-failure (failure sensitive)
  "Return command monitoring FAILURE, redacted when SENSITIVE is non-nil."
  (if (not sensitive)
      failure
    (when (mongo--document-value-p failure)
      (let ((pairs (mongo--document-pairs failure))
            redacted)
        (dolist (key '("code" "codeName" "errorLabels"))
          (when-let* ((entry (assoc key pairs)))
            (push entry redacted)))
        (nreverse redacted)))))

(defun mongo--command-event-server-connection-id (conn)
  "Return CONN's server-generated connectionId, or nil."
  (cdr (assoc "connectionId" (mongo-conn-last-hello conn))))

(defun mongo--next-command-operation-id ()
  "Return the next command monitoring operation id."
  (setq mongo--next-command-operation-id
        (1+ mongo--next-command-operation-id)))

(defun mongo--command-event-common-fields
    (conn database command-name request-id)
  "Return common command monitoring fields for CONN."
  (let ((fields `((connection . ,conn)
                  (connection-id . ,(mongo--conn-address conn))
                  (database-name . ,database)
                  (command-name . ,command-name)
                  (request-id . ,request-id))))
    (when-let* ((operation-id
                 (plist-get mongo--command-event-context :operation-id)))
      (setq fields (append fields (list (cons 'operation-id operation-id)))))
    (when-let* ((server-id (mongo--command-event-server-connection-id conn)))
      (setq fields (append fields
                           (list (cons 'server-connection-id server-id)))))
    (when-let* ((service-id (and (mongo-conn-load-balanced conn)
                                 (mongo-conn-service-id conn))))
      (setq fields (append fields (list (cons 'service-id service-id)))))
    fields))

(defun mongo--emit-command-event (type &rest fields)
  "Emit MongoDB command monitoring event TYPE with FIELDS."
  (unless mongo--suppress-command-events
    (let ((event `((type . ,type)
                   ,@fields)))
      (run-hook-with-args 'mongo-command-event-hook event)
      event)))

(defun mongo--command-event-started (conn request-id)
  "Emit a command-started event for CONN and REQUEST-ID."
  (unless (or mongo--suppress-command-events
              (not mongo-command-event-hook)
              (not mongo--command-event-context)
              (plist-get mongo--command-event-context :started))
    (let* ((database
            (plist-get mongo--command-event-context :database-name))
           (command-name
            (plist-get mongo--command-event-context :command-name))
           (command
            (plist-get mongo--command-event-context :command))
           (sensitive
            (plist-get mongo--command-event-context :sensitive))
           (started-at (float-time)))
      (setq mongo--command-event-context
            (plist-put mongo--command-event-context :request-id request-id))
      (setq mongo--command-event-context
            (plist-put mongo--command-event-context :started-at started-at))
      (setq mongo--command-event-context
            (plist-put mongo--command-event-context :started t))
      (apply #'mongo--emit-command-event
             'command-started
             (append
              (mongo--command-event-common-fields
               conn database command-name request-id)
              (list
               (cons 'command
                     (mongo--redact-command-event-document
                      command sensitive))))))))

(defun mongo--command-event-duration-ms ()
  "Return the current command monitoring context duration in milliseconds."
  (mongo--pool-duration-ms
   (or (plist-get mongo--command-event-context :started-at)
       (float-time))))

(defun mongo--command-event-finished-p ()
  "Return non-nil when current command monitoring context already finished."
  (plist-get mongo--command-event-context :finished))

(defun mongo--command-event-failed (conn failure)
  "Emit command-failed for CONN with FAILURE unless already emitted."
  (unless (or mongo--suppress-command-events
              (not mongo-command-event-hook)
              (not mongo--command-event-context)
              (mongo--command-event-finished-p))
    (let ((request-id (plist-get mongo--command-event-context :request-id)))
      (when request-id
        (let* ((database
                (plist-get mongo--command-event-context :database-name))
               (command-name
                (plist-get mongo--command-event-context :command-name))
               (sensitive
                (plist-get mongo--command-event-context :sensitive)))
          (setq mongo--command-event-context
                (plist-put mongo--command-event-context :finished t))
          (apply #'mongo--emit-command-event
                 'command-failed
                 (append
                  (mongo--command-event-common-fields
                   conn database command-name request-id)
                  (list
                   (cons 'duration-ms
                         (mongo--command-event-duration-ms))
                   (cons 'failure
                         (mongo--redact-command-event-failure
                          failure sensitive))))))))))

(defun mongo--command-event-succeeded (conn reply)
  "Emit command-succeeded for CONN with REPLY unless already emitted."
  (unless (or mongo--suppress-command-events
              (not mongo-command-event-hook)
              (not mongo--command-event-context)
              (mongo--command-event-finished-p))
    (let ((request-id (plist-get mongo--command-event-context :request-id)))
      (when request-id
        (let* ((database
                (plist-get mongo--command-event-context :database-name))
               (command-name
                (plist-get mongo--command-event-context :command-name))
               (sensitive
                (plist-get mongo--command-event-context :sensitive)))
          (setq mongo--command-event-context
                (plist-put mongo--command-event-context :finished t))
          (apply #'mongo--emit-command-event
                 'command-succeeded
                 (append
                  (mongo--command-event-common-fields
                   conn database command-name request-id)
                  (list
                   (cons 'duration-ms
                         (mongo--command-event-duration-ms))
                   (cons 'reply
                          (mongo--redact-command-event-document
                           reply sensitive))))))))))

(defun mongo--emit-sdam-event (type &rest fields)
  "Emit MongoDB SDAM monitoring event TYPE with FIELDS."
  (when mongo-sdam-event-hook
    (let ((event `((type . ,type)
                   ,@fields)))
      (run-hook-with-args 'mongo-sdam-event-hook event)
      event)))

(defun mongo--sdam-heartbeat-event-fields (conn awaited)
  "Return common SDAM heartbeat event fields for CONN."
  (let* ((address (mongo--conn-address conn))
         (fields `((connection . ,conn)
                   (connection-id . ,address)
                   (address . ,address)
                   (awaited . ,awaited))))
    (when-let* ((server-id
                 (cdr (assoc "connectionId" (mongo-conn-last-hello conn)))))
      (setq fields (append fields
                           (list (cons 'server-connection-id server-id)))))
    fields))

(defun mongo--conn-topology-id (conn)
  "Return CONN's stable SDAM topology id."
  (or (mongo-conn-topology-id conn)
      (setf (mongo-conn-topology-id conn)
            (setq mongo--next-topology-id
                  (1+ mongo--next-topology-id)))))

(defun mongo--sdam-description-event-fields (conn)
  "Return common SDAM description event fields for CONN."
  `((connection . ,conn)
    (topology-id . ,(mongo--conn-topology-id conn))))

(defun mongo--emit-sdam-lifecycle-event (conn type &optional address)
  "Emit SDAM lifecycle event TYPE for CONN."
  (apply #'mongo--emit-sdam-event
         type
         (append
          (mongo--sdam-description-event-fields conn)
          (when address
            (list (cons 'address address))))))

(defun mongo--sdam-server-description-event-value (server)
  "Return SERVER normalized for SDAM description-changed comparison."
  (when (mongo-server-description-p server)
    (let ((copy (copy-mongo-server-description server)))
      (setf (mongo-server-description-last-update-time copy) nil)
      (setf (mongo-server-description-round-trip-time copy) nil)
      copy)))

(defun mongo--sdam-topology-description-event-value (topology)
  "Return TOPOLOGY normalized for SDAM description-changed comparison."
  (when (mongo-topology-description-p topology)
    (let ((copy (copy-mongo-topology-description topology)))
      (setf (mongo-topology-description-servers copy)
            (mapcar
             (lambda (entry)
               (cons (car entry)
                     (mongo--sdam-server-description-event-value
                      (cdr entry))))
             (mongo-topology-description-servers topology)))
      copy)))

(defun mongo--sdam-description-event-equal-p (old new)
  "Return non-nil when OLD and NEW are equal for SDAM changed events."
  (cond
   ((or (mongo-server-description-p old)
        (mongo-server-description-p new))
    (equal (mongo--sdam-server-description-event-value old)
           (mongo--sdam-server-description-event-value new)))
   ((or (mongo-topology-description-p old)
        (mongo-topology-description-p new))
    (equal (mongo--sdam-topology-description-event-value old)
           (mongo--sdam-topology-description-event-value new)))
   (t
    (equal old new))))

(defun mongo--topology-server-description (topology address)
  "Return TOPOLOGY's server description for ADDRESS."
  (when (mongo-topology-description-p topology)
    (cdr (assoc address (mongo-topology-description-servers topology)))))

(defun mongo--unknown-topology-description (conn)
  "Return an Unknown SDAM topology description for CONN's current address."
  (let* ((address (mongo--conn-address conn))
         (server (mongo--unknown-server-description address)))
    (make-mongo-topology-description
     :type 'unknown
     :servers `((,address . ,server))
     :compatible t)))

(defun mongo--emit-sdam-description-changes (conn old-topology new-topology)
  "Emit SDAM description-changed events for CONN topology changes."
  (when (and mongo-sdam-event-hook old-topology new-topology)
    (let* ((address (mongo--conn-address conn))
           (old-server (mongo--topology-server-description
                        old-topology address))
           (new-server (mongo--topology-server-description
                        new-topology address)))
      (unless (mongo--sdam-description-event-equal-p old-server new-server)
        (apply #'mongo--emit-sdam-event
               'server-description-changed
               (append
                (mongo--sdam-description-event-fields conn)
                (list (cons 'address address)
                      (cons 'previous-description old-server)
                      (cons 'new-description new-server)))))
      (unless (mongo--sdam-description-event-equal-p
               old-topology new-topology)
        (apply #'mongo--emit-sdam-event
               'topology-description-changed
               (append
                (mongo--sdam-description-event-fields conn)
                (list (cons 'previous-description old-topology)
                      (cons 'new-description new-topology))))))))

(defun mongo--set-conn-topology (conn topology)
  "Set CONN's TOPOLOGY and emit SDAM description change events."
  (let ((old-topology (mongo-conn-topology conn)))
    (setf (mongo-conn-topology conn) topology)
    (when old-topology
      (mongo--emit-sdam-description-changes conn old-topology topology)))
  topology)

(defun mongo--emit-sdam-opening-events (conn topology)
  "Emit initial SDAM opening events for CONN and TOPOLOGY."
  (when mongo-sdam-event-hook
    (let ((address (mongo--conn-address conn))
          (previous (mongo--unknown-topology-description conn)))
      (mongo--emit-sdam-lifecycle-event conn 'topology-opening)
      (mongo--emit-sdam-lifecycle-event conn 'server-opening address)
      (mongo--emit-sdam-description-changes conn previous topology))))

(defun mongo--emit-sdam-closing-events (conn)
  "Emit terminal SDAM closing events for CONN."
  (when (and mongo-sdam-event-hook
             (mongo-conn-topology conn)
             (not (mongo-conn-closed conn)))
    (let ((address (mongo--conn-address conn)))
      (mongo--set-conn-topology conn (mongo--unknown-topology-description conn))
      (mongo--emit-sdam-lifecycle-event conn 'server-closed address)
      (mongo--emit-sdam-lifecycle-event conn 'topology-closed))))

(defun mongo--monitor-awaitable-p (conn)
  "Return non-nil when CONN's next monitor heartbeat is awaitable."
  (and (not (eq (mongo-conn-server-monitoring-mode conn) 'poll))
       (when-let* ((server (mongo--current-server-description conn)))
         (mongo-server-description-topology-version server))))

(defun mongo--make-command-event-context (database document sequences)
  "Return command monitoring context for DATABASE, DOCUMENT, and SEQUENCES."
  (let* ((command (mongo--command-event-document document sequences))
         (command-name (mongo--command-name command))
         (sensitive (mongo--sensitive-command-p command)))
    (list :database-name database
          :command-name command-name
          :command command
          :operation-id mongo--command-operation-id
          :sensitive sensitive)))

(defun mongo--write-command-p (command)
  "Return non-nil when COMMAND requires a writable server."
  (member (mongo--command-name command)
          mongo--write-command-names))

(defun mongo--read-command-p (command)
  "Return non-nil when COMMAND is a read command."
  (member (mongo--command-name command)
          mongo--read-command-names))

(defun mongo--aggregate-write-stage-p (command)
  "Return non-nil when aggregate COMMAND contains a write stage."
  (when (equal (mongo--command-name command) "aggregate")
    (when-let* ((pipeline (cdr (assoc "pipeline"
                                      (mongo--document-pairs command)))))
      (seq-some (lambda (stage)
                  (let ((pairs (mongo--document-pairs stage)))
                    (or (assoc "$out" pairs)
                        (assoc "$merge" pairs))))
                (append pipeline nil)))))

(defun mongo--retryable-read-command-p (command)
  "Return non-nil when COMMAND is eligible for retryable reads."
  (and (member (mongo--command-name command)
               mongo--retryable-read-command-names)
       (not (mongo--aggregate-write-stage-p command))))

(defun mongo--retryable-reads-supported-p (conn)
  "Return non-nil when CONN's server supports retryable reads."
  (>= (or (mongo-conn-max-wire-version conn) 0) 6))

(defun mongo--retryable-server-error-p (response)
  "Return non-nil when RESPONSE reports a retryable read server error."
  (let ((code (cdr (assoc "code" response)))
        (labels (cdr (assoc "errorLabels" response))))
    (or (member code mongo--retryable-read-error-codes)
        (and labels
             (seq-some (lambda (label)
                         (member label '("RetryableReadError"
                                         "RetryableWriteError"
                                         "ResumableChangeStreamError")))
                       (append labels nil))))))

(defun mongo--network-error-p (err)
  "Return non-nil when ERR looks like a MongoDB network read error."
  (let ((message (error-message-string err)))
    (and (eq (car err) 'mongo-error)
         (string-match-p
          "\\(connection closed\\|Timed out waiting for MongoDB response\\)"
          message))))

(defun mongo--network-timeout-error-p (err)
  "Return non-nil when ERR is a MongoDB command response timeout."
  (and (eq (car err) 'mongo-error)
       (string-match-p
        "Timed out waiting for MongoDB response"
        (error-message-string err))))

(defun mongo--pool-command-clear-error-p (err)
  "Return non-nil when ERR should clear a checked-out command's pool."
  (and (mongo--network-error-p err)
       (not (mongo--network-timeout-error-p err))
       (not (mongo-error-has-label-p
             err mongo--system-overloaded-error-label))))

(defun mongo--connect-non-overload-error-message-p (message)
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

(defun mongo--connect-network-overload-error-p (phase err)
  "Return non-nil when PHASE and ERR should receive backpressure labels."
  (let ((message (error-message-string err)))
    (and (memq phase '(socket tls hello))
         (not (mongo--connect-non-overload-error-message-p message))
         (or (mongo--network-error-p err)
             (string-match-p
              "\\(timed out\\|connection \\(?:refused\\|reset\\|closed\\)\\|end of file\\|broken pipe\\|network is unreachable\\|host unreachable\\)"
              (downcase message))
             (and (eq phase 'tls)
                  (string-match-p
                   "\\(gnutls\\|tls negotiation failed\\)"
                   (downcase message)))))))

(defun mongo--resignal-connect-error (phase err)
  "Resignal connection ERR from PHASE, adding CMAP backpressure labels."
  (if (mongo--connect-network-overload-error-p phase err)
      (mongo--signal-error-with-labels
       (mongo--condition-message err)
       (mongo--add-error-labels
        (mongo-error-labels err)
        mongo--system-overloaded-error-label
        mongo--retryable-error-label))
    (signal (car err) (cdr err))))

(defun mongo--server-selection-error-p (err)
  "Return non-nil when ERR looks like a MongoDB server-selection error."
  (let ((message (error-message-string err)))
    (and (eq (car err) 'mongo-error)
         (string-match-p
          "\\(No writable MongoDB server\\|No readable MongoDB server\\|serverSelectionTimeoutMS\\|server selection\\|did not find a server matching\\)"
          message))))

(defun mongo--transaction-transient-condition-p (conn command err)
  "Return non-nil when ERR should have TransientTransactionError."
  (and (mongo-in-transaction-p conn)
       (not (equal (mongo--command-name command) "commitTransaction"))
       (or (mongo--network-error-p err)
           (mongo--server-selection-error-p err))))

(defun mongo--signal-transaction-transient-error (err &optional conn)
  "Signal ERR with TransientTransactionError added."
  (when conn
    (mongo--unpin-transaction conn))
  (mongo--signal-error-with-labels
   (mongo--condition-message err)
   (mongo--add-error-labels
    (mongo-error-labels err)
    mongo--transient-transaction-error-label)))

(defun mongo--retryable-read-enabled-p (conn command)
  "Return non-nil when CONN should retry read COMMAND once."
  (and (mongo-conn-retry-reads conn)
       (not (mongo-in-transaction-p conn))
       (mongo--retryable-reads-supported-p conn)
       (mongo--retryable-read-command-p command)))

(defun mongo--sequence-values (sequences identifier)
  "Return OP_MSG sequence values named IDENTIFIER from SEQUENCES."
  (when-let* ((value (cdr (assoc identifier sequences))))
    (cond
     ((vectorp value) (append value nil))
     ((listp value) value)
     (t nil))))

(defun mongo--sequence-document-list (sequence)
  "Return the document list from OP_MSG SEQUENCE after basic validation."
  (let ((identifier (car sequence))
        (documents (cdr sequence)))
    (unless (stringp identifier)
      (signal 'mongo-error
              (list (format "MongoDB OP_MSG sequence identifier must be a string: %S"
                            identifier))))
    (cond
     ((vectorp documents) (append documents nil))
     ((listp documents) documents)
     (t
      (signal 'mongo-error
              (list (format "MongoDB OP_MSG sequence documents must be a list or vector: %S"
                            documents)))))))

(defun mongo--validate-op-msg-size (conn document sequences)
  "Signal if OP_MSG DOCUMENT and SEQUENCES exceed CONN wire limits."
  (let* ((max-bson (mongo--max-bson-object-size conn))
         (max-message (mongo--max-message-size-bytes conn))
         (body-bytes (mongo--encode-document document))
         (message-size (+ 16 4 1 (length body-bytes))))
    (when (> (length body-bytes) max-bson)
      (signal 'mongo-error
              (list
               (format "MongoDB command document is %s bytes, exceeding maxBsonObjectSize %s"
                       (length body-bytes) max-bson))))
    (dolist (sequence sequences)
      (let* ((identifier (car sequence))
             (section-size
              (mongo--document-sequence-overhead-bytes identifier)))
        (dolist (sequence-document
                 (mongo--sequence-document-list sequence))
          (let ((sequence-document-size
                 (length (mongo--encode-document sequence-document))))
            (when (> sequence-document-size max-bson)
              (signal 'mongo-error
                      (list
                       (format "MongoDB OP_MSG sequence document is %s bytes, exceeding maxBsonObjectSize %s"
                               sequence-document-size max-bson))))
            (setq section-size (+ section-size sequence-document-size))))
        (setq message-size (+ message-size section-size))))
    (when (> message-size max-message)
      (signal 'mongo-error
              (list
               (format "MongoDB OP_MSG message is %s bytes, exceeding maxMessageSizeBytes %s"
                       message-size max-message))))
    message-size))

(defun mongo--document-field (document field)
  "Return DOCUMENT FIELD value, or nil."
  (cdr (assoc field (mongo--document-pairs document))))

(defun mongo--document-has-field-p (document field)
  "Return non-nil when DOCUMENT has FIELD."
  (assoc field (mongo--document-pairs document)))

(defun mongo--insert-documents-retryable-p (sequences)
  "Return non-nil when insert SEQUENCES are safe for retryable writes."
  (let ((docs (mongo--sequence-values sequences "documents")))
    (and docs
         (seq-every-p
          (lambda (doc)
            (mongo--document-has-field-p doc "_id"))
          docs))))

(defun mongo--update-statements-retryable-p (sequences)
  "Return non-nil when update SEQUENCES are safe for retryable writes."
  (let ((updates (mongo--sequence-values sequences "updates")))
    (and updates
         (seq-every-p
          (lambda (update)
            (not (mongo--wire-truthy-p
                  (mongo--document-field update "multi"))))
          updates))))

(defun mongo--delete-statements-retryable-p (sequences)
  "Return non-nil when delete SEQUENCES are safe for retryable writes."
  (let ((deletes (mongo--sequence-values sequences "deletes")))
    (and deletes
         (seq-every-p
          (lambda (delete)
            (= (or (mongo--document-field delete "limit") 0) 1))
          deletes))))

(defun mongo--document-with-generated-id (document)
  "Return DOCUMENT with a generated `_id' when it lacks one.
Documents that already contain `_id' are returned unchanged."
  (if (mongo--document-has-field-p document "_id")
      document
    (mongo-document
     (cons (cons "_id" (mongo-new-object-id))
           (mongo--document-pairs document)))))

(defun mongo--insert-documents-with-generated-ids (documents)
  "Return DOCUMENTS vector with `_id' generated for any missing document ids."
  (let* ((docs (cond
                ((vectorp documents) (append documents nil))
                ((and (listp documents)
                      (not (mongo--document-value-p documents)))
                 documents)
                (t (list documents))))
         (materialized
          (mapcar #'mongo--document-with-generated-id docs)))
    (vconcat materialized)))

(defun mongo--chunk-vector (values chunk-size)
  "Return VALUES vector split into vectors of at most CHUNK-SIZE."
  (unless (and (integerp chunk-size)
               (> chunk-size 0))
    (signal 'mongo-error
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

(defun mongo--command-for-size-estimate (conn database command)
  "Return COMMAND with the metadata known before send for size estimates."
  (if (mongo-conn-p conn)
      (let* ((transaction-state (mongo--transaction-command-state conn command))
             (transaction-number
              (mongo--transaction-command-number conn transaction-state)))
        (mongo--command-with-db
         command
         (or database (mongo-conn-database conn))
         (mongo-conn-server-api conn)
         (mongo-conn-session-id conn)
         (mongo--effective-command-read-preference conn command)
         (mongo-conn-read-concern conn)
         (mongo-conn-write-concern conn)
         transaction-number
         transaction-state
         (mongo-conn-transaction-read-concern conn)
         (mongo--cluster-time-to-send conn)))
    (mongo--command-with-db command database)))

(defun mongo--document-sequence-overhead-bytes (identifier)
  "Return OP_MSG kind 1 sequence overhead bytes for IDENTIFIER."
  (+ 1 4 (length (mongo--encode-cstring identifier))))

(defun mongo--insert-batch-byte-budget (conn database command)
  "Return safe document-sequence byte budget for insert COMMAND."
  (let* ((command-document
          (mongo--command-for-size-estimate conn database command))
         (base-message
          (mongo--make-op-msg 1 command-document nil nil nil))
         (budget (- (mongo--max-message-size-bytes conn)
                    (length base-message)
                    (mongo--document-sequence-overhead-bytes "documents")
                    mongo--write-batch-message-safety-bytes)))
    (unless (> budget 0)
      (signal 'mongo-error
              (list
               (format "MongoDB maxMessageSizeBytes is too small for insert command metadata: %s"
                       (mongo--max-message-size-bytes conn)))))
    budget))

(defun mongo--insert-document-batches (conn database command docs)
  "Return DOCS split for insert using count and wire-size limits."
  (let ((max-bson (mongo--max-bson-object-size conn))
        (max-count (mongo--max-write-batch-size conn))
        (max-bytes (mongo--insert-batch-byte-budget conn database command))
        current
        (current-count 0)
        (current-bytes 0)
        batches)
    (cl-loop for doc across docs
             for doc-bytes = (length (mongo--encode-document doc))
             do
             (when (> doc-bytes max-bson)
               (signal 'mongo-error
                       (list
                        (format "MongoDB insert document is %s bytes, exceeding maxBsonObjectSize %s"
                                doc-bytes max-bson))))
             (when (> doc-bytes max-bytes)
               (signal 'mongo-error
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

(defun mongo--retryable-write-command-p (command sequences)
  "Return non-nil when COMMAND and SEQUENCES are eligible for retryable writes."
  (pcase (mongo--command-name command)
    ("insert"
     (mongo--insert-documents-retryable-p sequences))
    ("update"
     (mongo--update-statements-retryable-p sequences))
    ("delete"
     (mongo--delete-statements-retryable-p sequences))
    ((or "findAndModify" "findandmodify") t)
    (_ nil)))

(defun mongo--write-concern-value (conn command)
  "Return the effective writeConcern document for CONN and COMMAND."
  (or (mongo--document-field command "writeConcern")
      (mongo--write-concern-document
       (and conn (mongo-conn-write-concern conn)))))

(defun mongo--unacknowledged-write-concern-p (write-concern)
  "Return non-nil when WRITE-CONCERN is unacknowledged."
  (when write-concern
    (let ((w (mongo--document-field write-concern "w")))
      (or (and (numberp w) (zerop w))
          (equal w "0")))))

(defun mongo--retryable-writes-supported-p (conn)
  "Return non-nil when CONN's selected server supports retryable writes."
  (and (mongo-conn-session-id conn)
       (>= (or (mongo-conn-max-wire-version conn) 0) 6)
       (when-let* ((server (mongo-select-server conn 'write)))
         (memq (mongo-server-description-type server)
               '(rs-primary mongos load-balanced)))))

(defun mongo--retryable-write-enabled-p (conn command sequences)
  "Return non-nil when CONN should retry write COMMAND once."
  (and mongo--retryable-write-context
       (mongo-conn-retry-writes conn)
       (not (mongo-in-transaction-p conn))
       (not (mongo--unacknowledged-write-concern-p
             (mongo--write-concern-value conn command)))
       (mongo--retryable-writes-supported-p conn)
       (mongo--retryable-write-command-p command sequences)))

(defun mongo--next-transaction-number (conn)
  "Increment and return CONN's next retryable-write transaction number."
  (let ((next (1+ (or (mongo-conn-txn-number conn) 0))))
    (setf (mongo-conn-txn-number conn) next)
    (mongo-int64 next)))

(defun mongo--retryable-write-concern-error-p (conn response)
  "Return non-nil when RESPONSE has a retryable writeConcernError."
  (let ((write-concern-error (cdr (assoc "writeConcernError" response))))
    (and write-concern-error
         (not (eq (mongo--topology-current-server-type conn) 'mongos))
         (member (mongo--document-field write-concern-error "code")
                 mongo--retryable-write-error-codes))))

(defun mongo--retryable-write-server-error-p (conn response)
  "Return non-nil when RESPONSE reports a retryable write server error."
  (let ((code (cdr (assoc "code" response)))
        (labels (cdr (assoc "errorLabels" response))))
    (or (and labels
             (seq-some (lambda (label)
                         (equal label "RetryableWriteError"))
                       (append labels nil)))
        (member code mongo--retryable-write-error-codes)
        (mongo--retryable-write-concern-error-p conn response))))

(defun mongo--conn-address (conn)
  "Return CONN's normalized server address."
  (mongo--endpoint-key (mongo-conn-host conn)
                       (mongo-conn-port conn)))

(defun mongo--ensure-topology-description (conn)
  "Return CONN's topology description, deriving it from last hello if needed."
  (or (mongo-conn-topology conn)
      (when-let* ((hello (mongo-conn-last-hello conn)))
        (setf (mongo-conn-topology conn)
              (mongo--topology-description-from-hello conn hello)))))

(defun mongo--current-server-description (conn)
  "Return the current server description for CONN, or nil."
  (when-let* ((topology (mongo--ensure-topology-description conn)))
    (cdr (assoc (mongo--conn-address conn)
                (mongo-topology-description-servers topology)))))

(defun mongo--replace-server-description (servers address server)
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

(defun mongo--topology-with-replaced-server
    (conn server &optional old-topology)
  "Return topology for CONN with current address replaced by SERVER."
  (let* ((topology (or old-topology
                       (mongo--ensure-topology-description conn)))
         (address (mongo--conn-address conn))
         (servers (mongo--replace-server-description
                   (and topology
                        (mongo-topology-description-servers topology))
                   address
                   server))
         (topology-type
          (mongo--topology-type-after-hello
           conn server servers topology))
         (primary-address
          (mongo--topology-primary-address-from-servers servers))
         (compatible
          (mongo--topology-compatible-p servers)))
    (make-mongo-topology-description
     :type topology-type
     :set-name (or (mongo-server-description-set-name server)
                   (and topology
                        (mongo-topology-description-set-name topology)))
     :servers servers
     :primary-address primary-address
     :max-election-id
     (and topology
          (mongo-topology-description-max-election-id topology))
     :max-set-version
     (and topology
          (mongo-topology-description-max-set-version topology))
     :logical-session-timeout-minutes
     (or (mongo-server-description-logical-session-timeout-minutes server)
         (and topology
              (mongo-topology-description-logical-session-timeout-minutes
               topology)))
     :compatible compatible
     :compatibility-error
     (unless compatible
       (mongo--topology-compatibility-error servers)))))

(defun mongo--mark-current-server-unknown
    (conn error &optional topology-version)
  "Mark CONN's current server Unknown after ERROR.
TOPOLOGY-VERSION, when non-nil, is stored on the Unknown description so later
state-change errors can be compared for freshness."
  (let* ((address (mongo--conn-address conn))
         (unknown (mongo--unknown-server-description
                   address
                   (error-message-string error)
                   topology-version)))
    (mongo--set-conn-topology
     conn
     (mongo--topology-with-replaced-server conn unknown)))
  conn)

(defun mongo--object-id-value (value)
  "Return VALUE as a `mongo-object-id' when it is Extended JSON ObjectId."
  (cond
   ((mongo-object-id-p value) value)
   ((and (consp value)
         (consp (car value))
         (assoc "$oid" value))
    (mongo-object-id (cdr (assoc "$oid" value))))
   (t value)))

(defun mongo--topology-version-command-value (topology-version)
  "Return TOPOLOGY-VERSION encoded for a hello command."
  (when topology-version
    (mongo-document
     (mapcar (lambda (pair)
               (pcase (car pair)
                 ("processId"
                  (cons (car pair)
                        (mongo--object-id-value (cdr pair))))
                 ("counter"
                  (cons (car pair)
                        (if (mongo-int64-p (cdr pair))
                            (cdr pair)
                          (mongo-int64 (cdr pair)))))
                 (_ pair)))
             (mongo--document-pairs topology-version)))))

(defun mongo--datetime-value-seconds (value)
  "Return BSON datetime VALUE as epoch seconds, or nil."
  (cond
   ((mongo-datetime-p value)
    (/ (mongo-datetime-millis value) 1000.0))
   ((integerp value)
    (/ value 1000.0))
   ((and (mongo--document-value-p value)
         (assoc "$date" (mongo--document-pairs value)))
    (/ (cdr (assoc "$date" (mongo--document-pairs value))) 1000.0))
   (t nil)))

(defun mongo--hello-last-write-date (hello)
  "Return HELLO lastWrite.lastWriteDate as epoch seconds, or nil."
  (when-let* ((last-write (cdr (assoc "lastWrite" hello))))
    (mongo--datetime-value-seconds
     (cdr (assoc "lastWriteDate"
                 (mongo--document-pairs last-write))))))

(defun mongo--writable-server-p (server)
  "Return non-nil when SERVER is writable for command selection."
  (memq (mongo-server-description-type server)
        '(standalone mongos rs-primary load-balanced)))

(defun mongo--tag-set-matches-server-p (tag-set server)
  "Return non-nil when TAG-SET matches SERVER's hello tags."
  (let ((required (mongo--document-pairs tag-set))
        (server-tags (mongo--document-pairs
                      (mongo-server-description-tags server))))
    (or (null required)
        (seq-every-p
         (lambda (tag)
           (equal (cdr tag)
                  (cdr (assoc (car tag) server-tags))))
         required))))

(defun mongo--server-matches-read-preference-tags-p (server read-preference)
  "Return non-nil when SERVER matches READ-PREFERENCE tag sets."
  (let ((tags (and read-preference
                   (mongo--read-preference-tags read-preference))))
    (or (not tags)
        (seq-some (lambda (tag-set)
                    (mongo--tag-set-matches-server-p tag-set server))
                  (append tags nil)))))

(defun mongo--topology-primary-server (topology)
  "Return TOPOLOGY's known primary server description, or nil."
  (when-let* ((address (and topology
                            (mongo-topology-description-primary-address
                             topology))))
    (cdr (assoc address (mongo-topology-description-servers topology)))))

(defun mongo--topology-secondary-servers (topology)
  "Return known secondary server descriptions in TOPOLOGY."
  (when topology
    (seq-keep
     (lambda (entry)
       (let ((server (cdr entry)))
         (and (eq (mongo-server-description-type server) 'rs-secondary)
              server)))
     (mongo-topology-description-servers topology))))

(defun mongo--server-staleness-seconds
    (server topology heartbeat-seconds)
  "Return SERVER's estimated staleness in seconds, or nil."
  (let ((server-last-write (mongo-server-description-last-write-date server))
        (heartbeat (or heartbeat-seconds
                       mongo-monitor-heartbeat-seconds)))
    (when server-last-write
      (if-let* ((primary (mongo--topology-primary-server topology))
                (primary-last-write
                 (mongo-server-description-last-write-date primary)))
          (+ (- (- (mongo-server-description-last-update-time server)
                   server-last-write)
                (- (mongo-server-description-last-update-time primary)
                   primary-last-write))
             heartbeat)
        (let ((secondary-last-writes
               (delq nil
                     (mapcar
                      #'mongo-server-description-last-write-date
                      (mongo--topology-secondary-servers topology)))))
          (when secondary-last-writes
            (+ (- (apply #'max secondary-last-writes)
                  server-last-write)
               heartbeat)))))))

(defun mongo--server-within-max-staleness-p
    (server read-preference topology heartbeat-seconds)
  "Return non-nil when SERVER satisfies READ-PREFERENCE max staleness."
  (let ((max-staleness
         (and read-preference
              (mongo--read-preference-max-staleness-seconds
               read-preference))))
    (cond
     ((not max-staleness) t)
     ((not (eq (mongo-server-description-type server) 'rs-secondary)) t)
     ((< (or (mongo-server-description-max-wire-version server) 0) 5)
      (signal 'mongo-error
              (list "MongoDB maxStalenessSeconds requires servers with maxWireVersion >= 5")))
     (t
      (when-let* ((staleness
                   (mongo--server-staleness-seconds
                    server topology heartbeat-seconds)))
        (<= staleness max-staleness))))))

(defun mongo--server-matches-read-preference-constraints-p
    (server read-preference topology heartbeat-seconds)
  "Return non-nil when SERVER satisfies read preference constraints."
  (and (mongo--server-matches-read-preference-tags-p
        server read-preference)
       (mongo--server-within-max-staleness-p
        server read-preference topology heartbeat-seconds)))

(defun mongo--readable-server-p
    (server read-preference topology &optional heartbeat-seconds)
  "Return non-nil when SERVER satisfies READ-PREFERENCE in TOPOLOGY."
  (let ((type (and server
                   (mongo-server-description-type server)))
        (mode (if read-preference
                  (mongo--read-preference-mode read-preference)
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
         (mongo--server-matches-read-preference-constraints-p
          server read-preference topology heartbeat-seconds))))
      ('rs-secondary
       (and
        (pcase mode
          ("primary" nil)
          ("primaryPreferred"
           (not (mongo-topology-description-primary-address topology)))
          ((or "secondary" "secondaryPreferred" "nearest") t)
          (_ nil))
        (mongo--server-matches-read-preference-constraints-p
         server read-preference topology heartbeat-seconds)))
      (_ nil))))

(defun mongo--available-server-p (server)
  "Return non-nil when SERVER is available for Single topology selection."
  (and server
       (not (eq (mongo-server-description-type server) 'unknown))))

(defun mongo-topology-description-has-readable-server-p
    (topology &optional read-preference heartbeat-seconds)
  "Return non-nil when TOPOLOGY has a readable MongoDB server.
READ-PREFERENCE accepts the same values as command and transaction options:
nil or primary by default, a read preference mode string/symbol, or a
readPreference document.  HEARTBEAT-SECONDS is used for maxStalenessSeconds
calculation and defaults to `mongo-monitor-heartbeat-seconds'."
  (when (mongo-topology-description-p topology)
    (let ((read-preference (mongo--read-preference-value read-preference)))
      (pcase (mongo-topology-description-type topology)
        ('unknown nil)
        ('load-balanced t)
        ('single
         (seq-some (lambda (entry)
                     (mongo--available-server-p (cdr entry)))
                   (mongo-topology-description-servers topology)))
        ('sharded
         (seq-some (lambda (entry)
                     (mongo--available-server-p (cdr entry)))
                   (mongo-topology-description-servers topology)))
        (_
         (seq-some (lambda (entry)
                     (mongo--readable-server-p
                      (cdr entry) read-preference topology heartbeat-seconds))
                   (mongo-topology-description-servers topology)))))))

(defun mongo-topology-description-has-writable-server-p (topology)
  "Return non-nil when TOPOLOGY has a writable MongoDB server."
  (when (mongo-topology-description-p topology)
    (pcase (mongo-topology-description-type topology)
      ('unknown nil)
      ('load-balanced t)
      ('single
       (seq-some (lambda (entry)
                   (mongo--available-server-p (cdr entry)))
                 (mongo-topology-description-servers topology)))
      ('sharded
       (seq-some (lambda (entry)
                   (mongo--available-server-p (cdr entry)))
                 (mongo-topology-description-servers topology)))
      (_
       (seq-some (lambda (entry)
                   (mongo--writable-server-p (cdr entry)))
                 (mongo-topology-description-servers topology))))))

(defun mongo--single-topology-read-preference (conn command read-preference)
  "Return effective OP_MSG read preference for CONN and COMMAND.
In Server Selection Spec Single topology, reads against a replica-set member
must carry primaryPreferred when the application did not request a non-primary
read preference.  This allows directConnection=true reads from secondaries."
  (let* ((topology (mongo--ensure-topology-description conn))
         (server (mongo--current-server-description conn))
         (mode (and read-preference
                    (mongo--read-preference-mode read-preference))))
    (if (and (mongo--read-command-p command)
             (eq (and topology
                      (mongo-topology-description-type topology))
                 'single)
             server
             (memq (mongo-server-description-type server)
                   '(rs-primary rs-secondary rs-other rs-arbiter rs-ghost))
             (or (not mode)
                 (equal mode "primary")))
        (make-mongo--read-preference :mode "primaryPreferred")
      read-preference)))

(defun mongo--effective-command-read-preference (conn command)
  "Return the read preference to attach to COMMAND on CONN."
  (mongo--single-topology-read-preference
   conn command (mongo-conn-read-preference conn)))

(defun mongo-select-server (conn &optional purpose read-preference)
  "Return the selected current server description for CONN and PURPOSE.
PURPOSE may be `write' or `read'.  The current implementation tracks one
socket; this function exposes the server-selection boundary used by future
  multi-server topology monitoring."
  (let* ((topology (mongo--ensure-topology-description conn))
         (server (mongo--current-server-description conn))
         (read-preference (or read-preference
                              (mongo-conn-read-preference conn))))
    (mongo--ensure-topology-compatible topology)
    (if (eq (and topology
                 (mongo-topology-description-type topology))
            'single)
        (and (mongo--available-server-p server)
             server)
      (pcase (or purpose 'read)
        ('write
         (and server
              (mongo--writable-server-p server)
              server))
        (_
         (and server
              (mongo--readable-server-p
               server
               read-preference
               topology
               (or (mongo-conn-heartbeat-frequency conn)
                   mongo-monitor-heartbeat-seconds))
              server))))))

(defun mongo--topology-current-server-type (conn)
  "Return CONN's current topology server type, or nil."
  (when-let* ((server (mongo--current-server-description conn)))
    (mongo-server-description-type server)))

(defun mongo--topology-current-server-error (conn)
  "Return CONN's current server description error, or nil."
  (when-let* ((server (mongo--current-server-description conn)))
    (mongo-server-description-error server)))

(defun mongo--topology-current-server-context (conn)
  "Return a user-facing summary of CONN's current selected server state."
  (let ((type (or (mongo--topology-current-server-type conn) 'unknown))
        (error (mongo--topology-current-server-error conn)))
    (if error
        (format "%s (%s)" type error)
      (format "%s" type))))

(defun mongo--ensure-writable-server (conn command &optional timeout)
  "Refresh CONN if COMMAND needs a writable server and none is selected."
  (when (and (mongo--write-command-p command)
             (not (mongo-select-server conn 'write)))
    (ignore-errors
      (mongo-hello conn timeout))
    (unless (mongo-select-server conn 'write)
      (signal 'mongo-error
              (list
               (format
                "No writable MongoDB server available for %s; current server type is %s"
                (or (mongo--command-name command) "command")
                (mongo--topology-current-server-context conn)))))))

(defun mongo--ensure-readable-server
    (conn command &optional timeout read-preference)
  "Refresh CONN if COMMAND needs a readable server and none is selected."
  (when (and (mongo--read-command-p command)
             (not (mongo-select-server conn 'read read-preference)))
    (ignore-errors
      (mongo-hello conn timeout))
    (unless (mongo-select-server conn 'read read-preference)
      (signal 'mongo-error
              (list
               (format
                "No readable MongoDB server available for %s with readPreference=%s; current server type is %s"
                (or (mongo--command-name command) "command")
                (if read-preference
                    (mongo--read-preference-mode
                     read-preference)
                  "primary")
                (mongo--topology-current-server-context conn)))))))

(defun mongo--not-writable-error-p (response)
  "Return non-nil when RESPONSE reports a stale/non-writable primary."
  (let ((code-name (cdr (assoc "codeName" response)))
        (errmsg (downcase (or (mongo--response-message response) ""))))
    (or (member code-name
                '("NotWritablePrimary" "NotPrimaryNoSecondaryOk"
                  "PrimarySteppedDown" "InterruptedDueToReplStateChange"
                  "NotMaster" "NotMasterNoSlaveOk"))
        (string-match-p
         "\\(not writable primary\\|not primary\\|not master\\|primary stepped down\\)"
         errmsg))))

(defun mongo--state-change-error-p (response)
  "Return non-nil when RESPONSE means the current server state is stale."
  (let ((code-name (cdr (assoc "codeName" response)))
        (errmsg (downcase (or (mongo--response-message response) ""))))
    (or (member code-name mongo--state-change-error-code-names)
        (string-match-p
         (concat "\\(not writable primary\\|not primary\\|not master\\|"
                 "primary stepped down\\|node is recovering\\|"
                 "node is shutting down\\|interrupted at shutdown\\|"
                 "interrupted due to repl state change\\)")
         errmsg))))

(defun mongo--state-change-error-fresh-p (conn response)
  "Return non-nil if RESPONSE should update CONN's server description."
  (let* ((server (mongo--current-server-description conn))
         (current-topology-version
          (and server
               (mongo-server-description-topology-version server)))
         (error-topology-version
          (mongo--topology-version-from-response response)))
    (mongo--topology-version-newer-p
     error-topology-version current-topology-version)))

(defun mongo--handle-state-change-error (conn response)
  "Apply SDAM state-change side effects for RESPONSE on CONN.
Return `marked' when the current server was marked Unknown, `stale' when
RESPONSE contained an old topologyVersion and was ignored for topology
purposes, or nil when RESPONSE is not a state-change error."
  (when (and conn
             (mongo--state-change-error-p response))
    (if (mongo--state-change-error-fresh-p conn response)
        (progn
          (mongo--mark-current-server-unknown
           conn
           (list 'mongo-error (mongo--response-message response))
           (mongo--topology-version-from-response response))
          'marked)
      'stale)))

(defun mongo--transaction-control-command-p (command)
  "Return non-nil when COMMAND is a transaction control command."
  (member (mongo--command-name command)
          '("commitTransaction" "abortTransaction")))

(defun mongo--transaction-active-state-p (state)
  "Return non-nil when transaction STATE is active."
  (memq state '(starting in-progress)))

(defun mongo--transaction-ended-state-p (state)
  "Return non-nil when transaction STATE is committed or aborted."
  (memq state '(committed aborted)))

(defun mongo--clear-ended-transaction-for-command (conn command)
  "Clear ended transaction state on CONN before non-control COMMAND."
  (when (and (mongo--transaction-ended-state-p
              (mongo-conn-transaction-state conn))
             (not (mongo--transaction-control-command-p command)))
    (mongo--clear-transaction conn))
  conn)

(defun mongo--transaction-command-state (conn command)
  "Return transaction state for COMMAND on CONN, or nil."
  (mongo--clear-ended-transaction-for-command conn command)
  (let ((state (mongo-conn-transaction-state conn)))
    (cond
     ((and state
           (mongo--transaction-control-command-p command))
      'in-progress)
     ((mongo--transaction-active-state-p state) state)
     (t nil))))

(defun mongo--transaction-command-number (conn state)
  "Return CONN transaction number for transaction STATE, or nil."
  (and state
       (mongo-conn-transaction-number conn)))

(defun mongo--primary-read-preference-p (read-preference)
  "Return non-nil when READ-PREFERENCE is nil or primary."
  (or (not read-preference)
      (equal (mongo--read-preference-mode read-preference) "primary")))

(defun mongo--validate-transaction-command (conn command transaction-state)
  "Signal when COMMAND violates transaction command rules for CONN."
  (when (and transaction-state
             (not (mongo--transaction-control-command-p command)))
    (let ((pairs (mongo--document-pairs command)))
      (when (and (mongo--read-command-p pairs)
                 (not (mongo--primary-read-preference-p
                       (mongo-conn-transaction-read-preference conn))))
        (signal 'mongo-error
                (list "read preference in a transaction must be primary")))
      (when (assoc "readConcern" pairs)
        (signal 'mongo-error
                (list "Cannot set read concern after starting a transaction")))
      (when (assoc "writeConcern" pairs)
        (signal 'mongo-error
                (list "Cannot set write concern after starting a transaction"))))))

(defun mongo--command-timeout (conn timeout)
  "Return the effective timeout seconds for a MongoDB command on CONN."
  (or timeout
      (mongo-conn-operation-timeout conn)
      (mongo-conn-socket-timeout conn)
      mongo-timeout-seconds))

(defun mongo--mark-transaction-command-sent (conn state)
  "Mark transaction STATE as having sent one command on CONN."
  (when (and (eq state 'starting)
             (eq (mongo-conn-transaction-state conn) 'starting))
    (setf (mongo-conn-transaction-state conn) 'in-progress)))

(defun mongo--unpin-transaction (conn)
  "Clear CONN's transaction server/connection pin."
  (setf (mongo-conn-transaction-pinned-address conn) nil)
  (setf (mongo-conn-transaction-pinned-service-id conn) nil)
  conn)

(defun mongo--transaction-pinnable-server (conn)
  "Return current server when transaction commands should pin to it."
  (when-let* ((server (mongo--current-server-description conn)))
    (when (memq (mongo-server-description-type server)
                '(mongos load-balanced))
      server)))

(defun mongo--ensure-transaction-pin (conn transaction-state)
  "Pin or validate CONN for TRANSACTION-STATE commands.
Sharded transactions pin to a mongos address.  Load-balanced transactions pin
to the selected serviceId on the single socket."
  (when transaction-state
    (let* ((server (mongo--transaction-pinnable-server conn))
           (address (and server
                         (mongo-server-description-address server)))
           (service-id (and server
                            (mongo-server-description-service-id server)))
           (pinned-address
            (mongo-conn-transaction-pinned-address conn))
           (pinned-service-id
            (mongo-conn-transaction-pinned-service-id conn)))
      (cond
       ((and pinned-address
             (not (equal pinned-address address)))
        (signal 'mongo-error
                (list
                 (format
                  "MongoDB transaction is pinned to %s but current server is %s"
                  pinned-address
                  (or address "<none>")))))
       ((and pinned-service-id
             (not (equal pinned-service-id service-id)))
        (signal 'mongo-error
                (list "MongoDB load-balanced transaction changed serviceId")))
       ((and server
             (not pinned-address))
        (setf (mongo-conn-transaction-pinned-address conn) address)
        (when service-id
          (setf (mongo-conn-transaction-pinned-service-id conn)
                service-id))))))
  conn)

(defun mongo--send-command-and-receive
    (conn database command timeout sequences txn-number)
  "Send one MongoDB COMMAND attempt and return the response alist.
SEQUENCES, when non-nil, is sent as OP_MSG document sequence sections."
  (unless (mongo-live-p conn)
    (signal 'mongo-error
            (list "MongoDB connection is closed")))
  (let* ((timeout (mongo--command-timeout conn timeout))
         (transaction-state (mongo--transaction-command-state conn command))
         (transaction-number
          (mongo--transaction-command-number conn transaction-state)))
    (mongo--validate-transaction-command conn command transaction-state)
    (mongo--ensure-writable-server conn command timeout)
    (mongo--ensure-readable-server
     conn command timeout
     (and transaction-state
          (mongo-conn-transaction-read-preference conn)))
    (mongo--ensure-transaction-pin conn transaction-state)
    (let* ((effective-txn-number (or transaction-number txn-number))
	   (document
	    (mongo--command-with-db
	     command
	     (or database (mongo-conn-database conn))
	     (mongo-conn-server-api conn)
             (mongo-conn-session-id conn)
             (mongo--effective-command-read-preference conn command)
             (mongo-conn-read-concern conn)
             (mongo-conn-write-concern conn)
             effective-txn-number
             transaction-state
	     (mongo-conn-transaction-read-concern conn)
	     (mongo--cluster-time-to-send conn)))
	   (request-id nil))
      (let ((mongo--command-event-context
	     (mongo--make-command-event-context
	      (or database (mongo-conn-database conn))
	      document
	      sequences)))
	(condition-case err
	    (progn
	      (setq request-id
	            (if sequences
	                (mongo--send-document conn document sequences)
	              (mongo--send-document conn document)))
	      (mongo--command-event-started conn request-id)
	      (mongo--mark-transaction-command-sent
	       conn transaction-state)
	      (let ((response
	             (mongo--recv-message conn timeout request-id)))
	        (mongo--advance-cluster-time-from-response
	         conn command response)
	        (mongo--advance-transaction-recovery-token-from-response
	         conn transaction-state response)
	        (if (mongo--ok-p response)
	            (mongo--command-event-succeeded conn response)
	          (mongo--command-event-failed conn response))
	        response))
	  (error
	   (mongo--command-event-failed conn err)
	   (signal (car err) (cdr err))))))))

(defun mongo--decoded-message-more-to-come-p (frame)
  "Return non-nil when decoded OP_MSG FRAME has the moreToCome flag."
  (not (zerop (logand (mongo--decoded-message-flags frame)
                      mongo--op-msg-more-to-come))))

(defun mongo--send-command-exhaust-and-receive
    (conn database command timeout sequences)
  "Send one MongoDB COMMAND attempt with exhaustAllowed and return responses.
SEQUENCES, when non-nil, is sent as OP_MSG document sequence sections.  The
caller must only use commands whose server semantics allow exhaust replies."
  (unless (mongo-live-p conn)
    (signal 'mongo-error
            (list "MongoDB connection is closed")))
  (unless (>= (or (mongo-conn-max-wire-version conn) 0) 6)
    (signal 'mongo-error
            (list "MongoDB OP_MSG exhaustAllowed requires MongoDB 3.6+ wire version support")))
  (let* ((timeout (mongo--command-timeout conn timeout))
         (transaction-state (mongo--transaction-command-state conn command))
         (transaction-number
          (mongo--transaction-command-number conn transaction-state)))
    (mongo--validate-transaction-command conn command transaction-state)
    (mongo--ensure-writable-server conn command timeout)
    (mongo--ensure-readable-server
     conn command timeout
     (and transaction-state
          (mongo-conn-transaction-read-preference conn)))
    (mongo--ensure-transaction-pin conn transaction-state)
    (let* ((document
            (mongo--command-with-db
             command
             (or database (mongo-conn-database conn))
             (mongo-conn-server-api conn)
             (mongo-conn-session-id conn)
             (mongo--effective-command-read-preference conn command)
             (mongo-conn-read-concern conn)
             (mongo-conn-write-concern conn)
	     transaction-number
	     transaction-state
	     (mongo-conn-transaction-read-concern conn)
	     (mongo--cluster-time-to-send conn)))
	   (request-id nil)
	   responses
	   more-to-come)
      (let ((mongo--command-event-context
	     (mongo--make-command-event-context
	      (or database (mongo-conn-database conn))
	      document
	      sequences)))
	(condition-case err
	    (progn
	      (setq request-id
	            (mongo--send-document-with-flags
	             conn document sequences mongo--op-msg-exhaust-allowed))
	      (mongo--command-event-started conn request-id)
	      (mongo--mark-transaction-command-sent conn transaction-state)
	      (setq more-to-come t)
	      (while more-to-come
	        (let* ((frame (mongo--recv-message-frame
	                       conn timeout request-id t))
	               (response (mongo--decoded-message-document frame)))
	          (push response responses)
	          (mongo--advance-cluster-time-from-response conn command response)
	          (mongo--advance-transaction-recovery-token-from-response
	           conn transaction-state response)
	          (setq more-to-come
	                (mongo--decoded-message-more-to-come-p frame))))
	      (setq responses (nreverse responses))
	      (dolist (response responses)
	        (unless (mongo--ok-p response)
	          (mongo--command-event-failed conn response)
	          (signal 'mongo-error
	                  (list (mongo--response-message response)))))
	      (mongo--command-event-succeeded
	       conn (or (car (last responses)) '(("ok" . 1))))
	      (dolist (response responses)
	        (when-let* ((message (and (mongo--write-command-p command)
	                                  (mongo--write-error-message response))))
	          (signal 'mongo-error (list message))))
	        responses)
	    (error
	     (mongo--command-event-failed conn err)
	     (signal (car err) (cdr err))))))))

(defun mongo--replace-conn-transport (conn replacement old-session-id)
  "Replace CONN's transport and server state with REPLACEMENT.
OLD-SESSION-ID, when non-nil, is preserved so retryable reads reuse the same
implicit session across a reconnect."
  (setf (mongo-conn-process conn)
        (mongo-conn-process replacement))
  (setf (mongo-conn-buffer conn)
        (mongo-conn-buffer replacement))
  (setf (mongo-conn-host conn)
        (mongo-conn-host replacement))
  (setf (mongo-conn-port conn)
        (mongo-conn-port replacement))
  (setf (mongo-conn-database conn)
        (mongo-conn-database replacement))
  (setf (mongo-conn-socket-timeout conn)
        (mongo-conn-socket-timeout replacement))
  (setf (mongo-conn-operation-timeout conn)
        (mongo-conn-operation-timeout replacement))
  (setf (mongo-conn-local-threshold conn)
        (mongo-conn-local-threshold replacement))
  (setf (mongo-conn-heartbeat-frequency conn)
        (mongo-conn-heartbeat-frequency replacement))
  (setf (mongo-conn-server-monitoring-mode conn)
        (mongo-conn-server-monitoring-mode replacement))
  (setf (mongo-conn-request-id conn)
        (mongo-conn-request-id replacement))
  (setf (mongo-conn-max-wire-version conn)
        (mongo-conn-max-wire-version replacement))
  (setf (mongo-conn-max-bson-object-size conn)
        (mongo-conn-max-bson-object-size replacement))
  (setf (mongo-conn-max-message-size-bytes conn)
        (mongo-conn-max-message-size-bytes replacement))
  (setf (mongo-conn-max-write-batch-size conn)
        (mongo-conn-max-write-batch-size replacement))
  (setf (mongo-conn-compressors conn)
        (mongo-conn-compressors replacement))
  (setf (mongo-conn-server-api conn)
        (mongo-conn-server-api replacement))
  (setf (mongo-conn-read-preference conn)
        (mongo-conn-read-preference replacement))
  (setf (mongo-conn-read-concern conn)
        (mongo-conn-read-concern replacement))
  (setf (mongo-conn-write-concern conn)
        (mongo-conn-write-concern replacement))
  (setf (mongo-conn-load-balanced conn)
        (mongo-conn-load-balanced replacement))
  (setf (mongo-conn-service-id conn)
        (mongo-conn-service-id replacement))
  (setf (mongo-conn-hello-command conn)
        (mongo-conn-hello-command replacement))
  (setf (mongo-conn-last-hello conn)
        (mongo-conn-last-hello replacement))
  (setf (mongo-conn-topology conn)
        (mongo-conn-topology replacement))
  (setf (mongo-conn-session-id conn)
        (or old-session-id
            (mongo-conn-session-id replacement)))
  (setf (mongo-conn-cluster-time conn)
        (mongo--max-cluster-time
         (mongo-conn-cluster-time conn)
         (mongo-conn-cluster-time replacement)))
  (setf (mongo-conn-session-cluster-time conn)
        (mongo--max-cluster-time
         (mongo-conn-session-cluster-time conn)
         (mongo-conn-session-cluster-time replacement)))
  (setf (mongo-conn-transaction-state conn)
        (mongo-conn-transaction-state replacement))
  (setf (mongo-conn-transaction-number conn)
        (mongo-conn-transaction-number replacement))
  (setf (mongo-conn-transaction-read-preference conn)
        (mongo-conn-transaction-read-preference replacement))
  (setf (mongo-conn-transaction-read-concern conn)
        (mongo-conn-transaction-read-concern replacement))
  (setf (mongo-conn-transaction-write-concern conn)
        (mongo-conn-transaction-write-concern replacement))
  (setf (mongo-conn-transaction-max-commit-time-ms conn)
        (mongo-conn-transaction-max-commit-time-ms replacement))
  (setf (mongo-conn-transaction-recovery-token conn)
        (mongo-conn-transaction-recovery-token replacement))
  (setf (mongo-conn-transaction-pinned-address conn)
        (mongo-conn-transaction-pinned-address replacement))
  (setf (mongo-conn-transaction-pinned-service-id conn)
        (mongo-conn-transaction-pinned-service-id replacement))
  (setf (mongo-conn-transaction-commit-sent conn)
        (mongo-conn-transaction-commit-sent replacement))
  (setf (mongo-conn-closed conn) nil)
  conn)

(defun mongo--close-transport (conn)
  "Close CONN's socket and buffer without ending logical sessions."
  (mongo-stop-monitor conn)
  (when-let* ((proc (mongo-conn-process conn)))
    (when (process-live-p proc)
      (delete-process proc)))
  (when-let* ((buffer (mongo-conn-buffer conn)))
    (when (buffer-live-p buffer)
      (kill-buffer buffer))))

(defun mongo--reconnect-current-server (conn)
  "Reconnect CONN to its current endpoint and return CONN."
  (let* ((old-session-id (mongo-conn-session-id conn))
         (params (or (mongo-conn-params conn)
                     `(:host ,(mongo-conn-host conn)
                       :port ,(mongo-conn-port conn)
                       :database ,(mongo-conn-database conn))))
         (credential (mongo-conn-credential conn))
         (authenticate (mongo-conn-authenticate conn))
         (host (mongo-conn-host conn))
         (port (mongo-conn-port conn))
         (database (mongo-conn-database conn))
         replacement)
    (mongo--close-transport conn)
    (setf (mongo-conn-closed conn) t)
    (setq replacement
          (car (mongo--connect-endpoint
                params host port database credential authenticate)))
    (setf (mongo-conn-params replacement)
          params)
    (setf (mongo-conn-credential replacement)
          credential)
    (setf (mongo-conn-authenticate replacement)
          authenticate)
    (setf (mongo-conn-retry-reads replacement)
          (mongo-conn-retry-reads conn))
    (setf (mongo-conn-retry-writes replacement)
          (mongo-conn-retry-writes conn))
    (mongo--replace-conn-transport
     conn replacement old-session-id)))

(defun mongo--retry-read-once (conn err)
  "Prepare CONN for one retryable read retry after ERR."
  (mongo--mark-current-server-unknown conn err)
  (mongo--reconnect-current-server conn))

(defun mongo--retry-write-once (conn err)
  "Prepare CONN for one retryable write retry after ERR."
  (mongo--mark-current-server-unknown conn err)
  (mongo--reconnect-current-server conn))

(defun mongo--retry-transaction-control-once (conn err)
  "Reconnect CONN for a transaction control retry after ERR.
The reconnect path replaces transport state from a new connection, so preserve
the active transaction metadata that commitTransaction/abortTransaction must
reuse."
  (let ((state (mongo-conn-transaction-state conn))
        (txn-number (mongo-conn-transaction-number conn))
        (read-preference (mongo-conn-transaction-read-preference conn))
        (read-concern (mongo-conn-transaction-read-concern conn))
        (write-concern (mongo-conn-transaction-write-concern conn))
        (max-commit-time-ms
         (mongo-conn-transaction-max-commit-time-ms conn))
        (recovery-token (mongo-conn-transaction-recovery-token conn))
        (commit-sent (mongo-conn-transaction-commit-sent conn)))
    (mongo--unpin-transaction conn)
    (mongo--retry-write-once conn err)
    (setf (mongo-conn-transaction-state conn) state)
    (setf (mongo-conn-transaction-number conn) txn-number)
    (setf (mongo-conn-transaction-read-preference conn) read-preference)
    (setf (mongo-conn-transaction-read-concern conn) read-concern)
    (setf (mongo-conn-transaction-write-concern conn) write-concern)
    (setf (mongo-conn-transaction-max-commit-time-ms conn)
          max-commit-time-ms)
    (setf (mongo-conn-transaction-recovery-token conn) recovery-token)
    (setf (mongo-conn-transaction-commit-sent conn) commit-sent)
    conn))

(defun mongo-in-transaction-p (conn)
  "Return non-nil when CONN has an active transaction."
  (and (mongo-conn-p conn)
       (mongo--transaction-active-state-p
        (mongo-conn-transaction-state conn))))

(defun mongo--conn-session-supported-p (conn)
  "Return non-nil when CONN reports logical session support."
  (and (mongo-conn-p conn)
       (or (mongo-conn-session-id conn)
           (mongo-conn-load-balanced conn)
           (and (mongo-conn-last-hello conn)
                (mongo--session-supported-p (mongo-conn-last-hello conn)))
           (let ((topology (mongo-conn-topology conn)))
             (and topology
                  (numberp
                   (mongo-topology-description-logical-session-timeout-minutes
                    topology)))))))

(defun mongo--ensure-session (conn)
  "Ensure CONN has an implicit logical session and return it."
  (unless (mongo--conn-session-supported-p conn)
    (signal 'mongo-error
            (list "MongoDB transactions require logical session support")))
  (or (mongo-conn-session-id conn)
      (let ((session-id (mongo--make-session-id)))
        (setf (mongo-conn-session-id conn) session-id)
        session-id)))

(defun mongo--transaction-write-concern (conn option-pairs)
  "Return effective transaction writeConcern for CONN and OPTION-PAIRS."
  (or (cdr (assoc "writeConcern" option-pairs))
      (mongo--write-concern-document
       (and conn (mongo-conn-write-concern conn)))))

(defun mongo--read-preference-value (value)
  "Return VALUE as a `mongo--read-preference'."
  (cond
   ((null value) nil)
   ((mongo--read-preference-p value) value)
   ((or (stringp value)
        (symbolp value))
    (mongo--params-read-preference
     (list :read-preference value)))
   ((or (mongo-document-p value)
        (hash-table-p value)
        (and (consp value)
             (consp (car value))))
    (let* ((pairs (mongo--document-pairs value))
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
      (mongo--params-read-preference params)))
   (t
    (signal 'mongo-error
            (list (format "Invalid MongoDB readPreference value: %S"
                          value))))))

(defun mongo--transaction-read-preference (conn option-pairs)
  "Return effective transaction readPreference for CONN and OPTION-PAIRS."
  (if-let* ((pair (assoc "readPreference" option-pairs)))
      (or (mongo--read-preference-value (cdr pair))
          (mongo-conn-read-preference conn))
    (mongo-conn-read-preference conn)))

(defun mongo--validate-transaction-write-concern (write-concern)
  "Signal when WRITE-CONCERN cannot be used in a MongoDB transaction."
  (when (mongo--unacknowledged-write-concern-p write-concern)
    (signal 'mongo-error
            (list "MongoDB transactions do not support unacknowledged write concerns")))
  write-concern)

(defun mongo--transaction-max-commit-time-ms (option-pairs)
  "Return maxCommitTimeMS from transaction OPTION-PAIRS, or nil."
  (mongo--parse-integer-option
   (cdr (assoc "maxCommitTimeMS" option-pairs))
   "maxCommitTimeMS"))

(defun mongo--validate-nonnegative-time-ms (value name)
  "Return VALUE parsed as a non-negative integer for MongoDB option NAME."
  (when-let* ((number (mongo--parse-integer-option value name)))
    (when (< number 0)
      (signal 'mongo-error
              (list (format "MongoDB %s must be non-negative" name))))
    number))

(defun mongo-start-transaction (conn &optional options)
  "Start a MongoDB transaction on CONN.
OPTIONS is an optional MongoDB document containing readConcern and
writeConcern transaction options.  The server transaction begins when the next
command is sent."
  (unless (mongo-live-p conn)
    (signal 'mongo-error
            (list "MongoDB connection is closed")))
  (when (mongo-in-transaction-p conn)
    (signal 'mongo-error
            (list "Transaction already in progress")))
  (when (mongo--transaction-ended-state-p
         (mongo-conn-transaction-state conn))
    (mongo--clear-transaction conn))
  (mongo--ensure-session conn)
  (let* ((pairs (mongo--document-pairs options))
         (read-preference (mongo--transaction-read-preference conn pairs))
         (read-concern (cdr (assoc "readConcern" pairs)))
         (write-concern
          (mongo--validate-transaction-write-concern
           (mongo--transaction-write-concern conn pairs)))
         (max-commit-time-ms
          (mongo--validate-nonnegative-time-ms
           (mongo--transaction-max-commit-time-ms pairs)
           "maxCommitTimeMS"))
         (txn-number (mongo--next-transaction-number conn)))
    (setf (mongo-conn-transaction-state conn) 'starting)
    (setf (mongo-conn-transaction-number conn) txn-number)
    (setf (mongo-conn-transaction-read-preference conn) read-preference)
    (setf (mongo-conn-transaction-read-concern conn) read-concern)
    (setf (mongo-conn-transaction-write-concern conn) write-concern)
    (setf (mongo-conn-transaction-max-commit-time-ms conn)
          max-commit-time-ms)
    (setf (mongo-conn-transaction-recovery-token conn) nil)
    (setf (mongo-conn-transaction-pinned-address conn) nil)
    (setf (mongo-conn-transaction-pinned-service-id conn) nil)
    (setf (mongo-conn-transaction-commit-sent conn) nil)
    conn))

(defun mongo--clear-transaction (conn)
  "Clear CONN transaction state."
  (setf (mongo-conn-transaction-state conn) nil)
  (setf (mongo-conn-transaction-number conn) nil)
  (setf (mongo-conn-transaction-read-preference conn) nil)
  (setf (mongo-conn-transaction-read-concern conn) nil)
  (setf (mongo-conn-transaction-write-concern conn) nil)
  (setf (mongo-conn-transaction-max-commit-time-ms conn) nil)
  (setf (mongo-conn-transaction-recovery-token conn) nil)
  (mongo--unpin-transaction conn)
  (setf (mongo-conn-transaction-commit-sent conn) nil)
  conn)

(defun mongo--document-set-field (pairs field value)
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

(defun mongo--commit-retry-write-concern (write-concern)
  "Return commitTransaction retry writeConcern from WRITE-CONCERN.
Retries and explicit subsequent commit attempts must use majority write
concern and a finite wtimeout when no wtimeout is already present."
  (let ((pairs (copy-sequence (mongo--document-pairs write-concern))))
    (setq pairs (mongo--document-set-field pairs "w" "majority"))
    (unless (assoc "wtimeout" pairs)
      (setq pairs
            (append pairs '(("wtimeout" . 10000)))))
    pairs))

(defun mongo--transaction-commit-command
    (conn max-time-ms retry-attempt)
  "Return commitTransaction command for CONN.
MAX-TIME-MS is included when non-nil.  RETRY-ATTEMPT means apply commit retry
writeConcern rules."
  (let* ((write-concern (mongo-conn-transaction-write-concern conn))
         (recovery-token (mongo-conn-transaction-recovery-token conn))
         (effective-write-concern
          (if retry-attempt
              (mongo--commit-retry-write-concern write-concern)
            write-concern)))
    `(("commitTransaction" . 1)
      ,@(when effective-write-concern
          `(("writeConcern" . ,effective-write-concern)))
      ,@(when max-time-ms
          `(("maxTimeMS" . ,max-time-ms)))
      ,@(when recovery-token
          `(("recoveryToken" . ,recovery-token))))))

(defun mongo--effective-commit-max-time-ms (conn max-time-ms)
  "Return effective commitTransaction maxTimeMS for CONN."
  (or (mongo--validate-nonnegative-time-ms max-time-ms "maxTimeMS")
      (mongo-conn-transaction-max-commit-time-ms conn)))

(defun mongo--commit-write-concern-unknown-result-p (response)
  "Return non-nil if RESPONSE writeConcernError means unknown commit result."
  (when-let* ((write-concern-error (cdr (assoc "writeConcernError" response))))
    (let ((code (cdr (assoc "code" write-concern-error)))
          (code-name (cdr (assoc "codeName" write-concern-error))))
      (not (or (member code mongo--commit-non-unknown-write-concern-error-codes)
               (member code-name
                       '("UnknownReplWriteConcern"
                         "CannotSatisfyWriteConcern"
                         "UnsatisfiableWriteConcern")))))))

(defun mongo--commit-response-unknown-result-p (conn response)
  "Return non-nil when commitTransaction RESPONSE should be labeled unknown."
  (or (mongo--retryable-write-server-error-p conn response)
      (= (or (cdr (assoc "code" response)) -1) 50)
      (mongo--commit-write-concern-unknown-result-p response)))

(defun mongo--commit-response-labels (conn response)
  "Return error labels for commitTransaction RESPONSE."
  (let ((labels (mongo--response-error-labels response)))
    (when (mongo--commit-response-unknown-result-p conn response)
      (setq labels
            (mongo--add-error-labels
             labels mongo--unknown-transaction-commit-result-label)))
    (when (mongo--retryable-write-server-error-p conn response)
      (setq labels
            (mongo--add-error-labels
             labels mongo--retryable-write-error-label)))
    labels))

(defun mongo--commit-condition-message (condition)
  "Return primary message from CONDITION."
  (let ((data (and (consp condition)
                   (cdr condition))))
    (if (and (eq (car condition) 'mongo-error)
             (stringp (car data)))
        (car data)
      (error-message-string condition))))

(defun mongo--commit-condition-labels (condition)
  "Return MongoDB labels for a failed commitTransaction CONDITION."
  (mongo--add-error-labels
   (mongo-error-labels condition)
   mongo--unknown-transaction-commit-result-label))

(defun mongo--commit-response-retryable-p (conn response)
  "Return non-nil when commitTransaction RESPONSE should be retried once."
  (or (mongo--retryable-write-server-error-p conn response)
      (mongo--retryable-write-concern-error-p conn response)))

(defun mongo--transaction-abort-command (conn)
  "Return abortTransaction command for CONN."
  (let ((write-concern (mongo-conn-transaction-write-concern conn))
        (recovery-token (mongo-conn-transaction-recovery-token conn)))
    `(("abortTransaction" . 1)
      ,@(when write-concern
          `(("writeConcern" . ,write-concern)))
      ,@(when recovery-token
          `(("recoveryToken" . ,recovery-token))))))

(defun mongo--abort-response-retryable-p (conn response)
  "Return non-nil when abortTransaction RESPONSE should be retried once."
  (or (mongo--retryable-write-server-error-p conn response)
      (mongo--retryable-write-concern-error-p conn response)))

(defun mongo--abort-ignored-response (response)
  "Return abortTransaction RESPONSE without surfacing command failure."
  (or response '(("ok" . 1))))

(defun mongo--finish-transaction (conn state)
  "Move CONN transaction to terminal STATE and return CONN."
  (setf (mongo-conn-transaction-state conn) state)
  (when (eq state 'aborted)
    (mongo--unpin-transaction conn))
  conn)

(defun mongo--run-commit-transaction
    (conn max-time-ms retry-attempt)
  "Run commitTransaction for CONN and return the response.
RETRY-ATTEMPT means apply commit retry writeConcern rules to the first attempt."
  (let ((retries 1)
        response)
    (condition-case final-error
        (catch 'done
          (while t
            (catch 'retry
              (let ((command
                     (mongo--transaction-commit-command
                      conn max-time-ms retry-attempt)))
                (condition-case err
                    (progn
                      (setf (mongo-conn-transaction-commit-sent conn) t)
                      (setq response
                            (mongo--send-command-and-receive
                             conn "admin" command nil nil nil))
                      (unless (mongo--ok-p response)
                        (if (and (> retries 0)
                                 (mongo--commit-response-retryable-p
                                  conn response))
                            (progn
                              (setq retries (1- retries))
                              (setq retry-attempt t)
                              (condition-case _reconnect-err
                                  (mongo--retry-transaction-control-once
                                   conn
                                   (list 'mongo-error
                                         (mongo--response-message response)))
                                (error
                                 (mongo--signal-transaction-error-with-labels
                                  conn
                                  (mongo--response-message response)
                                  (mongo--commit-response-labels
                                   conn response))))
                              (throw 'retry nil))
                          (mongo--signal-transaction-error-with-labels
                           conn
                           (mongo--response-message response)
                           (mongo--commit-response-labels conn response))))
                      (when-let* ((message
                                   (mongo--write-error-message response)))
                        (if (and (> retries 0)
                                 (mongo--commit-response-retryable-p
                                  conn response))
                            (progn
                              (setq retries (1- retries))
                              (setq retry-attempt t)
                              (condition-case _reconnect-err
                                  (mongo--retry-transaction-control-once
                                   conn
                                   (list 'mongo-error message))
                                (error
                                 (mongo--signal-transaction-error-with-labels
                                  conn
                                  message
                                  (mongo--commit-response-labels
                                   conn response))))
                              (throw 'retry nil))
                          (mongo--signal-transaction-error-with-labels
                           conn
                           message
                           (mongo--commit-response-labels conn response))))
                      (throw 'done response))
                  (error
                   (if (and (> retries 0)
                            (mongo--network-error-p err))
                       (progn
                         (setq retries (1- retries))
                         (setq retry-attempt t)
                         (condition-case _reconnect-err
                             (mongo--retry-transaction-control-once
                              conn err)
                           (error
                            (mongo--signal-transaction-error-with-labels
                             conn
                             (mongo--commit-condition-message err)
                             (mongo--commit-condition-labels err))))
                         (throw 'retry nil))
                     (mongo--signal-transaction-error-with-labels
                      conn
                      (mongo--commit-condition-message err)
                      (mongo--commit-condition-labels err)))))))))
      (error
       (mongo--finish-transaction conn 'committed)
       (signal (car final-error) (cdr final-error))))
    (mongo--finish-transaction conn 'committed)
    response))

(defun mongo-commit-transaction (conn &optional max-time-ms)
  "Commit the active MongoDB transaction on CONN.
When MAX-TIME-MS is non-nil, include it in the commit command."
  (pcase (mongo-conn-transaction-state conn)
    ('nil
     (signal 'mongo-error
             (list "No transaction started")))
    ('aborted
     (signal 'mongo-error
             (list "Cannot call commitTransaction after calling abortTransaction")))
    ('starting
     (mongo--finish-transaction conn 'committed)
     '(("ok" . 1)))
    ('committed
     (if (mongo-conn-transaction-commit-sent conn)
         (mongo--run-commit-transaction
          conn
          (mongo--effective-commit-max-time-ms conn max-time-ms)
          t)
       '(("ok" . 1))))
    ('in-progress
     (mongo--run-commit-transaction
      conn
      (mongo--effective-commit-max-time-ms conn max-time-ms)
      nil))
    (_
     (signal 'mongo-error
             (list "No transaction started")))))

(defun mongo-abort-transaction (conn)
  "Abort the active MongoDB transaction on CONN."
  (pcase (mongo-conn-transaction-state conn)
    ('nil
     (signal 'mongo-error
             (list "No transaction started")))
    ('committed
     (signal 'mongo-error
             (list "Cannot call abortTransaction after calling commitTransaction")))
    ('aborted
     (signal 'mongo-error
             (list "Cannot call abortTransaction twice")))
    ('starting
     (mongo--finish-transaction conn 'aborted)
     '(("ok" . 1)))
    ('in-progress
     (let ((retries 1)
           response)
       (unwind-protect
           (catch 'done
             (while t
               (catch 'retry
                 (let ((command (mongo--transaction-abort-command conn)))
                   (condition-case err
                       (progn
                         (setq response
                               (mongo--send-command-and-receive
                                conn "admin" command nil nil nil))
                         (cond
                          ((and (or (not (mongo--ok-p response))
                                    (mongo--write-error-message response))
                                (> retries 0)
                                (mongo--abort-response-retryable-p
                                 conn response))
                           (setq retries (1- retries))
                           (condition-case _reconnect-err
                               (mongo--retry-transaction-control-once
                                conn
                                (list 'mongo-error
                                      (or (mongo--write-error-message response)
                                          (mongo--response-message response))))
                             (error nil))
                           (throw 'retry nil))
                          (t
                           (throw 'done
                                  (mongo--abort-ignored-response response)))))
                     (error
                      (if (and (> retries 0)
                               (mongo--network-error-p err))
                          (progn
                            (setq retries (1- retries))
                            (condition-case _reconnect-err
                                (mongo--retry-transaction-control-once
                                 conn err)
                              (error nil))
                            (throw 'retry nil))
                        (throw 'done
                               (mongo--abort-ignored-response response)))))))))
         (mongo--finish-transaction conn 'aborted))))
    (_
     (signal 'mongo-error
             (list "No transaction started")))))

(defun mongo-command (conn database command &optional timeout sequences)
  "Run MongoDB COMMAND on DATABASE over CONN and return the response alist.
SEQUENCES, when non-nil, is sent as OP_MSG document sequence sections."
  (when conn
    (mongo--clear-ended-transaction-for-command conn command))
  (let* ((timeout (and conn (mongo--command-timeout conn timeout)))
         (retryable-read (and conn
                              (mongo--retryable-read-enabled-p conn command)))
         (retryable-write (and conn
                               (mongo--retryable-write-enabled-p
                                conn command sequences)))
         (retries (if (or retryable-read retryable-write) 1 0))
         (txn-number (and retryable-write
                          (mongo--next-transaction-number conn)))
        response)
    (catch 'done
      (while t
        (catch 'retry
          (condition-case err
              (progn
                (setq response
                      (mongo--send-command-and-receive
                       conn database command timeout sequences txn-number))
                (unless (mongo--ok-p response)
                  (let ((state-change
                         (mongo--handle-state-change-error conn response)))
                    (when (and (mongo--write-command-p command)
                               (eq state-change 'marked))
                      (ignore-errors
                        (mongo-hello conn timeout)))
                    (when (eq state-change 'stale)
                      (setq retries 0))
                    (when (and (mongo--write-command-p command)
                               (mongo--not-writable-error-p response)
                               (not (mongo--state-change-error-p response)))
                      (ignore-errors
                        (mongo-hello conn timeout)))
                    (if (and (> retries 0)
                             (or (and retryable-read
                                      (mongo--retryable-server-error-p
                                       response))
                                 (and retryable-write
                                      (mongo--retryable-write-server-error-p
                                       conn response))))
                        (progn
                          (setq retries (1- retries))
                          (if (eq state-change 'marked)
                              (mongo--reconnect-current-server conn)
                            (if retryable-read
                                (mongo--retry-read-once
                                 conn
                                 (list 'mongo-error
                                       (mongo--response-message response)))
                              (mongo--retry-write-once
                               conn
                               (list 'mongo-error
                                     (mongo--response-message response)))))
                          (throw 'retry nil))
                      (let ((labels (mongo--response-error-labels response)))
                        (mongo--transaction-unpin-for-labels conn labels)
                        (mongo--signal-error-with-labels
                         (mongo--response-message response)
                         labels)))))
                (when (and retryable-write
                           (> retries 0)
                           (mongo--retryable-write-concern-error-p
                            conn response))
                  (setq retries (1- retries))
                  (mongo--retry-write-once
                   conn
                   (list 'mongo-error
                         (or (mongo--write-error-message response)
                             (mongo--response-message response))))
                  (throw 'retry nil))
                (when-let* ((message (and (mongo--write-command-p command)
                                          (mongo--write-error-message response))))
                  (let ((labels (mongo--response-error-labels response)))
                    (mongo--transaction-unpin-for-labels conn labels)
                    (mongo--signal-error-with-labels message labels)))
                (throw 'done response))
            (error
             (if (and (> retries 0)
                      (mongo--network-error-p err)
                      (or retryable-read retryable-write))
                 (progn
                   (setq retries (1- retries))
                   (condition-case _reconnect-err
                       (if retryable-read
                           (mongo--retry-read-once conn err)
                         (mongo--retry-write-once conn err))
                     (error
                      (signal (car err) (cdr err))))
                   (throw 'retry nil))
               (if (mongo--transaction-transient-condition-p
                    conn command err)
                   (mongo--signal-transaction-transient-error err conn)
                 (signal (car err) (cdr err)))))))))))

(defun mongo-command-exhaust (conn database command &optional timeout sequences)
  "Run MongoDB COMMAND with OP_MSG exhaustAllowed and return response alists.
SEQUENCES, when non-nil, is sent as OP_MSG document sequence sections.  This is
a low-level protocol helper; callers must only use it with MongoDB commands
that can legally return exhaust-style replies."
  (when conn
    (mongo--clear-ended-transaction-for-command conn command))
  (mongo--send-command-exhaust-and-receive
   conn database command
   (and conn (mongo--command-timeout conn timeout))
   sequences))

(defun mongo--session-supported-p (hello)
  "Return non-nil when HELLO reports logical session support."
  (numberp (cdr (assoc "logicalSessionTimeoutMinutes" hello))))

(defun mongo--mark-connection-authenticated (conn)
  "Record that CONN has completed authentication when it is a real connection."
  (when (mongo-conn-p conn)
    (setf (mongo-conn-authenticate conn) t)))

(defun mongo--initialize-session (conn hello)
  "Initialize an implicit logical session on CONN if HELLO supports sessions."
  (when (and (mongo-conn-p conn)
             (or (mongo-conn-load-balanced conn)
                 (mongo--session-supported-p hello))
             (not (mongo-conn-session-id conn)))
    (setf (mongo-conn-session-id conn)
          (mongo--make-session-id))))

(defun mongo--cursor-batch (cursor key)
  "Return cursor KEY batch from CURSOR."
  (or (cdr (assoc key cursor)) nil))

(defun mongo--cursor-id (cursor)
  "Return cursor id from CURSOR."
  (or (cdr (assoc "id" cursor)) 0))

(defun mongo--cursor-namespace-collection (cursor database fallback)
  "Return getMore collection name for CURSOR in DATABASE.
FALLBACK is used when the server reply omits cursor namespace metadata."
  (let ((namespace (cdr (assoc "ns" cursor))))
    (if (and (stringp namespace)
             (string-prefix-p (concat database ".") namespace))
        (substring namespace (1+ (length database)))
      fallback)))

(defun mongo--cursor-get-more-options (options)
  "Return getMore option pairs derived from cursor OPTIONS."
  (let ((pairs (mongo--option-pairs options)))
    (delq nil
          (list
           (let ((pair (assoc "batchSize" pairs)))
             (when pair
               (cons "batchSize" (cdr pair))))
           (let ((pair (assoc "maxAwaitTimeMS" pairs)))
             (when pair
               (cons "maxAwaitTimeMS" (cdr pair))))
           (when (or (mongo--wire-truthy-p (cdr (assoc "awaitData" pairs)))
                     (mongo--wire-truthy-p (cdr (assoc "tailable" pairs)))
                     (mongo--wire-truthy-p (cdr (assoc "_stopOnEmptyBatch"
                                                       pairs))))
             (cons "_stopOnEmptyBatch" t))))))

(defun mongo-kill-cursors (conn database collection cursor-ids)
  "Kill CURSOR-IDS for COLLECTION in DATABASE on CONN."
  (when cursor-ids
    (mongo-command
     conn database
     `(("killCursors" . ,collection)
       ("cursors" . ,(vconcat cursor-ids))))))

(defun mongo--cursor-results
    (conn database collection response first-key
          &optional get-more-options suppress-network-error-kill)
  "Return all cursor results from RESPONSE, fetching more as needed.
GET-MORE-OPTIONS may include batchSize and maxAwaitTimeMS.  If it includes
_stopOnEmptyBatch, stop when an awaitable cursor returns an empty non-terminal
batch and close that server-side cursor.  When SUPPRESS-NETWORK-ERROR-KILL is
non-nil, do not issue killCursors after a getMore network error."
  (let* ((get-more-options (mongo--option-pairs get-more-options))
         (get-more-batch-size (or (cdr (assoc "batchSize" get-more-options))
                                  1000))
         (max-await-time-ms (cdr (assoc "maxAwaitTimeMS" get-more-options)))
         (stop-on-empty-batch
          (mongo--wire-truthy-p
           (cdr (assoc "_stopOnEmptyBatch" get-more-options))))
         (cursor (cdr (assoc "cursor" response)))
         (rows (copy-sequence
                (mongo--cursor-batch cursor first-key)))
         (cursor-id (mongo--cursor-id cursor))
         (cursor-collection
          (mongo--cursor-namespace-collection cursor database collection))
         close-cursor-id)
    (condition-case err
        (progn
          (while (and (integerp cursor-id)
                      (not (zerop cursor-id)))
            (setq response
                  (mongo-command
                   conn database
                   `(("getMore" . ,cursor-id)
                     ("collection" . ,cursor-collection)
                     ("batchSize" . ,get-more-batch-size)
                     ,@(when max-await-time-ms
                         `(("maxTimeMS" . ,max-await-time-ms))))))
            (let ((batch (mongo--cursor-batch
                          (cdr (assoc "cursor" response))
                          "nextBatch")))
              (setq cursor (cdr (assoc "cursor" response))
                    rows (append rows batch)
                    cursor-id (mongo--cursor-id cursor)
                    cursor-collection
                    (mongo--cursor-namespace-collection
                     cursor database cursor-collection))
              (when (and stop-on-empty-batch
                         (null batch)
                         (integerp cursor-id)
                         (not (zerop cursor-id)))
                (setq close-cursor-id cursor-id
                      cursor-id 0))))
          (when close-cursor-id
            (ignore-errors
              (mongo-kill-cursors
               conn database cursor-collection (list close-cursor-id))))
          rows)
      (error
       (when (and (integerp cursor-id)
                  (not (zerop cursor-id))
                  (not (and suppress-network-error-kill
                            (mongo--network-error-p err))))
         (ignore-errors
           (mongo-kill-cursors
            conn database cursor-collection (list cursor-id))))
       (signal (car err) (cdr err))))))

(defun mongo-list-databases (conn)
  "Return database names visible to CONN."
  (let ((response (mongo-command
                   conn "admin"
                   '(("listDatabases" . 1)))))
    (mapcar (lambda (db) (cdr (assoc "name" db)))
            (cdr (assoc "databases" response)))))

(defun mongo-list-collection-docs
    (conn database &optional filter)
  "Return collection metadata documents for DATABASE on CONN."
  (let ((response (mongo-command
                   conn database
                   `(("listCollections" . 1)
                     ("cursor" . ,(mongo-document nil))
                     ,@(when filter `(("filter" . ,filter)))))))
    (mongo--cursor-results
     conn database "$cmd.listCollections" response "firstBatch")))

(defun mongo-list-collections (conn database)
  "Return collection names for DATABASE on CONN."
  (mapcar (lambda (doc) (cdr (assoc "name" doc)))
          (mongo-list-collection-docs conn database)))

(defun mongo-create-collection
    (conn database collection &optional options)
  "Create COLLECTION in DATABASE on CONN.
OPTIONS is an alist or document of additional create command fields."
  (mongo-command
   conn database
   `(("create" . ,collection)
     ,@(mongo--option-pairs options))))

(defun mongo-list-indexes (conn database collection)
  "Return index documents for COLLECTION in DATABASE on CONN."
  (let ((response
         (mongo-command
          conn database
          `(("listIndexes" . ,collection)
            ("cursor" . ,(mongo-document nil))))))
    (mongo--cursor-results
     conn database collection response "firstBatch")))

(defun mongo-find-command
    (collection &optional filter projection limit skip options)
  "Return a MongoDB find command document for COLLECTION."
  (let ((option-pairs (mongo--option-pairs options)))
    `(("find" . ,collection)
      ("filter" . ,(or filter (mongo-document nil)))
      ("batchSize" . ,(or (cdr (assoc "batchSize" option-pairs))
                          1000))
      ,@(when projection `(("projection" . ,projection)))
      ,@(when limit `(("limit" . ,limit)))
      ,@(when skip `(("skip" . ,skip)))
      ,@(cl-remove-if (lambda (pair)
                        (member (car pair) '("batchSize" "maxAwaitTimeMS")))
                      option-pairs))))

(defun mongo-find
    (conn database collection &optional filter projection limit skip options)
  "Return documents from COLLECTION in DATABASE on CONN.
OPTIONS is an alist of additional MongoDB find command fields."
  (let* ((option-pairs (mongo--option-pairs options))
         (response
          (mongo-command
           conn database
           (mongo-find-command collection filter projection limit skip
                               option-pairs))))
    (mongo--cursor-results
     conn database collection response "firstBatch"
     (mongo--cursor-get-more-options option-pairs))))

(defun mongo-count-documents
    (conn database collection &optional filter options)
  "Return count for COLLECTION in DATABASE on CONN."
  (let ((response
         (mongo-command
          conn database
          `(("count" . ,collection)
            ,@(when filter `(("query" . ,filter)))
            ,@(mongo--option-pairs options)))))
    (cdr (assoc "n" response))))

(defun mongo-distinct
    (conn database collection field &optional filter options)
  "Return distinct FIELD values for COLLECTION in DATABASE on CONN."
  (let ((response
         (mongo-command
          conn database
          `(("distinct" . ,collection)
            ("key" . ,field)
            ,@(when filter `(("query" . ,filter)))
            ,@(mongo--option-pairs options)))))
    (cdr (assoc "values" response))))

(defun mongo--cursor-option (options)
  "Return the MongoDB cursor option document from OPTIONS."
  (let* ((option-pairs (mongo--option-pairs options))
         (cursor (cdr (assoc "cursor" option-pairs)))
         (batch-size (cdr (assoc "batchSize" option-pairs))))
    (or cursor
        (and batch-size
             (mongo-document `(("batchSize" . ,batch-size))))
        (mongo-document nil))))

(defun mongo-aggregate-command (collection pipeline &optional options)
  "Return a MongoDB aggregate command document for COLLECTION and PIPELINE.
OPTIONS is an alist or document of additional aggregate command fields.
The convenience option field batchSize is translated into cursor.batchSize."
  (let* ((option-pairs (mongo--option-pairs options))
         (extra (mongo--remove-option-pairs '("cursor" "batchSize")
                                            option-pairs)))
    `(("aggregate" . ,collection)
      ("pipeline" . ,pipeline)
      ("cursor" . ,(mongo--cursor-option options))
      ,@extra)))

(defun mongo-aggregate
    (conn database collection pipeline &optional options)
  "Return aggregation results for COLLECTION in DATABASE on CONN.
OPTIONS is an alist or document of additional aggregate command fields.
The convenience option field batchSize is translated into cursor.batchSize."
  (let* ((option-pairs (mongo--option-pairs options))
         (response
          (mongo-command
           conn database
           (mongo-aggregate-command collection pipeline option-pairs))))
    (mongo--cursor-results
     conn database collection response "firstBatch"
     (mongo--cursor-get-more-options option-pairs))))

(defun mongo-aggregate-database (conn database pipeline &optional options)
  "Return database-level aggregation results for DATABASE on CONN.
This is the protocol equivalent of mongosh `db.aggregate'.  PIPELINE should
start with a stage that does not require an underlying collection."
  (let* ((option-pairs (mongo--option-pairs options))
         (response
          (mongo-command
           conn database
           (mongo-aggregate-command 1 pipeline option-pairs))))
    (mongo--cursor-results
     conn database "$cmd.aggregate" response "firstBatch"
     (mongo--cursor-get-more-options option-pairs))))

(defconst mongo--change-stream-option-keys
  '("resumeAfter" "startAfter" "fullDocument" "fullDocumentBeforeChange"
    "showExpandedEvents" "startAtOperationTime")
  "MongoDB watch() option names that belong in the $changeStream stage.")

(defconst mongo--watch-command-option-keys
  '("batchSize" "collation" "comment" "maxTimeMS")
  "MongoDB watch() option names that belong on the aggregate command.")

(defun mongo--change-stream-stage-options (options)
  "Return the $changeStream stage option document from OPTIONS."
  (mongo-document
   (cl-remove-if-not
    (lambda (pair)
      (member (car pair) mongo--change-stream-option-keys))
    (mongo--option-pairs options))))

(defun mongo--watch-command-options (options)
  "Return aggregate command options derived from watch OPTIONS."
  (cl-remove-if-not
   (lambda (pair)
     (member (car pair) mongo--watch-command-option-keys))
   (mongo--option-pairs options)))

(defun mongo--watch-get-more-options (options)
  "Return getMore options derived from watch OPTIONS."
  (append (mongo--cursor-get-more-options options)
          '(("_stopOnEmptyBatch" . t))))

(defun mongo--watch-pipeline (pipeline options)
  "Return a change-stream aggregate pipeline from PIPELINE and OPTIONS."
  (vconcat
   (vector (mongo-document
            (list (cons "$changeStream"
                        (mongo--change-stream-stage-options options)))))
   (or pipeline [])))

(defun mongo-watch-command (collection &optional pipeline options)
  "Return a MongoDB aggregate command that opens a change stream.
COLLECTION may be a collection name or 1 for database-level watches."
  (mongo-aggregate-command
   collection
   (mongo--watch-pipeline pipeline options)
   (mongo--watch-command-options options)))

(defun mongo-watch
    (conn database collection &optional pipeline options)
  "Open a collection change stream and return available events.
Clutch consumes a finite batch rather than returning a live cursor object: once
an empty await batch is observed, the server cursor is closed."
  (let* ((option-pairs (mongo--option-pairs options))
         (response
          (mongo-command
           conn database
           (mongo-watch-command collection pipeline option-pairs))))
    (mongo--cursor-results
     conn database collection response "firstBatch"
     (mongo--watch-get-more-options option-pairs))))

(defun mongo-watch-database
    (conn database &optional pipeline options)
  "Open a database-level change stream and return available events.
This is the protocol equivalent of mongosh `db.watch'."
  (let* ((option-pairs (mongo--option-pairs options))
         (response
          (mongo-command
           conn database
           (mongo-watch-command 1 pipeline option-pairs))))
    (mongo--cursor-results
     conn database "$cmd.aggregate" response "firstBatch"
     (mongo--watch-get-more-options option-pairs))))

(defun mongo--explain-verbosity (verbosity)
  "Return MongoDB explain VERBOSITY normalized from shell-style values."
  (cond
   ((null verbosity) nil)
   ((eq verbosity t) "allPlansExecution")
   ((eq verbosity :false) "queryPlanner")
   (t verbosity)))

(defun mongo-explain (conn database command &optional verbosity)
  "Explain MongoDB COMMAND on DATABASE over CONN.
VERBOSITY may be nil, a MongoDB verbosity string, t, or :false.  Boolean
values follow mongosh compatibility rules."
  (let ((verbosity (mongo--explain-verbosity verbosity)))
    (mongo-command
     conn database
     `(("explain" . ,(mongo-document command))
       ,@(when verbosity
           `(("verbosity" . ,verbosity)))))))

(defun mongo-insert
    (conn database collection documents &optional ordered)
  "Insert DOCUMENTS into COLLECTION in DATABASE on CONN."
  (let ((docs (mongo--insert-documents-with-generated-ids documents))
        (command `(("insert" . ,collection)
                   ("ordered" . ,(if (eq ordered :false) :false t))))
        (response nil))
    (let ((mongo--retryable-write-context t))
      (dolist (batch (mongo--insert-document-batches
                      conn database command docs))
        (setq response
              (mongo-command
               conn database
               command
               nil
               `(("documents" . ,batch))))))
    response))

(defun mongo-delete
    (conn database collection filter &optional limit)
  "Delete documents from COLLECTION in DATABASE on CONN."
  (let ((deletes (vector
                  `(("q" . ,(or filter
                                (mongo-document nil)))
                    ("limit" . ,(or limit 0))))))
    (let ((mongo--retryable-write-context t))
      (mongo-command
       conn database
       `(("delete" . ,collection))
       nil
       `(("deletes" . ,deletes))))))

(defun mongo--bulk-write-operation-p (value)
  "Return non-nil when VALUE is one bulkWrite operation document."
  (and (mongo--document-value-p value)
       (let ((pairs (mongo--document-pairs value)))
         (or (assoc "insert" pairs)
             (assoc "update" pairs)
             (assoc "delete" pairs)))))

(defun mongo--bulk-write-operations-list (operations)
  "Return MongoDB bulkWrite OPERATIONS as a non-empty list."
  (let ((ops (cond
              ((null operations) nil)
              ((vectorp operations) (append operations nil))
              ((mongo--bulk-write-operation-p operations)
               (list operations))
              ((listp operations) operations)
              (t (list operations)))))
    (unless ops
      (signal 'mongo-error
              (list "MongoDB bulkWrite requires at least one operation")))
    ops))

(defun mongo--bulk-write-namespace (operation)
  "Return the namespace string from bulkWrite OPERATION."
  (let* ((pairs (mongo--document-pairs operation))
         (value (or (cdr (assoc "insert" pairs))
                    (cdr (assoc "update" pairs))
                    (cdr (assoc "delete" pairs)))))
    (unless (and (stringp value)
                 (string-match-p "\\`[^.]+\\..+\\'" value))
      (signal 'mongo-error
              (list (format "MongoDB bulkWrite operation requires a namespace like database.collection, got %S"
                            value))))
    value))

(defun mongo--bulk-write-op-kind (operation)
  "Return the bulkWrite operation kind for OPERATION."
  (let* ((pairs (mongo--document-pairs operation))
         (kinds (delq nil
                      (list (and (assoc "insert" pairs) "insert")
                            (and (assoc "update" pairs) "update")
                            (and (assoc "delete" pairs) "delete")))))
    (unless (= (length kinds) 1)
      (signal 'mongo-error
              (list "MongoDB bulkWrite operation must contain exactly one of insert, update, or delete")))
    (car kinds)))

(defun mongo--bulk-write-namespace-index (namespace namespaces)
  "Return zero-based index for NAMESPACE, adding it to NAMESPACES if needed."
  (let ((existing (assoc namespace (cdr namespaces))))
    (if existing
        (cdr existing)
      (let ((index (length (cdr namespaces))))
        (setcdr namespaces
                (append (cdr namespaces)
                        (list (cons namespace index))))
        index))))

(defun mongo--bulk-write-op-document (operation namespaces)
  "Return one server-format bulkWrite op from OPERATION and NAMESPACES."
  (let* ((pairs (mongo--document-pairs operation))
         (kind (mongo--bulk-write-op-kind operation))
         (namespace (mongo--bulk-write-namespace operation))
         (namespace-index
          (mongo--bulk-write-namespace-index namespace namespaces))
         (extra (cl-remove-if (lambda (pair)
                                (member (car pair)
                                        '("insert" "update" "delete")))
                              pairs)))
    (when (and (equal kind "insert")
               (not (assoc "document" extra)))
      (signal 'mongo-error
              (list "MongoDB bulkWrite insert operation requires document")))
    (append (list (cons kind namespace-index))
            (if (and (equal kind "insert")
                     (assoc "document" extra))
                (mongo--document-set-field
                 extra
                 "document"
                 (mongo--document-with-generated-id
                  (cdr (assoc "document" extra))))
              extra))))

(defun mongo--bulk-write-ns-info (namespaces)
  "Return bulkWrite nsInfo sequence from NAMESPACES."
  (vconcat
   (mapcar (lambda (entry)
             `(("ns" . ,(car entry))))
           (cdr namespaces))))

(defun mongo--bulk-write-option (pairs name)
  "Return option NAME from PAIRS."
  (cdr (assoc name pairs)))

(defun mongo--bulk-write-command-document (options)
  "Return the MongoDB bulkWrite command document for OPTIONS."
  (let* ((pairs (mongo--option-pairs options))
         (ordered-pair (assoc "ordered" pairs))
         (verbose-pair (assoc "verboseResults" pairs))
         (ordered (if ordered-pair
                      (if (mongo--wire-truthy-p (cdr ordered-pair)) t :false)
                    t))
         (verbose (and verbose-pair
                       (mongo--wire-truthy-p (cdr verbose-pair))))
         (errors-only (if verbose :false t))
         (extra (mongo--remove-option-pairs
                 '("ordered" "verboseResults" "errorsOnly")
                 pairs)))
    (append `(("bulkWrite" . 1)
              ("ordered" . ,ordered)
              ("errorsOnly" . ,errors-only))
            extra)))

(defun mongo--bulk-write-count-fields ()
  "Return numeric bulkWrite response counter field names."
  '("nErrors" "nInserted" "nMatched" "nModified" "nDeleted" "nUpserted"))

(defun mongo--bulk-write-ordered-p (command)
  "Return non-nil when bulkWrite COMMAND is ordered."
  (mongo--wire-truthy-p (mongo--document-field command "ordered")))

(defun mongo--bulk-write-validate-write-concern
    (conn command verbose-results)
  "Signal when bulkWrite COMMAND uses invalid unacknowledged write concern."
  (let ((write-concern (mongo--write-concern-value conn command))
        (ordered (mongo--wire-truthy-p
                  (mongo--document-field command "ordered"))))
    (when (and (mongo--unacknowledged-write-concern-p write-concern)
               (or ordered verbose-results))
      (signal 'mongo-error
              (list "MongoDB bulkWrite with unacknowledged write concern requires ordered=false and verboseResults=false")))))

(defun mongo--bulk-write-batch-command (operations options)
  "Return one bulkWrite (COMMAND . SEQUENCES) batch for OPERATIONS."
  (let ((namespaces (list nil))
        (ops nil))
    (dolist (operation operations)
      (push (mongo--bulk-write-op-document operation namespaces)
            ops))
    (cons (mongo--bulk-write-command-document options)
          `(("ops" . ,(vconcat (nreverse ops)))
            ("nsInfo" . ,(mongo--bulk-write-ns-info namespaces))))))

(defun mongo--bulk-write-message-size (conn command sequences)
  "Return bulkWrite COMMAND and SEQUENCES OP_MSG size for CONN.
The size is measured without later command-agnostic fields such as $db or lsid,
matching the bulkWrite batching rule."
  (let ((max-message (mongo--max-message-size-bytes conn)))
    (cl-letf (((symbol-function 'mongo--max-message-size-bytes)
               (lambda (_conn) max-message)))
      (mongo--validate-op-msg-size conn command sequences))))

(defun mongo--bulk-write-batch-within-budget-p
    (conn command sequences)
  "Return non-nil when bulkWrite COMMAND and SEQUENCES fit one batch."
  (<= (mongo--bulk-write-message-size conn command sequences)
      (- (mongo--max-message-size-bytes conn)
         mongo--write-batch-message-safety-bytes)))

(defun mongo--bulk-write-batch-entry
    (start operations options)
  "Return one bulkWrite batch entry from START, OPERATIONS, and OPTIONS."
  (let ((command-and-sequences
         (mongo--bulk-write-batch-command operations options)))
    (list :start start
          :count (length operations)
          :command (car command-and-sequences)
          :sequences (cdr command-and-sequences))))

(defun mongo--bulk-write-batches (conn operations options)
  "Return bulkWrite batches for OPERATIONS respecting CONN limits."
  (let* ((max-count (mongo--max-write-batch-size conn))
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
                    (mongo--bulk-write-batch-command candidate options))
                   (command (car command-and-sequences))
                   (sequences (cdr command-and-sequences))
                   (fits (mongo--bulk-write-batch-within-budget-p
                          conn command sequences)))
              (cond
               (fits
                (setq current candidate)
                (setq current-count (1+ current-count))
                (setq remaining (cdr remaining)))
               ((null current)
                (signal 'mongo-error
                        (list "MongoDB bulkWrite operation exceeds maxMessageSizeBytes batch budget")))
               (t
                (throw 'batch-full nil))))))
        (push (mongo--bulk-write-batch-entry
               start current options)
              batches)
        (setq start (+ start (length current)))))
    (nreverse batches)))

(defun mongo-bulk-write-command (operations &optional options)
  "Return (COMMAND . SEQUENCES) for MongoDB client-level bulkWrite.
OPERATIONS is a list or vector of operation documents.  Each operation uses
one of (\"insert\" . \"db.coll\"), (\"update\" . \"db.coll\"), or
(\"delete\" . \"db.coll\") plus the command fields for that operation.
OPTIONS is a MongoDB command option document."
  (mongo--bulk-write-batch-command
   (mongo--bulk-write-operations-list operations)
   options))

(defun mongo--bulk-write-adjust-result-index (result offset)
  "Return bulkWrite RESULT with idx adjusted by OFFSET."
  (if (and offset
           (not (zerop offset))
           (assoc "idx" (mongo--document-pairs result)))
      (mongo--document-set-field
       (copy-sequence (mongo--document-pairs result))
       "idx"
       (+ offset (cdr (assoc "idx" (mongo--document-pairs result)))))
    result))

(defun mongo--bulk-write-accumulate-counts (counts response)
  "Accumulate bulkWrite numeric counters from RESPONSE into COUNTS."
  (dolist (field (mongo--bulk-write-count-fields))
    (when-let* ((value (cdr (assoc field response))))
      (setf (alist-get field counts nil nil #'equal)
            (+ (or (alist-get field counts nil nil #'equal) 0)
               value))))
  counts)

(defun mongo-bulk-write
    (conn operations &optional options timeout)
  "Run a MongoDB client-level bulkWrite on CONN.
The command is sent to admin using OP_MSG document sequences for ops and
nsInfo.  The returned response includes a \"results\" vector containing all
cursor result documents."
  (let* ((operations (mongo--bulk-write-operations-list operations))
         (command (mongo--bulk-write-command-document options))
         (verbose-results
          (mongo--wire-truthy-p
           (mongo--bulk-write-option
            (mongo--option-pairs options)
            "verboseResults")))
         (ordered (mongo--bulk-write-ordered-p command))
	 (batches (mongo--bulk-write-batches conn operations options))
	 counts
	 results
	 last-response
	 stop
	 (operation-id (mongo--next-command-operation-id)))
    (mongo--bulk-write-validate-write-concern
     conn command verbose-results)
    (let ((mongo--command-operation-id operation-id))
      (dolist (batch batches)
	(unless stop
	  (let* ((batch-start (plist-get batch :start))
		 (batch-command (plist-get batch :command))
		 (batch-sequences (plist-get batch :sequences))
		 (response
		  (mongo-command
		   conn "admin" batch-command timeout batch-sequences))
		 (batch-results
		  (mongo--cursor-results
		   conn "admin" "$cmd.bulkWrite" response "firstBatch")))
	    (setq last-response response)
	    (setq counts (mongo--bulk-write-accumulate-counts counts response))
	    (setq results
		  (append results
			  (mapcar (lambda (result)
				    (mongo--bulk-write-adjust-result-index
				     result batch-start))
				  batch-results)))
	    (when (and ordered
		       (> (or (cdr (assoc "nErrors" response)) 0) 0))
	      (setq stop t))))))
    (append (cl-remove-if
	     (lambda (pair)
	       (member (car pair) (mongo--bulk-write-count-fields)))
             (or last-response '(("ok" . 1))))
            counts
            `(("results" . ,(vconcat results))))))

(defun mongo--option-pairs (options)
  "Return MongoDB command option pairs from OPTIONS."
  (if options
      (mongo--document-pairs options)
    nil))

(defun mongo--remove-option-pairs (keys pairs)
  "Return PAIRS without any entry whose car is in KEYS."
  (cl-remove-if (lambda (pair)
                  (member (car pair) keys))
                pairs))

(defun mongo--index-name (keys)
  "Return a MongoDB index name for key document KEYS."
  (mapconcat
   (lambda (pair)
     (format "%s_%s" (car pair) (cdr pair)))
   (mongo--document-pairs keys)
   "_"))

(defun mongo-create-index
    (conn database collection keys &optional options)
  "Create one index with KEYS on COLLECTION in DATABASE on CONN."
  (let* ((option-pairs (mongo--option-pairs options))
         (name (or (cdr (assoc "name" option-pairs))
                   (mongo--index-name keys)))
         (extra (mongo--remove-option-pairs '("key" "name")
                                            option-pairs)))
    (mongo-command
     conn database
     `(("createIndexes" . ,collection)
       ("indexes" . ,(vector
                      (append
                       `(("key" . ,keys)
                         ("name" . ,name))
                       extra)))))))

(defun mongo-drop-index (conn database collection index)
  "Drop INDEX from COLLECTION in DATABASE on CONN."
  (mongo-command
   conn database
   `(("dropIndexes" . ,collection)
     ("index" . ,index))))

(defun mongo-update
    (conn database collection filter update &optional multi options)
  "Update documents in COLLECTION in DATABASE on CONN.
FILTER is the update query, UPDATE is an update document or pipeline, MULTI
controls whether more than one document may be updated, and OPTIONS is a
MongoDB options document."
  (let* ((option-pairs (mongo--option-pairs options))
         (upsert (cdr (assoc "upsert" option-pairs)))
         (extra (mongo--remove-option-pairs '("upsert" "multi")
                                            option-pairs)))
    (let ((updates
           (vector
            (append
             `(("q" . ,(or filter (mongo-document nil)))
               ("u" . ,update)
               ("multi" . ,(if multi t :false)))
             (when upsert
               `(("upsert" . ,upsert)))
             extra))))
      (let ((mongo--retryable-write-context t))
        (mongo-command
         conn database
         `(("update" . ,collection))
         nil
         `(("updates" . ,updates)))))))

(defun mongo--find-and-modify-new-value (options)
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

(defun mongo-find-and-modify
    (conn database collection filter &optional update remove options)
  "Run findAndModify on COLLECTION in DATABASE on CONN.
FILTER is the query document.  UPDATE is an update/replacement value unless
REMOVE is non-nil.  OPTIONS is a MongoDB options document."
  (let* ((option-pairs (mongo--option-pairs options))
         (projection (or (cdr (assoc "projection" option-pairs))
                         (cdr (assoc "fields" option-pairs))))
         (new (mongo--find-and-modify-new-value option-pairs))
         (extra (mongo--remove-option-pairs
                 '("projection" "fields" "new" "returnNewDocument"
                   "returnDocument")
                 option-pairs)))
    (let ((mongo--retryable-write-context t))
      (mongo-command
       conn database
       (append
        `(("findAndModify" . ,collection)
          ("query" . ,(or filter (mongo-document nil))))
        (if remove
            '(("remove" . t))
          `(("update" . ,update)))
        (when projection
          `(("fields" . ,projection)))
        (when new
          `(("new" . ,new)))
        extra)))))

(defun mongo-drop-collection (conn database collection)
  "Drop COLLECTION in DATABASE on CONN."
  (mongo-command
   conn database
   `(("drop" . ,collection))))

(defun mongo-drop-database (conn database)
  "Drop DATABASE on CONN."
  (mongo-command
   conn database
   '(("dropDatabase" . 1))))

;;;; Lifecycle

(defun mongo--tls-available-p ()
  "Return non-nil when GnuTLS is available."
  (and (fboundp 'gnutls-available-p)
       (gnutls-available-p)))

(defun mongo--upgrade-to-tls (proc host params timeout)
  "Upgrade PROC to TLS for HOST using PARAMS within TIMEOUT seconds."
  (unless (mongo--tls-available-p)
    (signal 'mongo-error
            (list "Native MongoDB TLS requires GnuTLS support in Emacs")))
  (let ((spec (mongo--params-tls-spec params host)))
    (when spec
      (condition-case err
          (with-timeout (timeout
                         (signal 'mongo-error
                                 (list "Timed out negotiating MongoDB TLS")))
            (apply #'gnutls-negotiate
                   (append (list :process proc
                                 :type 'gnutls-x509pki)
                           spec)))
        (gnutls-error
         (signal 'mongo-error
                 (list (format "MongoDB TLS negotiation failed: %s"
                               (error-message-string err)))))))))

(defun mongo--local-socket-endpoint-p (host port)
  "Return non-nil when HOST and PORT name a UNIX-domain socket endpoint."
  (and (null port)
       (stringp host)
       (file-name-absolute-p host)))

(defun mongo--make-network-process (buffer host port)
  "Open a MongoDB network process for BUFFER, HOST, and PORT."
  (if (mongo--local-socket-endpoint-p host port)
      (make-network-process
       :name "mongo"
       :buffer buffer
       :family 'local
       :service host
       :coding 'binary
       :filter-multibyte nil
       :noquery t)
    (make-network-process
     :name "mongo"
     :buffer buffer
     :host host
     :service port
     :coding 'binary
     :filter-multibyte nil
     :noquery t)))

(defun mongo--process-read-bytes (proc buffer count timeout context)
  "Read COUNT bytes from PROC BUFFER within TIMEOUT for CONTEXT."
  (let ((conn (make-mongo-conn :process proc
                               :buffer buffer
                               :socket-timeout timeout
                               :closed nil)))
    (condition-case err
        (progn
          (mongo--wait-for-bytes conn count timeout)
          (with-current-buffer buffer
            (prog1 (buffer-substring-no-properties
                    (point-min)
                    (+ (point-min) count))
              (delete-region (point-min) (+ (point-min) count)))))
      (mongo-error
       (signal 'mongo-error
               (list (format "%s: %s"
                             context
                             (error-message-string err))))))))

(defun mongo--socks5-reply-message (code)
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

(defun mongo--socks5-send (proc data)
  "Send SOCKS5 DATA to PROC."
  (process-send-string proc (mongo--byte-string data)))

(defun mongo--socks5-auth-methods (proxy)
  "Return SOCKS5 auth method bytes for PROXY."
  (if (plist-get proxy :username)
      (unibyte-string #x00 #x02)
    (unibyte-string #x00)))

(defun mongo--socks5-username-password-auth (proc buffer proxy timeout)
  "Authenticate SOCKS5 PROC with username/password PROXY credentials."
  (let* ((username (mongo--utf8-bytes (plist-get proxy :username)))
         (password (mongo--utf8-bytes (plist-get proxy :password)))
         (reply nil))
    (mongo--socks5-send
     proc
     (concat (unibyte-string #x01
                             (length username))
             username
             (unibyte-string (length password))
             password))
    (setq reply
          (mongo--process-read-bytes
           proc buffer 2 timeout "MongoDB SOCKS5 username/password auth"))
    (unless (= (aref reply 0) #x01)
      (signal 'mongo-error
              (list (format "MongoDB SOCKS5 auth returned unexpected version: %s"
                            (aref reply 0)))))
    (unless (= (aref reply 1) #x00)
      (signal 'mongo-error
              (list "MongoDB SOCKS5 username/password authentication failed")))))

(defun mongo--socks5-connect-request (host port)
  "Return SOCKS5 CONNECT request bytes for MongoDB HOST and PORT."
  (let ((host-bytes (mongo--utf8-bytes host)))
    (unless (and (integerp port)
                 (> port 0)
                 (<= port 65535))
      (signal 'mongo-error
              (list "MongoDB SOCKS5 target port must be between 1 and 65535")))
    (when (> (length host-bytes) 255)
      (signal 'mongo-error
              (list "MongoDB SOCKS5 target host cannot exceed 255 UTF-8 bytes")))
    (concat (unibyte-string #x05 #x01 #x00 #x03
                            (length host-bytes))
            host-bytes
            (mongo--pack-uint16-be port))))

(defun mongo--socks5-read-reply (proc buffer timeout)
  "Read and validate a SOCKS5 CONNECT reply from PROC BUFFER."
  (let* ((header (mongo--process-read-bytes
                  proc buffer 4 timeout "MongoDB SOCKS5 CONNECT reply"))
         (version (aref header 0))
         (reply-code (aref header 1))
         (reserved (aref header 2))
         (address-type (aref header 3)))
    (unless (= version #x05)
      (signal 'mongo-error
              (list (format "MongoDB SOCKS5 CONNECT returned unexpected version: %s"
                            version))))
    (unless (= reserved #x00)
      (signal 'mongo-error
              (list "MongoDB SOCKS5 CONNECT reply reserved byte is invalid")))
    (pcase address-type
      (#x01
       (mongo--process-read-bytes
        proc buffer 6 timeout "MongoDB SOCKS5 IPv4 bind address"))
      (#x03
       (let* ((length-byte (mongo--process-read-bytes
                            proc buffer 1 timeout
                            "MongoDB SOCKS5 domain bind address length"))
              (length (aref length-byte 0)))
         (mongo--process-read-bytes
          proc buffer (+ length 2) timeout
          "MongoDB SOCKS5 domain bind address")))
      (#x04
       (mongo--process-read-bytes
        proc buffer 18 timeout "MongoDB SOCKS5 IPv6 bind address"))
      (_
       (signal 'mongo-error
               (list (format "MongoDB SOCKS5 CONNECT returned unknown address type: %s"
                             address-type)))))
    (unless (= reply-code #x00)
      (signal 'mongo-error
              (list (format "MongoDB SOCKS5 CONNECT failed: %s"
                            (or (mongo--socks5-reply-message reply-code)
                                (format "reply code %s" reply-code))))))))

(defun mongo--socks5-connect (proc buffer host port proxy timeout)
  "Open a SOCKS5 tunnel over PROC to MongoDB HOST and PORT using PROXY."
  (let* ((methods (mongo--socks5-auth-methods proxy))
         (reply nil))
    (mongo--socks5-send
     proc
     (concat (unibyte-string #x05 (length methods))
             methods))
    (setq reply
          (mongo--process-read-bytes
           proc buffer 2 timeout "MongoDB SOCKS5 greeting"))
    (unless (= (aref reply 0) #x05)
      (signal 'mongo-error
              (list (format "MongoDB SOCKS5 greeting returned unexpected version: %s"
                            (aref reply 0)))))
    (pcase (aref reply 1)
      (#x00 nil)
      (#x02
       (unless (plist-get proxy :username)
         (signal 'mongo-error
                 (list "MongoDB SOCKS5 proxy requested username/password authentication but no proxyUsername was configured")))
       (mongo--socks5-username-password-auth proc buffer proxy timeout))
      (#xff
       (signal 'mongo-error
               (list "MongoDB SOCKS5 proxy has no acceptable authentication method")))
      (method
       (signal 'mongo-error
               (list (format "MongoDB SOCKS5 proxy selected unsupported authentication method: %s"
                             method)))))
    (mongo--socks5-send
     proc
     (mongo--socks5-connect-request host port))
    (mongo--socks5-read-reply proc buffer timeout)))

(defun mongo--send-initial-handshake
    (conn credential compressors server-api load-balanced speculative-auth
          app-name)
  "Send the initial MongoDB handshake and return the hello response."
  (let ((command (mongo--initial-handshake-command
                  credential compressors server-api load-balanced
                  speculative-auth app-name)))
    (if (or server-api load-balanced)
        (let ((request-id
               (mongo--send-document
                conn
                (mongo--command-with-db command "admin" server-api))))
          (mongo--recv-message conn nil request-id))
      (let ((request-id (mongo--send-handshake conn command)))
        (mongo--recv-handshake-message conn nil request-id)))))

(defun mongo--connect-endpoint (params host port database credential
                                       &optional authenticate)
  "Open one MongoDB endpoint from PARAMS and return (CONN . HELLO).
HOST, PORT, and DATABASE identify the endpoint.  CREDENTIAL is used for
handshake negotiation.  When AUTHENTICATE is non-nil, authenticate CONN before
returning."
  (let ((buffer (generate-new-buffer " *mongo*"))
        (timeout (mongo--params-connect-timeout params))
        (compressors (mongo--params-compressors params))
        (server-api (mongo--params-server-api params))
        (read-preference (mongo--params-read-preference params))
        (read-concern (mongo--params-read-concern params))
        (write-concern (mongo--params-write-concern params))
        (load-balanced (mongo--params-load-balanced-p params))
        (app-name (mongo--params-app-name params))
        (socket-timeout (mongo--params-socket-timeout params))
        (operation-timeout (mongo--params-operation-timeout params))
        (local-threshold (mongo--params-local-threshold params))
        (heartbeat-frequency (mongo--params-heartbeat-frequency params))
        (server-monitoring-mode
         (mongo--params-server-monitoring-mode params))
        (proxy (mongo--params-proxy params))
        (speculative-auth (and authenticate
                               (mongo--speculative-auth-state credential)))
        (phase 'preflight)
        proc conn)
    (with-current-buffer buffer
      (set-buffer-multibyte nil))
    (condition-case err
        (progn
          (when (and (mongo--local-socket-endpoint-p host port)
                     (mongo--params-tls-enabled-p params))
            (signal 'mongo-error
                    (list "Native MongoDB TLS is not supported over UNIX-domain sockets")))
          (when (and proxy
                     (mongo--local-socket-endpoint-p host port))
            (signal 'mongo-error
                    (list "Native MongoDB SOCKS5 proxy is not supported over UNIX-domain sockets")))
          (setq phase 'socket)
          (setq proc
                (with-timeout (timeout
                               (signal 'mongo-error
                                       (list "Timed out connecting to MongoDB")))
                  (if proxy
                      (mongo--make-network-process
                       buffer
                       (plist-get proxy :host)
                       (plist-get proxy :port))
                    (mongo--make-network-process buffer host port))))
          (set-process-coding-system proc 'binary 'binary)
          (when proxy
            (setq phase 'socks5)
            (mongo--socks5-connect proc buffer host port proxy timeout))
          (when (mongo--params-tls-enabled-p params)
            (setq phase 'tls)
            (mongo--upgrade-to-tls proc host params timeout)
            (set-process-coding-system proc 'binary 'binary))
          (setq conn
                (make-mongo-conn
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
                 :retry-reads (mongo--params-retry-reads-p params)
                 :retry-writes (mongo--params-retry-writes-p params)
                 :request-id 0
                 :txn-number 0
                 :closed nil))
          (let* ((handshake-start (float-time))
                 (hello (progn
                          (setq phase 'hello)
                          (mongo--send-initial-handshake
                           conn credential compressors server-api
                           load-balanced speculative-auth app-name)))
                 (handshake-rtt (- (float-time) handshake-start))
                 (max-wire (or (cdr (assoc "maxWireVersion" hello)) 0))
                 (negotiated-compressors
                  (mongo--negotiated-compressors
                   compressors
                   (cdr (assoc "compression" hello))))
                 (service-id (cdr (assoc "serviceId" hello))))
            (setq phase 'post-hello)
            (setf (mongo-conn-max-wire-version conn)
                  max-wire)
            (mongo--apply-hello-limits conn hello)
            (setf (mongo-conn-compressors conn)
                  negotiated-compressors)
            (setf (mongo-conn-server-api conn)
                  server-api)
            (setf (mongo-conn-read-preference conn)
                  read-preference)
            (setf (mongo-conn-read-concern conn)
                  read-concern)
            (setf (mongo-conn-write-concern conn)
                  write-concern)
            (setf (mongo-conn-load-balanced conn)
                  load-balanced)
            (setf (mongo-conn-service-id conn)
                  service-id)
            (setf (mongo-conn-hello-command conn)
                  (mongo--post-handshake-hello-command
                   hello
                   (or server-api load-balanced)))
            (setf (mongo-conn-last-hello conn)
                  hello)
            (setf (mongo-conn-topology conn)
                  (mongo--topology-description-from-hello
                   conn hello handshake-rtt))
            (mongo--ensure-topology-compatible
             (mongo-conn-topology conn))
            (when (and load-balanced
                       (not service-id))
              (signal 'mongo-error
                      (list "Driver attempted to initialize in load balancing mode, but the server does not support this mode.")))
            (mongo--emit-sdam-opening-events
             conn (mongo-conn-topology conn))
            (setq phase 'auth)
            (when (and authenticate credential)
              (mongo--authenticate conn credential hello speculative-auth))
            (setq phase 'connected)
            (when authenticate
              (mongo--initialize-session conn hello))
            (cons conn hello)))
      (error
       (ignore-errors (mongo-disconnect conn))
       (unless conn
         (when proc
           (ignore-errors
             (delete-process proc)))
         (when (buffer-live-p buffer)
           (kill-buffer buffer)))
       (mongo--resignal-connect-error phase err)))))

(defun mongo--wire-truthy-p (value)
  "Return non-nil when MongoDB wire VALUE represents truth."
  (or (eq value t)
      (and (numberp value) (> value 0))
      (equal value "1")
      (equal value "true")))

(defun mongo--hello-command-document
    (conn &optional topology-version max-await-time-ms)
  "Return a post-handshake hello command document for CONN."
  (let ((command-name (or (mongo-conn-hello-command conn) "hello")))
    `((,command-name . 1)
      ,@(when topology-version
          `(("topologyVersion" .
             ,(mongo--topology-version-command-value topology-version))
            ("maxAwaitTimeMS" . ,max-await-time-ms))))))

(defun mongo--run-hello-command (conn command &optional timeout)
  "Run hello COMMAND on CONN and update cached topology state."
  (let* ((hello-start (float-time))
         (hello (mongo-command conn "admin" command timeout))
         (hello-rtt (- (float-time) hello-start)))
    (setf (mongo-conn-last-hello conn)
          hello)
    (mongo--apply-hello-limits conn hello)
    (mongo--set-conn-topology
     conn
     (mongo--topology-description-from-hello
      conn hello hello-rtt))
    (when (mongo--wire-truthy-p (cdr (assoc "helloOk" hello)))
      (setf (mongo-conn-hello-command conn)
            "hello"))
    hello))

(defun mongo-hello (conn &optional timeout)
  "Run a post-handshake hello probe on CONN and return the response.
This is the command shape used for topology monitoring: it does not include
initial handshake metadata such as client information, compression, or
speculative authentication."
  (mongo--run-hello-command
   conn
   (mongo--hello-command-document conn)
   timeout))

(defun mongo-awaitable-hello
    (conn max-await-time-ms &optional timeout)
  "Run an awaitable hello probe on CONN and return the response.
When the current server description has a topologyVersion, include both
topologyVersion and MAX-AWAIT-TIME-MS, matching MongoDB's awaitable hello
monitoring protocol.  Older servers without topologyVersion fall back to a
normal post-handshake hello."
  (let* ((server (mongo--current-server-description conn))
         (topology-version
          (and server
               (mongo-server-description-topology-version server))))
    (mongo--run-hello-command
     conn
     (mongo--hello-command-document
      conn
      topology-version
     (and topology-version max-await-time-ms))
     timeout)))

(defun mongo-monitor-once
    (conn &optional max-await-time-ms timeout)
  "Run one MongoDB monitor heartbeat for CONN.
The heartbeat uses awaitable hello when the server has a topologyVersion,
unless CONN is configured with serverMonitoringMode=poll.
On success, return the hello response and clear `mongo-conn-monitor-error'.
On failure, record the error, mark the current server Unknown, and signal it.
In load-balanced mode, do not run a monitoring command; return the cached hello
response from the initial connection handshake instead."
  (if (mongo-conn-load-balanced conn)
      (progn
        (setf (mongo-conn-monitor-error conn) nil)
        (mongo-conn-last-hello conn))
    (let* ((max-await (or max-await-time-ms
                          mongo-monitor-max-await-time-ms))
           (timeout (or timeout
                        (+ 1 (/ (float max-await) 1000.0))))
           (awaited (and (mongo--monitor-awaitable-p conn) t))
           (heartbeat-start (float-time)))
      (apply #'mongo--emit-sdam-event
             'server-heartbeat-started
             (mongo--sdam-heartbeat-event-fields conn awaited))
      (condition-case err
          (let ((hello (let ((mongo--suppress-command-events t))
                         (if (eq (mongo-conn-server-monitoring-mode conn) 'poll)
                             (mongo-hello conn timeout)
                           (mongo-awaitable-hello conn max-await timeout)))))
            (setf (mongo-conn-monitor-error conn) nil)
            (apply #'mongo--emit-sdam-event
                   'server-heartbeat-succeeded
                   (append
                    (mongo--sdam-heartbeat-event-fields conn awaited)
                    (list (cons 'duration-ms
                                (mongo--pool-duration-ms heartbeat-start))
                          (cons 'reply hello))))
            hello)
        (error
         (setf (mongo-conn-monitor-error conn) err)
         (mongo--mark-current-server-unknown conn err)
         (apply #'mongo--emit-sdam-event
                'server-heartbeat-failed
                (append
                 (mongo--sdam-heartbeat-event-fields conn awaited)
                 (list (cons 'duration-ms
                             (mongo--pool-duration-ms heartbeat-start))
                       (cons 'failure err))))
         (signal (car err) (cdr err)))))))

(defun mongo--monitor-tick (conn max-await-time-ms timeout)
  "Run one scheduled monitor tick for CONN."
  (if (not (mongo-live-p conn))
      (mongo-stop-monitor conn)
    (ignore-errors
      (mongo-monitor-once conn max-await-time-ms timeout))))

(defun mongo-stop-monitor (conn)
  "Stop CONN's MongoDB monitor timer."
  (when-let* ((timer (mongo-conn-monitor-timer conn)))
    (ignore-errors
      (cancel-timer timer))
    (setf (mongo-conn-monitor-timer conn) nil))
  conn)

(defun mongo-start-monitor
    (conn &optional heartbeat-seconds max-await-time-ms timeout)
  "Start an explicit MongoDB monitor timer for CONN.
The monitor is not started automatically by `mongo-connect'; callers opt in
when background topology refresh is appropriate for their UI/runtime."
  (mongo-stop-monitor conn)
  (unless (mongo-conn-load-balanced conn)
    (let* ((heartbeat (or heartbeat-seconds
                          (mongo-conn-heartbeat-frequency conn)
                          mongo-monitor-heartbeat-seconds))
           (max-await (or max-await-time-ms
                          (and (mongo-conn-heartbeat-frequency conn)
                               (round (* 1000 heartbeat)))
                          mongo-monitor-max-await-time-ms))
           (timeout (or timeout
                        (+ 1 (/ (float max-await) 1000.0)))))
      (setf (mongo-conn-monitor-timer conn)
            (run-at-time 0 heartbeat
                         #'mongo--monitor-tick
                         conn max-await timeout))))
  conn)

(defun mongo--hello-primary-p (hello)
  "Return non-nil when HELLO identifies a writable primary."
  (or (mongo--wire-truthy-p
       (cdr (assoc "isWritablePrimary" hello)))
      (mongo--wire-truthy-p
       (cdr (assoc "ismaster" hello)))))

(defun mongo--hello-hidden-p (hello)
  "Return non-nil when HELLO identifies a hidden replica-set member."
  (mongo--wire-truthy-p (cdr (assoc "hidden" hello))))

(defun mongo--hello-secondary-p (hello)
  "Return non-nil when HELLO identifies a selectable secondary."
  (and (mongo--wire-truthy-p (cdr (assoc "secondary" hello)))
       (not (mongo--hello-hidden-p hello))))

(defun mongo--hello-mongos-p (hello)
  "Return non-nil when HELLO identifies a mongos router."
  (equal (cdr (assoc "msg" hello)) "isdbgrid"))

(defun mongo--hello-replica-set-name (hello)
  "Return the replica set name from HELLO, or nil."
  (cdr (assoc "setName" hello)))

(defun mongo--hello-announced-hosts (hello)
  "Return replica-set member host strings announced by HELLO."
  (let ((primary (cdr (assoc "primary" hello))))
    (delete-dups
     (delq nil
           (append (and (stringp primary) (list primary))
                   (cdr (assoc "hosts" hello))
                   (cdr (assoc "passives" hello))
                   (cdr (assoc "arbiters" hello)))))))

(defun mongo--endpoint-key (host port)
  "Return a stable key for HOST and PORT."
  (if (mongo--local-socket-endpoint-p host port)
      (format "local:%s" host)
    (format "%s:%s" (downcase host) port)))

(defun mongo--endpoint-entry-key (endpoint)
  "Return the address key for ENDPOINT."
  (mongo--endpoint-key (nth 0 endpoint) (nth 1 endpoint)))

(defun mongo--endpoints-append-unique
    (endpoints additions &optional excluded-keys)
  "Return ENDPOINTS with ADDITIONS appended by address.
Endpoints whose keys already appear in ENDPOINTS or EXCLUDED-KEYS are skipped."
  (let ((keys (append excluded-keys
                      (mapcar #'mongo--endpoint-entry-key endpoints)))
        (result endpoints))
    (dolist (endpoint additions)
      (let ((key (mongo--endpoint-entry-key endpoint)))
        (unless (member key keys)
          (push key keys)
          (setq result (append result (list endpoint))))))
    result))

(defun mongo--hello-announced-endpoints (hello database)
  "Return ENDPOINT entries announced by HELLO for DATABASE."
  (mapcar
   (lambda (hostspec)
     (pcase-let ((`(,host ,port) (mongo--host-port hostspec)))
       (list host port database)))
   (mongo--hello-announced-hosts hello)))

(defun mongo--normalize-hostspec (hostspec)
  "Return HOSTSPEC normalized as a MongoDB address key."
  (pcase-let ((`(,host ,port) (mongo--host-port hostspec 27017)))
    (mongo--endpoint-key host port)))

(defun mongo--hello-member-hosts (hello)
  "Return all replica-set member host strings announced by HELLO."
  (let ((primary (cdr (assoc "primary" hello))))
    (delete-dups
     (delq nil
           (append (and (stringp primary) (list primary))
                   (cdr (assoc "hosts" hello))
                   (cdr (assoc "passives" hello))
                   (cdr (assoc "arbiters" hello)))))))

(defun mongo--hello-server-type (hello &optional load-balanced)
  "Return an SDAM-style server type symbol for HELLO."
  (cond
   (load-balanced 'load-balanced)
   ((not (mongo--ok-p hello)) 'unknown)
   ((mongo--hello-mongos-p hello) 'mongos)
   ((mongo--hello-replica-set-name hello)
    (cond
     ((mongo--hello-hidden-p hello) 'rs-other)
     ((mongo--hello-primary-p hello) 'rs-primary)
     ((mongo--hello-secondary-p hello) 'rs-secondary)
     ((mongo--wire-truthy-p (cdr (assoc "arbiterOnly" hello))) 'rs-arbiter)
     (t 'rs-other)))
   ((mongo--wire-truthy-p (cdr (assoc "isreplicaset" hello)))
    'rs-ghost)
   (t 'standalone)))

(defun mongo--unknown-server-description
    (address &optional error topology-version)
  "Return an Unknown server description for ADDRESS."
  (make-mongo-server-description
   :address address
   :type 'unknown
   :topology-version topology-version
   :last-update-time (float-time)
   :error error))

(defun mongo--average-round-trip-time (previous measurement)
  "Return MongoDB average RTT from PREVIOUS and MEASUREMENT.
MEASUREMENT is the latest hello round trip time in seconds."
  (cond
   ((not measurement) previous)
   ((not previous) measurement)
   (t
    (+ (* mongo--round-trip-time-alpha measurement)
       (* (- 1 mongo--round-trip-time-alpha) previous)))))

(defun mongo--server-description-from-hello
    (address hello &optional load-balanced round-trip-time)
  "Return a server description for ADDRESS from HELLO."
  (make-mongo-server-description
   :address address
   :type (mongo--hello-server-type hello load-balanced)
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
   :last-write-date (mongo--hello-last-write-date hello)
   :last-update-time (float-time)
   :round-trip-time round-trip-time))

(defun mongo--topology-version-process-id (topology-version)
  "Return TOPOLOGY-VERSION's processId as a comparable value."
  (when-let* ((value (cdr (assoc "processId"
                                 (mongo--document-pairs topology-version)))))
    (cond
     ((mongo-object-id-p value)
      (mongo-object-id-hex value))
     ((and (mongo--document-value-p value)
           (assoc "$oid" (mongo--document-pairs value)))
      (cdr (assoc "$oid" (mongo--document-pairs value))))
     ((and (consp value)
           (assoc "$oid" value))
      (cdr (assoc "$oid" value)))
     (t value))))

(defun mongo--topology-version-counter (topology-version)
  "Return TOPOLOGY-VERSION's counter as a comparable integer."
  (let ((value (cdr (assoc "counter"
                           (mongo--document-pairs topology-version)))))
    (cond
     ((mongo-int64-p value)
      (mongo-int64-value value))
     ((mongo-int32-p value)
      (mongo-int32-value value))
     (t value))))

(defun mongo--topology-version-newer-or-equal-p (new current)
  "Return non-nil when NEW topologyVersion may replace CURRENT.
This follows SDAM freshness rules: missing values, missing current values, or
different processId values are treated as fresh; matching processId values
compare by counter."
  (cond
   ((not new) t)
   ((not current) t)
   ((not (equal (mongo--topology-version-process-id new)
                (mongo--topology-version-process-id current)))
    t)
   (t
    (let ((new-counter (mongo--topology-version-counter new))
          (current-counter (mongo--topology-version-counter current)))
      (or (not (integerp new-counter))
          (not (integerp current-counter))
          (>= new-counter current-counter))))))

(defun mongo--topology-version-newer-p (new current)
  "Return non-nil when NEW topologyVersion is fresh for app error handling.
Application state-change errors only replace a server description when the
error's topologyVersion is newer than the current description.  Missing
topologyVersion values are treated as fresh for older servers."
  (cond
   ((not new) t)
   ((not current) t)
   ((not (equal (mongo--topology-version-process-id new)
                (mongo--topology-version-process-id current)))
    t)
   (t
    (let ((new-counter (mongo--topology-version-counter new))
          (current-counter (mongo--topology-version-counter current)))
      (or (not (integerp new-counter))
          (not (integerp current-counter))
          (> new-counter current-counter))))))

(defun mongo--topology-version-from-response (response)
  "Return RESPONSE topologyVersion, or nil."
  (cdr (assoc "topologyVersion" response)))

(defun mongo--object-id-hex-value (value)
  "Return VALUE as a lower-case ObjectId hex string, or nil."
  (cond
   ((mongo-object-id-p value)
    (downcase (mongo-object-id-hex value)))
   ((and (mongo--document-value-p value)
         (assoc "$oid" (mongo--document-pairs value)))
    (downcase (cdr (assoc "$oid" (mongo--document-pairs value)))))
   ((and (consp value)
         (assoc "$oid" value))
    (downcase (cdr (assoc "$oid" value))))
   ((stringp value)
    (downcase value))
   (t nil)))

(defun mongo--server-election-id-value (server)
  "Return SERVER's electionId as a comparable ObjectId hex string."
  (mongo--object-id-hex-value
   (and server
        (mongo-server-description-election-id server))))

(defun mongo--server-set-version-value (server)
  "Return SERVER's setVersion as an integer, or nil."
  (let ((value (and server
                    (mongo-server-description-set-version server))))
    (cond
     ((integerp value) value)
     ((mongo-int32-p value) (mongo-int32-value value))
     ((mongo-int64-p value) (mongo-int64-value value))
     (t nil))))

(defun mongo--compare-election-ids (a b)
  "Compare ObjectId hex strings A and B bytewise.
Return -1, 0, or 1."
  (cond
   ((equal a b) 0)
   ((string< a b) -1)
   (t 1)))

(defun mongo--compare-set-versions (a b)
  "Compare setVersion integers A and B.
Return -1, 0, or 1."
  (cond
   ((= a b) 0)
   ((< a b) -1)
   (t 1)))

(defun mongo--primary-version-compare
    (election-a set-a election-b set-b max-wire-version)
  "Compare primary version tuple A with B for MAX-WIRE-VERSION.
Return -1, 0, or 1, or nil when either tuple is incomplete.  MongoDB 6.0+
uses electionId before setVersion; older wire versions keep the historical
driver ordering for compatibility."
  (when (and election-a set-a election-b set-b)
    (let* ((modern (>= (or max-wire-version 0) 17))
           (first (if modern
                      (mongo--compare-election-ids election-a election-b)
                    (mongo--compare-set-versions set-a set-b))))
      (if (/= first 0)
          first
        (if modern
            (mongo--compare-set-versions set-a set-b)
          (mongo--compare-election-ids election-a election-b))))))

(defun mongo--topology-stale-primary-p (server topology)
  "Return non-nil when SERVER is an older primary than TOPOLOGY has seen."
  (and topology
       (eq (mongo-server-description-type server) 'rs-primary)
       (let ((comparison
              (mongo--primary-version-compare
               (mongo--server-election-id-value server)
               (mongo--server-set-version-value server)
               (mongo-topology-description-max-election-id topology)
               (mongo-topology-description-max-set-version topology)
               (mongo-server-description-max-wire-version server))))
         (and comparison
              (< comparison 0)))))

(defun mongo--stale-primary-server-description (address server)
  "Return an Unknown description for stale primary SERVER at ADDRESS."
  (mongo--unknown-server-description
   address
   (format "Stale primary detected: electionId=%s setVersion=%s"
           (or (mongo--server-election-id-value server) "unknown")
           (or (mongo--server-set-version-value server) "unknown"))))

(defun mongo--topology-primary-version-values (server topology)
  "Return (ELECTION-ID . SET-VERSION) after considering primary SERVER."
  (let ((max-election
         (and topology
              (mongo-topology-description-max-election-id topology)))
        (max-set
         (and topology
              (mongo-topology-description-max-set-version topology))))
    (if (eq (mongo-server-description-type server) 'rs-primary)
        (let* ((election (mongo--server-election-id-value server))
               (set-version (mongo--server-set-version-value server))
               (comparison
                (mongo--primary-version-compare
                 election set-version
                 max-election max-set
                 (mongo-server-description-max-wire-version server))))
          (cond
           ((not (and election set-version))
            (cons max-election max-set))
           ((or (not comparison)
                (>= comparison 0))
            (cons election set-version))
           (t
            (cons max-election max-set))))
      (cons max-election max-set))))

(defun mongo--topology-member-addresses (hello)
  "Return normalized hosts/passives/arbiters addresses from HELLO."
  (delete-dups
   (mapcar #'mongo--normalize-hostspec
           (mongo--hello-member-hosts hello))))

(defun mongo--topology-add-unknown-servers (servers addresses)
  "Return SERVERS with Unknown descriptions for missing ADDRESSES."
  (let ((result (copy-sequence servers)))
    (dolist (address addresses)
      (unless (assoc address result)
        (setq result
              (append result
                      (list
                       (cons address
                             (mongo--unknown-server-description address)))))))
    result))

(defun mongo--topology-prune-to-addresses
    (servers addresses &optional keep-address)
  "Return SERVERS whose addresses are in ADDRESSES or KEEP-ADDRESS."
  (seq-filter
   (lambda (entry)
     (or (member (car entry) addresses)
         (and keep-address
              (equal (car entry) keep-address))))
   servers))

(defun mongo--topology-remove-server (servers address)
  "Return SERVERS without the server at ADDRESS."
  (seq-remove (lambda (entry)
                (equal (car entry) address))
              servers))

(defun mongo--topology-primary-address-from-servers (servers)
  "Return the address of the known RSPrimary in SERVERS, or nil."
  (catch 'primary
    (dolist (entry servers)
      (when (eq (mongo-server-description-type (cdr entry)) 'rs-primary)
        (throw 'primary (car entry))))
    nil))

(defun mongo--stale-primary-discovery-description
    (old-address new-primary-address)
  "Return an Unknown description for OLD-ADDRESS after NEW-PRIMARY-ADDRESS."
  (mongo--unknown-server-description
   old-address
   (format "primary marked stale due to discovery of newer primary %s"
           new-primary-address)))

(defun mongo--topology-mark-other-primaries-unknown
    (servers primary-address)
  "Return SERVERS with all primaries except PRIMARY-ADDRESS marked Unknown."
  (mapcar
   (lambda (entry)
     (let ((address (car entry))
           (server (cdr entry)))
       (if (and (not (equal address primary-address))
                (eq (mongo-server-description-type server) 'rs-primary))
           (cons address
                 (mongo--stale-primary-discovery-description
                  address primary-address))
         entry)))
   servers))

(defun mongo--topology-servers-after-hello
    (address server hello old-servers)
  "Return updated server map after processing SERVER at ADDRESS.
Primary hello responses add current replica-set members and prune removed
members.  Non-primary replica-set responses add discovered members but leave
existing members in place until a primary becomes authoritative."
  (let* ((server-type (mongo-server-description-type server))
         (member-addresses (mongo--topology-member-addresses hello))
         (servers (mongo--replace-server-description
                   old-servers address server)))
    (pcase server-type
      ('rs-primary
       (setq servers
             (mongo--topology-add-unknown-servers
              servers member-addresses))
       (setq servers
             (if member-addresses
                 (mongo--topology-prune-to-addresses
                  servers member-addresses address)
               servers))
       (mongo--topology-mark-other-primaries-unknown
        servers address))
      ((or 'rs-secondary 'rs-arbiter 'rs-other)
       (mongo--topology-add-unknown-servers
        servers member-addresses))
      (_ servers))))

(defun mongo--topology-has-replica-set-server-p (servers)
  "Return non-nil when SERVERS contains any replica-set server description."
  (seq-some
   (lambda (entry)
     (memq (mongo-server-description-type (cdr entry))
           '(rs-primary rs-secondary rs-arbiter rs-other)))
   servers))

(defun mongo--replica-set-topology-type-p (type)
  "Return non-nil when TYPE is a replica-set topology type."
  (memq type '(replica-set-with-primary replica-set-no-primary)))

(defun mongo--replica-set-server-type-p (server)
  "Return non-nil when SERVER is a named replica-set member."
  (memq (mongo-server-description-type server)
        '(rs-primary rs-secondary rs-arbiter rs-other)))

(defun mongo--replica-set-non-primary-server-type-p (server)
  "Return non-nil when SERVER is a non-primary replica-set member."
  (memq (mongo-server-description-type server)
        '(rs-secondary rs-arbiter rs-other)))

(defun mongo--topology-expected-set-name (conn old-topology)
  "Return expected replica-set name from CONN params or OLD-TOPOLOGY."
  (or (and old-topology
           (mongo-topology-description-set-name old-topology))
      (and (mongo-conn-p conn)
           (mongo-conn-params conn)
           (mongo--params-replica-set-name
            (mongo-conn-params conn)))))

(defun mongo--replica-set-set-name-mismatch-p
    (conn old-topology server)
  "Return non-nil when SERVER has the wrong replica-set name."
  (and (not (mongo--conn-direct-connection-p conn))
       (not (mongo-conn-load-balanced conn))
       (mongo--replica-set-server-type-p server)
       (when-let* ((expected
                    (mongo--topology-expected-set-name conn old-topology)))
         (not (equal expected
                     (mongo-server-description-set-name server))))))

(defun mongo--server-me-mismatch-p (address server)
  "Return non-nil when SERVER's `me' field disagrees with ADDRESS."
  (when-let* ((me (mongo-server-description-me server)))
    (condition-case nil
        (not (equal (mongo--normalize-hostspec me) address))
      (error nil))))

(defun mongo--replica-set-me-mismatch-p (conn old-topology address server)
  "Return non-nil when SERVER should be removed for a `me' mismatch."
  (and old-topology
       (not (mongo--conn-direct-connection-p conn))
       (not (mongo-conn-load-balanced conn))
       (mongo--replica-set-non-primary-server-type-p server)
       (mongo--server-me-mismatch-p address server)))

(defun mongo--topology-type-after-hello
    (conn server servers &optional old-topology)
  "Return topology type after processing SERVER and SERVERS for CONN."
  (cond
   ((mongo--conn-direct-connection-p conn)
    'single)
   ((mongo-conn-load-balanced conn)
    'load-balanced)
   ((eq (mongo-server-description-type server) 'mongos)
    'sharded)
   ((eq (mongo-server-description-type server) 'standalone)
    'single)
   ((eq (mongo-server-description-type server) 'rs-ghost)
    (cond
     ((mongo--topology-primary-address-from-servers servers)
      'replica-set-with-primary)
     ((and old-topology
           (mongo--replica-set-topology-type-p
            (mongo-topology-description-type old-topology)))
      'replica-set-no-primary)
     (t 'unknown)))
   ((memq (mongo-server-description-type server)
          '(rs-primary rs-secondary rs-arbiter rs-other))
    (if (mongo--topology-primary-address-from-servers servers)
        'replica-set-with-primary
      'replica-set-no-primary))
   ((mongo--topology-primary-address-from-servers servers)
    'replica-set-with-primary)
   ((or (mongo--topology-has-replica-set-server-p servers)
        (and old-topology
             (mongo--replica-set-topology-type-p
              (mongo-topology-description-type old-topology))))
    'replica-set-no-primary)
   (t 'unknown)))

(defun mongo--wire-version-number (value default)
  "Return VALUE as an integer wire version, or DEFAULT."
  (cond
   ((integerp value) value)
   ((mongo-int32-p value) (mongo-int32-value value))
   ((mongo-int64-p value) (mongo-int64-value value))
   (t default)))

(defun mongo--server-wire-compatibility-error (address server)
  "Return SERVER wire compatibility error at ADDRESS, or nil."
  (unless (eq (mongo-server-description-type server) 'unknown)
    (let ((min-wire
           (mongo--wire-version-number
            (mongo-server-description-min-wire-version server)
            0))
          (max-wire
           (mongo--wire-version-number
            (mongo-server-description-max-wire-version server)
            0)))
      (cond
       ((> min-wire mongo--client-max-wire-version)
        (format
         "Server at %s requires wire version %s, but mongo.el only supports up to %s"
         address min-wire mongo--client-max-wire-version))
       ((< max-wire mongo--client-min-wire-version)
        (format
         "Server at %s reports wire version %s, but mongo.el requires at least %s (%s)"
         address
         max-wire
         mongo--client-min-wire-version
         mongo--client-min-wire-version-release))))))

(defun mongo--server-wire-compatible-p (address server)
  "Return non-nil when SERVER at ADDRESS is compatible with this client."
  (not (mongo--server-wire-compatibility-error address server)))

(defun mongo--topology-compatible-p (servers)
  "Return non-nil when all non-Unknown SERVERS are wire-compatible."
  (seq-every-p
   (lambda (entry)
     (mongo--server-wire-compatible-p (car entry) (cdr entry)))
   servers))

(defun mongo--topology-compatibility-error (servers)
  "Return compatibility error for SERVERS, or nil."
  (catch 'error
    (dolist (entry servers)
      (when-let* ((error (mongo--server-wire-compatibility-error
                          (car entry)
                          (cdr entry))))
        (throw 'error error)))
    nil))

(defun mongo--ensure-topology-compatible (topology)
  "Signal when TOPOLOGY contains an incompatible server description."
  (when topology
    (let ((error
           (or (mongo-topology-description-compatibility-error topology)
               (mongo--topology-compatibility-error
                (mongo-topology-description-servers topology)))))
      (if error
          (progn
            (setf (mongo-topology-description-compatible topology) nil)
            (setf (mongo-topology-description-compatibility-error topology)
                  error)
            (signal 'mongo-error (list error)))
        (setf (mongo-topology-description-compatible topology) t)
        (setf (mongo-topology-description-compatibility-error topology) nil))))
  topology)

(defun mongo--topology-type-from-server (server)
  "Return a topology type symbol implied by SERVER."
  (pcase (mongo-server-description-type server)
    ('load-balanced 'load-balanced)
    ('mongos 'sharded)
    ('rs-primary 'replica-set-with-primary)
    ((or 'rs-secondary 'rs-arbiter 'rs-other)
     'replica-set-no-primary)
    ('rs-ghost 'unknown)
    ('standalone 'single)
    (_ 'unknown)))

(defun mongo--conn-direct-connection-p (conn)
  "Return non-nil when CONN was opened as directConnection=true."
  (and (mongo-conn-p conn)
       (ignore-errors
         (mongo--params-direct-connection-p
          (mongo-conn-params conn)))))

(defun mongo--single-set-name-mismatch-error (conn server)
  "Return a Single-topology setName mismatch message for SERVER, or nil."
  (when (and (mongo--conn-direct-connection-p conn)
             (not (eq (mongo-server-description-type server) 'unknown)))
    (when-let* ((expected
                 (mongo--params-replica-set-name
                  (mongo-conn-params conn))))
      (let ((actual (mongo-server-description-set-name server)))
        (cond
         ((not actual)
          (format "MongoDB direct connection did not report replica set %s"
                  expected))
         ((not (equal expected actual))
          (format "MongoDB direct connection belongs to replica set %s, not %s"
                  actual expected)))))))

(defun mongo--verify-single-set-name (conn address server)
  "Return SERVER or an Unknown description for Single setName mismatch."
  (if-let* ((error (mongo--single-set-name-mismatch-error conn server)))
      (mongo--unknown-server-description address error)
    server))

(defun mongo--topology-description-from-hello
    (conn hello &optional round-trip-time)
  "Return a topology description for CONN from HELLO."
  (let* ((address (mongo--endpoint-key
                   (mongo-conn-host conn)
                   (mongo-conn-port conn)))
         (old-topology (mongo-conn-topology conn))
         (old-server (and old-topology
                          (cdr (assoc address
                                      (mongo-topology-description-servers
                                       old-topology)))))
         (average-round-trip-time
          (mongo--average-round-trip-time
           (and old-server
                (mongo-server-description-round-trip-time old-server))
           round-trip-time))
         (server (mongo--server-description-from-hello
                  address hello (mongo-conn-load-balanced conn)
                  average-round-trip-time))
         (old-topology-version
          (and old-server
               (mongo-server-description-topology-version old-server))))
    (if (and old-topology
             old-server
             (not (mongo--topology-version-newer-or-equal-p
                   (mongo-server-description-topology-version server)
                   old-topology-version)))
        old-topology
      (when (mongo--topology-stale-primary-p server old-topology)
        (setq server
              (mongo--stale-primary-server-description
               address server)))
      (setq server
            (mongo--verify-single-set-name conn address server))
      (let* ((old-servers
              (and old-topology
                   (mongo-topology-description-servers old-topology)))
             (expected-set-name
              (mongo--topology-expected-set-name conn old-topology))
             (set-name-mismatch
              (mongo--replica-set-set-name-mismatch-p
               conn old-topology server))
             (me-mismatch
              (mongo--replica-set-me-mismatch-p
               conn old-topology address server))
             (servers
              (cond
               ((or set-name-mismatch me-mismatch)
                (mongo--topology-remove-server old-servers address))
               ((or (mongo--conn-direct-connection-p conn)
                    (mongo-conn-load-balanced conn)
                    (eq (mongo-server-description-type server)
                        'standalone))
                (list (cons address server)))
               (t
                (mongo--topology-servers-after-hello
                 address server hello old-servers))))
             (topology-type
              (mongo--topology-type-after-hello
               conn server servers old-topology))
             (primary-address
              (mongo--topology-primary-address-from-servers servers))
             (primary-version
              (mongo--topology-primary-version-values
               server old-topology))
             (compatible
              (mongo--topology-compatible-p servers)))
        (make-mongo-topology-description
         :type topology-type
         :set-name (or expected-set-name
                       (mongo-server-description-set-name server)
                       (and old-topology
                            (mongo-topology-description-set-name
                             old-topology)))
         :servers servers
         :primary-address primary-address
         :max-election-id (car primary-version)
         :max-set-version (cdr primary-version)
         :logical-session-timeout-minutes
         (or (mongo-server-description-logical-session-timeout-minutes server)
             (and old-topology
                  (mongo-topology-description-logical-session-timeout-minutes
                   old-topology)))
         :compatible compatible
         :compatibility-error
         (unless compatible
           (mongo--topology-compatibility-error servers)))))))

(defun mongo--replica-set-hello-ok-p (expected-set hello)
  "Return non-nil when HELLO belongs to EXPECTED-SET, or no set was requested."
  (let ((actual-set (mongo--hello-replica-set-name hello)))
    (or (not expected-set)
        (equal expected-set actual-set))))

(defun mongo--replica-set-error-message (expected-set hello)
  "Return a replica-set mismatch message for EXPECTED-SET and HELLO."
  (let ((actual-set (mongo--hello-replica-set-name hello)))
    (cond
     ((and expected-set actual-set)
      (format "MongoDB seed belongs to replica set %s, not %s"
              actual-set expected-set))
     (expected-set
      (format "MongoDB seed did not report replica set %s"
              expected-set))
     (t
      "MongoDB seed did not report a writable primary"))))

(defun mongo--replica-set-canonical-address-ok-p (host port hello)
  "Return non-nil when HELLO's canonical `me' matches HOST and PORT.
Replica-set discovery must not select a seed alias that the server reports as
a different canonical address; directConnection bypasses this discovery path."
  (let ((me (cdr (assoc "me" hello))))
    (or (not me)
        (condition-case nil
            (equal (mongo--normalize-hostspec me)
                   (mongo--endpoint-key host port))
          (error nil)))))

(defun mongo--replica-set-canonical-error-message (host port hello)
  "Return an error message for HELLO `me' mismatch at HOST and PORT."
  (format "MongoDB seed %s is known as canonical replica-set member %s"
          (mongo--endpoint-key host port)
          (cdr (assoc "me" hello))))

(defun mongo--hello-announces-me-p (hello)
  "Return non-nil when HELLO's canonical `me' appears in announced hosts."
  (when-let* ((me (cdr (assoc "me" hello))))
    (member (mongo--normalize-hostspec me)
            (mapcar #'mongo--normalize-hostspec
                    (mongo--hello-announced-hosts hello)))))

(defun mongo--canonical-alias-fallback-candidate-p
    (mode constraints-ok hello)
  "Return non-nil when a `me' mismatch seed may remain a fallback.
The fallback is only used if canonical hosts cannot be selected, preserving
local port-forwarded development deployments without preferring aliases."
  (and (mongo--hello-announces-me-p hello)
       (cond
        ((mongo--hello-primary-p hello)
         (or (member mode '("primary" "primaryPreferred"
                            "secondaryPreferred"))
             (and (equal mode "nearest")
                  constraints-ok)))
        ((mongo--hello-secondary-p hello)
         (and constraints-ok
              (member mode '("secondary" "secondaryPreferred"
                             "primaryPreferred" "nearest")))))))

(defun mongo--replica-read-preference-mode (params)
  "Return read preference mode for replica-set connection PARAMS."
  (mongo--read-preference-mode
   (mongo--params-read-preference params)))

(defun mongo--queue-announced-replica-hosts (hello seen queue database)
  "Return QUEUE with unvisited replica-set hosts announced by HELLO appended."
  (mongo--endpoints-append-unique
   queue
   (mongo--hello-announced-endpoints hello database)
   seen))

(defun mongo--hello-read-preference-constraints-p
    (params host port hello read-preference)
  "Return non-nil when HELLO matches READ-PREFERENCE constraints."
  (let* ((probe (make-mongo-conn
                 :host host
                 :port port
                 :load-balanced (mongo--params-load-balanced-p params)))
         (topology (mongo--topology-description-from-hello probe hello))
         (address (mongo--endpoint-key host port))
         (server (cdr (assoc address
                             (mongo-topology-description-servers topology)))))
    (and server
         (mongo--server-matches-read-preference-constraints-p
          server
          read-preference
          topology
          (or (mongo--params-heartbeat-frequency params)
              mongo-monitor-heartbeat-seconds)))))

(defun mongo--endpoint-result-server-description (conn host port hello)
  "Return the server description for an endpoint RESULT."
  (let* ((address (mongo--endpoint-key host port))
         (topology (and (mongo-conn-p conn)
                        (mongo-conn-topology conn)))
         (server (and topology
                      (cdr (assoc address
                                  (mongo-topology-description-servers
                                   topology))))))
    (or server
        (mongo--server-description-from-hello
         address hello
         (and (mongo-conn-p conn)
              (mongo-conn-load-balanced conn))))))

(defun mongo--endpoint-result-candidate (conn host port hello)
  "Return a connected server candidate from CONN, HOST, PORT, and HELLO."
  (make-mongo--server-candidate
   :conn conn
   :hello hello
   :server (mongo--endpoint-result-server-description
            conn host port hello)))

(defun mongo--candidate-round-trip-time (candidate)
  "Return CANDIDATE average RTT in seconds, or nil."
  (when-let* ((server (mongo--server-candidate-server candidate)))
    (mongo-server-description-round-trip-time server)))

(defun mongo--candidates-within-latency-window
    (candidates local-threshold)
  "Return CANDIDATES whose RTT is inside the local-threshold latency window."
  (let ((rtts (delq nil
                    (mapcar #'mongo--candidate-round-trip-time
                            candidates))))
    (if rtts
        (let ((upper (+ (apply #'min rtts) local-threshold)))
          (seq-filter
           (lambda (candidate)
             (when-let* ((rtt (mongo--candidate-round-trip-time candidate)))
               (<= rtt upper)))
           candidates))
      candidates)))

(defun mongo--select-candidate-within-latency-window
    (candidates local-threshold)
  "Select one candidate from CANDIDATES within the latency window."
  (when candidates
    (let* ((window (or (mongo--candidates-within-latency-window
                       candidates local-threshold)
                      candidates))
           (count (length window)))
      (nth (random count) window))))

(defun mongo--disconnect-candidates-except (candidates selected)
  "Disconnect all CANDIDATES except SELECTED."
  (dolist (candidate candidates)
    (unless (eq candidate selected)
      (ignore-errors
        (mongo-disconnect
         (mongo--server-candidate-conn candidate))))))

(defun mongo--finalize-selected-candidate (candidate credential)
  "Authenticate and initialize CANDIDATE, then return its connection."
  (let ((conn (mongo--server-candidate-conn candidate))
        (hello (mongo--server-candidate-hello candidate)))
    (when credential
      (mongo--authenticate conn credential hello)
      (mongo--mark-connection-authenticated conn))
    (mongo--initialize-session conn hello)
    conn))

(defun mongo--connect-replica-server (params endpoints credential)
  "Connect to a replica-set server selected from ENDPOINTS."
  (let* ((expected-set (mongo--params-replica-set-name params))
         (read-preference (mongo--params-read-preference params))
         (mode (mongo--read-preference-mode read-preference))
         (local-threshold (mongo--params-local-threshold params))
         (selection-timeout (mongo--params-server-selection-timeout params))
         (try-once (mongo--params-server-selection-try-once-p params))
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
                       (key (mongo--endpoint-key host port)))
            (unless (member key seen)
              (push key seen)
              (condition-case err
                  (let* ((remaining (and deadline
                                          (max 0.001
                                               (- deadline (float-time)))))
                         (connect-params
                          (if remaining
                              (mongo--params-with-connect-timeout-limit
                               params remaining)
                            params))
                         (result (mongo--connect-endpoint
                                  connect-params host port database credential nil))
                         (conn (car result))
                         (hello (cdr result))
                         (candidate
                          (mongo--endpoint-result-candidate
                           conn host port hello))
                         (constraints-ok
                          (mongo--hello-read-preference-constraints-p
                           params host port hello read-preference)))
                    (cond
                     ((and (mongo--hello-mongos-p hello)
                           (not expected-set))
                      (push candidate mongos-candidates))
                     ((not (mongo--replica-set-hello-ok-p expected-set hello))
                      (setq last-error
                            (mongo--replica-set-error-message
                             expected-set hello))
                      (mongo-disconnect conn))
                     ((not (mongo--replica-set-canonical-address-ok-p
                            host port hello))
                      (setq known-endpoints
                            (mongo--endpoints-append-unique
                             known-endpoints
                             (mongo--hello-announced-endpoints
                              hello database)))
                      (setq queue (mongo--queue-announced-replica-hosts
                                   hello seen queue database))
                      (let ((fallback
                             (mongo--canonical-alias-fallback-candidate-p
                              mode constraints-ok hello)))
                        (when fallback
                          (push candidate canonical-alias-fallback-candidates))
                        (unless fallback
                          (mongo-disconnect conn)))
                      (setq last-error
                            (mongo--replica-set-canonical-error-message
                             host port hello)))
                     ((mongo--hello-primary-p hello)
                      (setq known-endpoints
                            (mongo--endpoints-append-unique
                             known-endpoints
                             (mongo--hello-announced-endpoints
                              hello database)))
                      (setq queue (mongo--queue-announced-replica-hosts
                                   hello seen queue database))
                      (cond
                       ((member mode '("primary" "primaryPreferred"))
                        (setq primary-candidate candidate
                              selected candidate))
                       ((equal mode "secondaryPreferred")
                        (when fallback-primary
                          (mongo-disconnect
                           (mongo--server-candidate-conn fallback-primary)))
                        (setq fallback-primary candidate))
                       ((and (equal mode "nearest")
                             constraints-ok)
                        (push candidate nearest-candidates))
                       ((equal mode "nearest")
                        (setq last-error
                              "readPreference tags/maxStalenessSeconds did not match primary")
                        (mongo-disconnect conn))
                       (t
                        (setq last-error
                              "readPreference=secondary did not find a secondary yet")
                        (mongo-disconnect conn))))
                     ((mongo--hello-secondary-p hello)
                      (setq known-endpoints
                            (mongo--endpoints-append-unique
                             known-endpoints
                             (mongo--hello-announced-endpoints
                              hello database)))
                      (setq queue (mongo--queue-announced-replica-hosts
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
                        (mongo-disconnect conn))))
                     (t
                      (setq last-error
                            (mongo--replica-set-error-message
                             expected-set hello))
                      (setq known-endpoints
                            (mongo--endpoints-append-unique
                             known-endpoints
                             (mongo--hello-announced-endpoints
                              hello database)))
                      (setq queue (mongo--queue-announced-replica-hosts
                                  hello seen queue database))
                      (mongo-disconnect conn))))
                (error
                 (setq last-error (error-message-string err)))))))
        (unless selected
          (setq selected
                (cond
                 (mongos-candidates
                  (mongo--select-candidate-within-latency-window
                   mongos-candidates local-threshold))
                 ((equal mode "nearest")
                  (mongo--select-candidate-within-latency-window
                   nearest-candidates local-threshold))
                 ((member mode '("secondary" "primaryPreferred"))
                  (mongo--select-candidate-within-latency-window
                   secondary-candidates local-threshold))
                 ((equal mode "secondaryPreferred")
                  (or (mongo--select-candidate-within-latency-window
                       secondary-candidates local-threshold)
                      fallback-primary))
                 (canonical-alias-fallback-candidates
                  (mongo--select-candidate-within-latency-window
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
                (mongo--disconnect-candidates-except all-candidates selected)
                (setq done t))
            (mongo--disconnect-candidates-except all-candidates nil)
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
        (mongo--finalize-selected-candidate selected credential)
      (when (and deadline
                 (<= deadline (float-time)))
        (setq last-error
              "serverSelectionTimeoutMS expired before a matching server was selected"))
      (signal 'mongo-error
              (list (if last-error
                        (format "Native MongoDB replica-set discovery did not find a server matching readPreference=%s: %s"
                                mode
                                last-error)
                      (format "Native MongoDB replica-set discovery did not find a server matching readPreference=%s"
                              mode)))))))

(defun mongo--validate-load-balanced-params (params endpoints)
  "Validate load-balanced PARAMS and ENDPOINTS."
  (when (mongo--params-load-balanced-p params)
    (when (> (length endpoints) 1)
      (signal 'mongo-error
              (list "MongoDB loadBalanced=true requires exactly one host")))
    (when (mongo--params-replica-set-name params)
      (signal 'mongo-error
              (list "MongoDB loadBalanced=true cannot be combined with replicaSet")))
    (when (mongo--params-direct-connection-p params)
      (signal 'mongo-error
              (list "MongoDB loadBalanced=true cannot be combined with directConnection=true")))
    (when (mongo--params-srv-max-hosts params)
      (signal 'mongo-error
              (list "MongoDB loadBalanced=true cannot be combined with srvMaxHosts")))))

(defun mongo--validate-srv-max-hosts-params (params)
  "Validate SRV max-host constraints after effective URL options are known."
  (when (and (mongo--params-srv-max-hosts params)
             (mongo--params-replica-set-name params))
    (signal 'mongo-error
            (list "MongoDB srvMaxHosts cannot be combined with replicaSet"))))

(defun mongo-connect (params)
  "Open a MongoDB wire protocol connection using PARAMS."
  (let ((mongo--srv-resolution-cache nil))
    (mongo--reject-unsupported-params params)
    (let* ((selection-timeout (mongo--params-server-selection-timeout params))
           (connect-params (if selection-timeout
                               (mongo--params-with-connect-timeout-limit
                                params selection-timeout)
                             params))
           (credential (mongo--params-credential params))
           (endpoints (mongo--params-endpoints params)))
      (mongo--validate-load-balanced-params params endpoints)
      (mongo--validate-srv-max-hosts-params params)
      (when (and (mongo--params-direct-connection-p params)
                 (> (length endpoints) 1))
        (signal 'mongo-error
                (list "Native MongoDB directConnection=true requires exactly one host")))
      (if (mongo--params-replica-discovery-p params endpoints)
          (mongo--connect-replica-server params endpoints credential)
        (pcase-let ((`(,host ,port ,database) (car endpoints)))
          (car (mongo--connect-endpoint
                connect-params host port database credential t)))))))

(defun mongo-disconnect (conn)
  "Close MongoDB wire CONN."
  (when conn
    (mongo-stop-monitor conn)
    (when-let* ((session-id (mongo-conn-session-id conn)))
      (when (mongo-live-p conn)
        (when (mongo-in-transaction-p conn)
          (ignore-errors
            (mongo-abort-transaction conn)))
        (setf (mongo-conn-session-id conn) nil)
        (ignore-errors
          (mongo-command
           conn "admin"
           `(("endSessions" . ,(vector session-id)))))))
    (mongo--emit-sdam-closing-events conn)
    (setf (mongo-conn-closed conn) t)
    (when-let* ((proc (mongo-conn-process conn)))
      (when (process-live-p proc)
        (delete-process proc)))
    (when-let* ((buffer (mongo-conn-buffer conn)))
      (when (buffer-live-p buffer)
        (kill-buffer buffer)))))

(defun mongo-live-p (conn)
  "Return non-nil when CONN is open."
  (and conn
       (not (mongo-conn-closed conn))
       (process-live-p (mongo-conn-process conn))))

(defun mongo--pool-total-size (pool)
  "Return total available, in-use, and connecting count for POOL."
  (+ (length (mongo-pool-available pool))
     (length (mongo-pool-in-use pool))
     (or (mongo-pool-connecting pool) 0)))

(defun mongo--pool-address (pool)
  "Return a display address for MongoDB POOL events."
  (let ((params (mongo-pool-params pool)))
    (or (when-let* ((parts (mongo--params-url-parts params)))
          (plist-get parts :hosts))
        (format "%s:%s"
                (or (plist-get params :host) "127.0.0.1")
                (or (plist-get params :port) 27017)))))

(defun mongo--pool-emit-event (pool type &rest fields)
  "Emit MongoDB pool event TYPE for POOL with alist FIELDS."
  (let ((event `((type . ,type)
                 (address . ,(mongo--pool-address pool))
                 (pool . ,pool)
                 ,@fields)))
    (run-hook-with-args 'mongo-pool-event-hook event)
    event))

(defun mongo--pool-duration-ms (start)
  "Return milliseconds elapsed since START."
  (* 1000.0 (- (float-time) start)))

(defun mongo--pool-millis-option (seconds)
  "Return SECONDS as a MongoDB millisecond pool option value."
  (round (* seconds 1000)))

(defun mongo--pool-created-options (pool)
  "Return non-default CMAP pool-created options for POOL."
  (let (options)
    (unless (equal (mongo-pool-max-size pool)
                   mongo--default-max-pool-size)
      (push (cons 'max-pool-size
                  (or (mongo-pool-max-size pool) 0))
            options))
    (unless (equal (mongo-pool-min-size pool)
                   mongo--default-min-pool-size)
      (push (cons 'min-pool-size (mongo-pool-min-size pool)) options))
    (when-let* ((max-idle (mongo-pool-max-idle-time pool)))
      (push (cons 'max-idle-time-ms
                  (mongo--pool-millis-option max-idle))
            options))
    (when-let* ((wait-timeout (mongo-pool-wait-queue-timeout pool)))
      (unless (zerop wait-timeout)
        (push (cons 'wait-queue-timeout-ms
                    (mongo--pool-millis-option wait-timeout))
              options)))
    (unless (equal (mongo-pool-max-connecting pool)
                   mongo--default-max-connecting)
      (push (cons 'max-connecting (mongo-pool-max-connecting pool))
            options))
    (nreverse options)))

(defun mongo--pool-emit-checkout-failed
    (pool checkout-start reason &optional error)
  "Emit POOL checkout failure REASON using CHECKOUT-START."
  (let ((fields (list (cons 'reason reason)
                      (cons 'duration-ms
                            (mongo--pool-duration-ms checkout-start)))))
    (when error
      (setq fields (append fields (list (cons 'error error)))))
    (apply #'mongo--pool-emit-event
           pool 'connection-check-out-failed fields)))

(defun mongo--pool-emit-checked-out (pool checkout-start conn)
  "Emit POOL checked-out event for CONN using CHECKOUT-START."
  (mongo--pool-emit-event
   pool 'connection-checked-out
   (cons 'connection conn)
   (cons 'connection-id
         (mongo--pool-connection-id pool conn))
   (cons 'duration-ms
         (mongo--pool-duration-ms checkout-start))))

(defun mongo--pool-normalize-purpose (purpose)
  "Return POOL checkout PURPOSE normalized to a CMAP tracking symbol."
  (pcase purpose
    ((or 'cursor :cursor) 'cursor)
    ((or 'transaction :transaction) 'transaction)
    (_ 'other)))

(defun mongo--pool-set-connection-purpose (pool conn purpose)
  "Record CONN's checked-out PURPOSE in POOL."
  (setf (mongo-pool-conn-purposes pool)
        (cons (cons conn (mongo--pool-normalize-purpose purpose))
              (cl-remove conn
                         (mongo-pool-conn-purposes pool)
                         :key #'car
                         :test #'eq)))
  conn)

(defun mongo--pool-forget-connection-purpose (pool conn)
  "Forget CONN's checked-out purpose in POOL."
  (setf (mongo-pool-conn-purposes pool)
        (cl-remove conn
                   (mongo-pool-conn-purposes pool)
                   :key #'car
                   :test #'eq)))

(defun mongo--pool-connection-purpose (pool conn)
  "Return CONN's checked-out purpose in POOL."
  (or (cdr (cl-assoc conn
                     (mongo-pool-conn-purposes pool)
                     :test #'eq))
      'other))

(defun mongo--pool-purpose-count (pool purpose)
  "Return how many checked-out POOL connections have PURPOSE."
  (let ((purpose (mongo--pool-normalize-purpose purpose)))
    (cl-count purpose
              (mongo-pool-in-use pool)
              :key (lambda (conn)
                     (mongo--pool-connection-purpose pool conn)))))

(defun mongo--pool-checkout-timeout-message (pool)
  "Return the wait queue timeout message for POOL."
  (if (mongo--params-load-balanced-p (mongo-pool-params pool))
      (format
       "Timeout waiting for connection from the connection pool. maxPoolSize: %s, connections in use by cursors: %d, connections in use by transactions: %d, connections in use by other operations: %d"
       (or (mongo-pool-max-size pool) 0)
       (mongo--pool-purpose-count pool 'cursor)
       (mongo--pool-purpose-count pool 'transaction)
       (mongo--pool-purpose-count pool 'other))
    "Timed out waiting for a MongoDB pooled connection"))

(defun mongo--pool-checkout-succeed (pool checkout-start conn purpose)
  "Record CONN as checked out from POOL with PURPOSE and return CONN."
  (push conn (mongo-pool-in-use pool))
  (mongo--pool-set-connection-purpose pool conn purpose)
  (mongo--pool-maintain-min-size pool)
  (mongo--pool-emit-checked-out pool checkout-start conn)
  conn)

(defun mongo--pool-signal-cleared-checkout-error (pool checkout-start)
  "Signal a retryable checkout error because POOL is cleared or paused."
  (let ((err `(mongo-error
               "MongoDB connection pool was cleared before checkout completed"
               :error-labels (,mongo--retryable-error-label))))
    (mongo--pool-emit-checkout-failed
     pool checkout-start 'connection-error err)
    (mongo--signal-error-with-labels
     (cadr err) (mongo-error-labels err))))

(defun mongo--pool-checkout-signal-unavailable (pool checkout-start)
  "Signal when POOL cannot service checkout at CHECKOUT-START."
  (cond
   ((mongo-pool-closed pool)
    (mongo--pool-emit-checkout-failed pool checkout-start 'pool-closed)
    (signal 'mongo-error
            (list "MongoDB connection pool is closed")))
   ((mongo-pool-paused pool)
    (mongo--pool-signal-cleared-checkout-error pool checkout-start))))

(defun mongo--pool-next-connection-id (pool)
  "Reserve and return the next monotonically increasing POOL connection id."
  (let ((id (or (mongo-pool-next-connection-id pool) 1)))
    (setf (mongo-pool-next-connection-id pool) (1+ id))
    id))

(defun mongo--pool-record-connection-id (pool conn connection-id)
  "Record CONNECTION-ID for CONN in POOL."
  (setf (mongo-pool-conn-ids pool)
        (cons (cons conn connection-id)
              (cl-remove conn
                         (mongo-pool-conn-ids pool)
                         :key #'car
                         :test #'eq)))
  connection-id)

(defun mongo--pool-connection-id (pool conn)
  "Return POOL's id for CONN, or nil."
  (cdr (cl-assoc conn
                 (mongo-pool-conn-ids pool)
                 :test #'eq)))

(defun mongo--pool-forget-connection-id (pool conn)
  "Forget POOL's id for CONN."
  (setf (mongo-pool-conn-ids pool)
        (cl-remove conn
                   (mongo-pool-conn-ids pool)
                   :key #'car
                   :test #'eq)))

(defun mongo--pool-close-connection (pool conn reason &optional connection-id)
  "Close CONN from POOL and emit a connection closed event with REASON."
  (let ((connection-id (or connection-id
                           (mongo--pool-connection-id pool conn))))
    (when conn
      (mongo--pool-untrack-connection pool conn))
    (when connection-id
      (mongo--pool-emit-event
       pool 'connection-closed
       (cons 'connection conn)
       (cons 'connection-id connection-id)
       (cons 'reason reason)))
    (when conn
      (mongo--pool-forget-connection-id pool conn)
      (unless (and (mongo-conn-p conn)
                   (mongo-conn-closed conn))
        (ignore-errors
          (mongo-disconnect conn))
        (when (mongo-conn-p conn)
          (setf (mongo-conn-closed conn) t))))))

(defun mongo--pool-at-capacity-p (pool)
  "Return non-nil when POOL cannot open another connection."
  (let ((max-size (mongo-pool-max-size pool)))
    (and max-size
         (>= (mongo--pool-total-size pool) max-size))))

(defun mongo--pool-connecting-at-capacity-p (pool)
  "Return non-nil when POOL has reached maxConnecting."
  (>= (or (mongo-pool-connecting pool) 0)
      (or (mongo-pool-max-connecting pool)
          mongo--default-max-connecting)))

(defun mongo--pool-generation (pool)
  "Return POOL's current CMAP generation."
  (or (mongo-pool-generation pool) 0))

(defun mongo--pool-service-generation (pool service-id)
  "Return POOL's current CMAP generation for SERVICE-ID."
  (if service-id
      (or (cdr (assoc service-id
                      (mongo-pool-service-generations pool)))
          0)
    0))

(defun mongo--pool-set-service-generation (pool service-id generation)
  "Set POOL's SERVICE-ID generation to GENERATION."
  (setf (mongo-pool-service-generations pool)
        (cons (cons service-id generation)
              (cl-remove service-id
                         (mongo-pool-service-generations pool)
                         :key #'car
                         :test #'equal)))
  generation)

(defun mongo--pool-service-count (pool service-id)
  "Return POOL's connection count for SERVICE-ID."
  (if service-id
      (or (cdr (assoc service-id
                      (mongo-pool-service-counts pool)))
          0)
    0))

(defun mongo--pool-remove-service-id (pool service-id)
  "Remove SERVICE-ID accounting entries from POOL."
  (setf (mongo-pool-service-counts pool)
        (cl-remove service-id
                   (mongo-pool-service-counts pool)
                   :key #'car
                   :test #'equal))
  (setf (mongo-pool-service-generations pool)
        (cl-remove service-id
                   (mongo-pool-service-generations pool)
                   :key #'car
                   :test #'equal))
  service-id)

(defun mongo--pool-set-service-count (pool service-id count)
  "Set POOL's SERVICE-ID connection count to COUNT."
  (cond
   ((not service-id) nil)
   ((<= count 0)
    (mongo--pool-remove-service-id pool service-id)
    0)
   (t
    (setf (mongo-pool-service-counts pool)
          (cons (cons service-id count)
                (cl-remove service-id
                           (mongo-pool-service-counts pool)
                           :key #'car
                           :test #'equal)))
    count)))

(defun mongo--pool-increment-service-count (pool service-id)
  "Increment POOL's connection count for SERVICE-ID."
  (when service-id
    (mongo--pool-set-service-count
     pool service-id
     (1+ (mongo--pool-service-count pool service-id)))))

(defun mongo--pool-decrement-service-count (pool service-id)
  "Decrement POOL's connection count for SERVICE-ID."
  (when service-id
    (mongo--pool-set-service-count
     pool service-id
     (1- (mongo--pool-service-count pool service-id)))))

(defun mongo--pool-connection-service-id (conn)
  "Return CONN's load-balanced serviceId, or nil."
  (and (mongo-conn-p conn)
       (mongo-conn-service-id conn)))

(defun mongo--pool-connection-service-id-equal-p (conn service-id)
  "Return non-nil when CONN belongs to SERVICE-ID."
  (equal (mongo--pool-connection-service-id conn) service-id))

(defun mongo--pool-generation-state (pool conn)
  "Return POOL generation state for CONN."
  (let ((service-id (mongo--pool-connection-service-id conn)))
    (cons (mongo--pool-generation pool)
          (and service-id
               (mongo--pool-service-generation pool service-id)))))

(defun mongo--pool-track-connection (pool conn &optional generation)
  "Record CONN as belonging to POOL GENERATION."
  (let ((generation (or generation
                        (mongo--pool-generation-state pool conn)))
        (existing (cl-assoc conn
                            (mongo-pool-conn-generations pool)
                            :test #'eq))
        (service-id (mongo--pool-connection-service-id conn)))
    (when existing
      (mongo--pool-decrement-service-count
       pool
       (cdr (cl-assoc conn
                      (mongo-pool-conn-service-ids pool)
                      :test #'eq))))
    (mongo--pool-increment-service-count pool service-id)
    (setf (mongo-pool-conn-generations pool)
          (cons (cons conn generation)
                (cl-remove conn
                           (mongo-pool-conn-generations pool)
                           :key #'car
                           :test #'eq)))
    (setf (mongo-pool-conn-service-ids pool)
          (cons (cons conn service-id)
                (cl-remove conn
                           (mongo-pool-conn-service-ids pool)
                           :key #'car
                           :test #'eq))))
  conn)

(defun mongo--pool-untrack-connection (pool conn)
  "Forget CONN's generation in POOL."
  (when (cl-assoc conn (mongo-pool-conn-generations pool) :test #'eq)
    (mongo--pool-decrement-service-count
     pool
     (cdr (cl-assoc conn
                    (mongo-pool-conn-service-ids pool)
                    :test #'eq)))
    (setf (mongo-pool-conn-generations pool)
          (cl-remove conn
                     (mongo-pool-conn-generations pool)
                     :key #'car
                     :test #'eq))
    (setf (mongo-pool-conn-service-ids pool)
          (cl-remove conn
                     (mongo-pool-conn-service-ids pool)
                     :key #'car
                     :test #'eq)))
  conn)

(defun mongo--pool-connection-generation (pool conn)
  "Return CONN's generation in POOL, or nil."
  (cdr (cl-assoc conn
                 (mongo-pool-conn-generations pool)
                 :test #'eq)))

(defun mongo--pool-current-generation-connection-p (pool conn)
  "Return non-nil when CONN belongs to POOL's current generation."
  (equal (mongo--pool-connection-generation pool conn)
         (mongo--pool-generation-state pool conn)))

(defun mongo--pool-clear-generation-connection-p
    (pool conn service-id generation service-generation)
  "Return non-nil when CONN is affected by a pool clear."
  (let ((conn-generation (mongo--pool-connection-generation pool conn)))
    (and (or (not service-id)
             (mongo--pool-connection-service-id-equal-p conn service-id))
         (if service-id
             (<= (or (cdr-safe conn-generation) 0)
                 service-generation)
           (<= (or (car-safe conn-generation) 0)
               generation)))))

(defun mongo--pool-entry-current-generation-p (pool entry)
  "Return non-nil when ENTRY belongs to POOL's current generation."
  (equal (mongo--pool-entry-generation entry)
         (mongo--pool-generation-state
          pool (mongo--pool-entry-conn entry))))

(defun mongo--pool-entry-stale-p (pool entry)
  "Return non-nil when POOL ENTRY exceeded maxIdleTimeMS."
  (when-let* ((max-idle (mongo-pool-max-idle-time pool)))
    (> (- (float-time) (mongo--pool-entry-idle-since entry))
       max-idle)))

(defun mongo--pool-prune-available (pool)
  "Close stale or dead available connections from POOL."
  (let ((kept nil)
        (min-size (mongo-pool-min-size pool))
        (total-size (mongo--pool-total-size pool)))
    (dolist (entry (mongo-pool-available pool))
      (let ((conn (mongo--pool-entry-conn entry)))
        (cond
         ((and (mongo--pool-entry-generation entry)
               (not (mongo--pool-entry-current-generation-p pool entry)))
          (setq total-size (1- total-size))
          (mongo--pool-close-connection pool conn 'stale))
         ((not (mongo-live-p conn))
          (setq total-size (1- total-size))
          (mongo--pool-close-connection pool conn 'error))
         ((and (mongo--pool-entry-stale-p pool entry)
               (> total-size min-size))
          (setq total-size (1- total-size))
          (mongo--pool-close-connection pool conn 'idle))
         (t
          (push entry kept)))))
    (setf (mongo-pool-available pool) (nreverse kept)))
  pool)

(defun mongo--pool-pop-available (pool)
  "Return one live available connection from POOL, or nil."
  (mongo--pool-prune-available pool)
  (let (conn)
    (while (and (not conn)
                (mongo-pool-available pool))
      (let* ((entry (pop (mongo-pool-available pool)))
             (candidate (mongo--pool-entry-conn entry)))
        (if (mongo-live-p candidate)
            (setq conn candidate)
          (mongo--pool-close-connection pool candidate 'error))))
    conn))

(defun mongo--pool-add-available-connection (pool conn)
  "Add CONN to POOL's available list."
  (push (make-mongo--pool-entry
         :conn conn
         :idle-since (float-time)
         :generation (mongo--pool-connection-generation pool conn))
        (mongo-pool-available pool))
  conn)

(defun mongo--pool-maintain-min-size (pool)
  "Populate POOL until minPoolSize is satisfied when ready."
  (unless (or (mongo-pool-closed pool)
              (mongo-pool-paused pool))
    (let ((min-size (or (mongo-pool-min-size pool) 0)))
      (while (and (< (mongo--pool-total-size pool) min-size)
                  (not (mongo--pool-at-capacity-p pool))
                  (not (mongo--pool-connecting-at-capacity-p pool)))
        (mongo--pool-add-available-connection
         pool (mongo--pool-open-connection pool)))))
  pool)

(defun mongo--pool-open-connection (pool)
  "Open one MongoDB connection for POOL."
  (let ((connection-id (mongo--pool-next-connection-id pool))
        (connection-start (float-time)))
    (setf (mongo-pool-connecting pool)
          (1+ (or (mongo-pool-connecting pool) 0)))
    (mongo--pool-emit-event
     pool 'connection-created
     (cons 'connection-id connection-id))
    (unwind-protect
        (condition-case err
            (let ((conn (mongo-connect (copy-sequence (mongo-pool-params pool)))))
              (mongo--pool-record-connection-id pool conn connection-id)
              (mongo--pool-track-connection pool conn)
              (mongo--pool-emit-event
               pool 'connection-ready
               (cons 'connection conn)
               (cons 'connection-id connection-id)
               (cons 'service-id (mongo--pool-connection-service-id conn))
               (cons 'duration-ms
                     (mongo--pool-duration-ms connection-start)))
              conn)
          (error
           (mongo--pool-close-connection pool nil 'error connection-id)
           (signal (car err) (cdr err))))
      (setf (mongo-pool-connecting pool)
            (max 0 (1- (or (mongo-pool-connecting pool) 0)))))))

(defun mongo-pool-open (params)
  "Open a MongoDB connection pool using PARAMS.
Pool options are read from PARAMS or MongoDB URI options, including
maxPoolSize, minPoolSize, maxIdleTimeMS, waitQueueTimeoutMS, and
maxConnecting.  Connections are still ordinary native `mongo-conn' values."
  (mongo--params-validate-pool-options params)
  (let* ((pool (make-mongo-pool
                :params (copy-sequence params)
                :max-size (mongo--params-max-pool-size params)
                :min-size (mongo--params-min-pool-size params)
                :max-idle-time (mongo--params-max-idle-time params)
                :wait-queue-timeout (mongo--params-wait-queue-timeout params)
                :max-connecting (mongo--params-max-connecting params)
                :paused t)))
    (mongo--pool-emit-event
     pool 'connection-pool-created
     (cons 'options (mongo--pool-created-options pool)))
    (mongo-pool-ready pool)
    pool))

(defun mongo-pool-checkout (pool &optional timeout purpose)
  "Check out and return one live MongoDB connection from POOL.
TIMEOUT overrides waitQueueTimeoutMS and is measured in seconds.
A nil pool wait queue timeout has no deadline.  A numeric TIMEOUT of 0 waits
no time.  PURPOSE is one of `cursor', `transaction', or `other' and is used for
load-balanced wait queue diagnostics."
  (let* ((checkout-start (float-time))
         (wait-timeout (or timeout
                           (mongo-pool-wait-queue-timeout pool)))
         (deadline (and wait-timeout
                        (+ checkout-start wait-timeout)))
         conn)
    (mongo--pool-emit-event pool 'connection-check-out-started)
    (mongo--pool-checkout-signal-unavailable pool checkout-start)
    (catch 'done
      (while t
        (mongo--pool-checkout-signal-unavailable pool checkout-start)
        (setq conn (mongo--pool-pop-available pool))
        (when conn
          (throw 'done
                 (mongo--pool-checkout-succeed
                  pool checkout-start conn purpose)))
        (unless (or (mongo--pool-at-capacity-p pool)
                    (mongo--pool-connecting-at-capacity-p pool))
          (condition-case err
              (progn
                (setq conn (mongo--pool-open-connection pool))
                (throw 'done
                       (mongo--pool-checkout-succeed
                        pool checkout-start conn purpose)))
            (error
             (mongo--pool-emit-checkout-failed
              pool checkout-start 'connection-error err)
             (signal (car err) (cdr err)))))
        (when (and deadline
                   (<= deadline (float-time)))
          (mongo--pool-emit-checkout-failed pool checkout-start 'timeout)
          (signal 'mongo-error
                  (list (mongo--pool-checkout-timeout-message pool))))
        (accept-process-output nil 0.05)
        (sit-for 0 t)))))

(defun mongo-pool-release (pool conn)
  "Release CONN back to POOL."
  (unless (memq conn (mongo-pool-in-use pool))
    (signal 'mongo-error
            (list "MongoDB connection is not checked out from this pool")))
  (setf (mongo-pool-in-use pool)
        (delq conn (mongo-pool-in-use pool)))
  (mongo--pool-forget-connection-purpose pool conn)
  (mongo--pool-emit-event
   pool 'connection-checked-in
   (cons 'connection conn)
   (cons 'connection-id (mongo--pool-connection-id pool conn)))
  (cond
   ((mongo-pool-closed pool)
    (mongo--pool-close-connection pool conn 'pool-closed))
   ((and (mongo-conn-p conn)
         (mongo-conn-closed conn)
         (not (mongo--pool-connection-generation pool conn)))
    (mongo--pool-forget-connection-id pool conn))
   ((not (mongo-live-p conn))
    (mongo--pool-close-connection pool conn 'error))
   ((not (mongo--pool-current-generation-connection-p pool conn))
    (mongo--pool-close-connection pool conn 'stale))
   (t
    (mongo--pool-add-available-connection pool conn)))
  (mongo--pool-maintain-min-size pool)
  pool)

(defun mongo--pool-interrupt-in-use
    (pool service-id generation service-generation)
  "Close checked-out POOL connections affected by a clear."
  (dolist (conn (copy-sequence (mongo-pool-in-use pool)))
    (when (mongo--pool-clear-generation-connection-p
           pool conn service-id generation service-generation)
      (let ((connection-id (mongo--pool-connection-id pool conn)))
        (mongo--pool-close-connection pool conn 'stale)
        (when connection-id
          (mongo--pool-record-connection-id pool conn connection-id)))))
  pool)

(defun mongo-pool-clear
    (pool &optional service-id interrupt-in-use-connections)
  "Clear POOL and advance its CMAP generation.
When SERVICE-ID is nil, clear all available connections, mark all checked-out
connections stale, and pause POOL until `mongo-pool-ready' is called.
When SERVICE-ID is non-nil, clear only load-balanced connections for that
serviceId without pausing POOL.
When INTERRUPT-IN-USE-CONNECTIONS is non-nil, immediately close checked-out
connections affected by the clear instead of waiting for release."
  (unless (mongo-pool-closed pool)
    (let ((emit-cleared-event t)
          (generation (mongo--pool-generation pool))
          (service-generation
           (mongo--pool-service-generation pool service-id)))
      (if service-id
          (mongo--pool-set-service-generation
           pool service-id
           (1+ (mongo--pool-service-generation pool service-id)))
        (setq emit-cleared-event (not (mongo-pool-paused pool)))
        (setf (mongo-pool-generation pool)
              (1+ (mongo--pool-generation pool)))
        (setf (mongo-pool-paused pool) t))
      (when emit-cleared-event
        (let ((fields (list (cons 'service-id service-id))))
          (when interrupt-in-use-connections
            (setq fields
                  (append fields
                          (list (cons 'interrupt-in-use-connections t)))))
          (apply #'mongo--pool-emit-event
                 pool 'connection-pool-cleared fields))
        (let (kept)
          (dolist (entry (mongo-pool-available pool))
            (let ((conn (mongo--pool-entry-conn entry)))
              (if (or (not service-id)
                      (mongo--pool-connection-service-id-equal-p
                       conn service-id))
                  (mongo--pool-close-connection pool conn 'stale)
                (push entry kept))))
          (setf (mongo-pool-available pool) (nreverse kept))))
      (when interrupt-in-use-connections
        (mongo--pool-interrupt-in-use
         pool service-id generation service-generation))))
  pool)

(defun mongo-pool-ready (pool)
  "Mark POOL ready after a clear."
  (when (mongo-pool-closed pool)
    (signal 'mongo-error
            (list "MongoDB connection pool is closed")))
  (when (mongo-pool-paused pool)
    (setf (mongo-pool-paused pool) nil)
    (mongo--pool-emit-event pool 'connection-pool-ready))
  (mongo--pool-maintain-min-size pool)
  pool)

(defun mongo--pool-monitor-disconnect (pool)
  "Close POOL's dedicated monitor connection, if any."
  (when-let* ((conn (mongo-pool-monitor-conn pool)))
    (setf (mongo-pool-monitor-conn pool) nil)
    (ignore-errors
      (mongo-disconnect conn))))

(defun mongo--pool-monitor-connection (pool)
  "Return a live dedicated monitor connection for POOL."
  (when (mongo--params-load-balanced-p (mongo-pool-params pool))
    (signal 'mongo-error
            (list "MongoDB load-balanced pools do not use monitor connections")))
  (let ((conn (mongo-pool-monitor-conn pool)))
    (unless (mongo-live-p conn)
      (mongo--pool-monitor-disconnect pool)
      (setq conn (mongo-connect (copy-sequence (mongo-pool-params pool))))
      (setf (mongo-pool-monitor-conn pool) conn))
    conn))

(defun mongo-pool-monitor-once
    (pool &optional max-await-time-ms timeout)
  "Run one SDAM monitor heartbeat for POOL.
On success, mark a cleared pool ready.  On failure, record the error, close the
dedicated monitor connection, clear the pool, and signal the heartbeat error.
In load-balanced mode, do not open a dedicated monitoring connection."
  (when (mongo-pool-closed pool)
    (signal 'mongo-error
            (list "MongoDB connection pool is closed")))
  (if (mongo--params-load-balanced-p (mongo-pool-params pool))
      (progn
        (setf (mongo-pool-monitor-error pool) nil)
        (mongo--pool-monitor-disconnect pool)
        nil)
    (condition-case err
        (let* ((conn (mongo--pool-monitor-connection pool))
               (hello (mongo-monitor-once conn max-await-time-ms timeout)))
          (setf (mongo-pool-monitor-error pool) nil)
          (mongo-pool-ready pool)
          hello)
      (error
       (setf (mongo-pool-monitor-error pool) err)
       (mongo--pool-monitor-disconnect pool)
       (unless (mongo-pool-closed pool)
         (mongo-pool-clear pool))
       (signal (car err) (cdr err))))))

(defun mongo--pool-monitor-tick (pool max-await-time-ms timeout)
  "Run one scheduled SDAM monitor tick for POOL."
  (if (mongo-pool-closed pool)
      (mongo-pool-stop-monitor pool)
    (ignore-errors
      (mongo-pool-monitor-once pool max-await-time-ms timeout))))

(defun mongo-pool-stop-monitor (pool)
  "Stop POOL's SDAM monitor timer and close its monitor connection."
  (when-let* ((timer (mongo-pool-monitor-timer pool)))
    (ignore-errors
      (cancel-timer timer))
    (setf (mongo-pool-monitor-timer pool) nil))
  (mongo--pool-monitor-disconnect pool)
  pool)

(defun mongo-pool-start-monitor
    (pool &optional heartbeat-seconds max-await-time-ms timeout)
  "Start an SDAM-style monitor timer for POOL.
Successful monitor checks mark a cleared pool ready; failed checks clear and
pause the pool so later successful checks can recover it."
  (when (mongo-pool-closed pool)
    (signal 'mongo-error
            (list "MongoDB connection pool is closed")))
  (mongo-pool-stop-monitor pool)
  (unless (mongo--params-load-balanced-p (mongo-pool-params pool))
    (let* ((params (mongo-pool-params pool))
           (heartbeat (or heartbeat-seconds
                          (mongo--params-heartbeat-frequency params)
                          mongo-monitor-heartbeat-seconds))
           (max-await (or max-await-time-ms
                          (round (* 1000 heartbeat))))
           (timeout (or timeout
                        (+ 1 (/ (float max-await) 1000.0)))))
      (setf (mongo-pool-monitor-timer pool)
            (run-at-time 0 heartbeat
                         #'mongo--pool-monitor-tick
                         pool max-await timeout))))
  pool)

(defun mongo-pool-disconnect (pool)
  "Close all connections owned by MongoDB POOL."
  (when pool
    (mongo-pool-stop-monitor pool)
    (setf (mongo-pool-closed pool) t)
    (dolist (entry (mongo-pool-available pool))
      (mongo--pool-close-connection
       pool (mongo--pool-entry-conn entry) 'pool-closed))
    (dolist (conn (mongo-pool-in-use pool))
      (mongo--pool-close-connection pool conn 'pool-closed))
    (setf (mongo-pool-available pool) nil)
    (setf (mongo-pool-in-use pool) nil)
    (setf (mongo-pool-service-generations pool) nil)
    (setf (mongo-pool-service-counts pool) nil)
    (setf (mongo-pool-conn-generations pool) nil)
    (setf (mongo-pool-conn-service-ids pool) nil)
    (setf (mongo-pool-conn-ids pool) nil)
    (setf (mongo-pool-conn-purposes pool) nil)
    (setf (mongo-pool-paused pool) nil)
    (setf (mongo-pool-connecting pool) 0)
    (mongo--pool-emit-event pool 'connection-pool-closed))
  pool)

(defmacro mongo-with-pool-connection (binding &rest body)
  "Run BODY with a connection checked out according to BINDING.
BINDING has the form (CONN POOL &optional TIMEOUT PURPOSE)."
  (declare (indent 1))
  (let ((conn (nth 0 binding))
        (pool (nth 1 binding))
        (timeout (nth 2 binding))
        (purpose (nth 3 binding)))
    `(let ((,conn (mongo-pool-checkout ,pool ,timeout ,purpose)))
       (unwind-protect
           (progn ,@body)
         (mongo-pool-release ,pool ,conn)))))

(defun mongo--pool-resignal-command-error (pool conn err)
  "Clear POOL for checked-out CONN when ERR requires it, then signal ERR."
  (when (mongo--pool-command-clear-error-p err)
    (mongo-pool-clear
     pool (mongo--pool-connection-service-id conn)))
  (signal (car err) (cdr err)))

(defun mongo-pool-command (pool database command &optional timeout sequences)
  "Run MongoDB COMMAND on DATABASE using one connection from POOL."
  (let ((conn (mongo-pool-checkout pool nil 'other)))
    (unwind-protect
        (condition-case err
            (mongo-command conn database command timeout sequences)
          (error
           (mongo--pool-resignal-command-error pool conn err)))
      (mongo-pool-release pool conn))))

(defun mongo-pool-cursor-results
    (pool database collection command first-key
          &optional timeout get-more-options sequences)
  "Run cursor COMMAND from POOL and return all result documents.
The same checked-out connection is used for the initial command, getMore, and
killCursors.  This is required for load-balanced cursor operations and is also a
safe default for ordinary pools."
  (let ((conn (mongo-pool-checkout pool nil 'cursor)))
    (unwind-protect
        (condition-case err
            (let ((response
                   (mongo-command conn database command timeout sequences)))
              (mongo--cursor-results
               conn database collection response first-key get-more-options
               (mongo-conn-load-balanced conn)))
          (error
           (mongo--pool-resignal-command-error pool conn err)))
      (mongo-pool-release pool conn))))

(defun mongo-pool-find
    (pool database collection &optional filter projection limit skip options timeout)
  "Return documents from COLLECTION in DATABASE using one connection from POOL."
  (let ((option-pairs (mongo--option-pairs options)))
    (mongo-pool-cursor-results
     pool database collection
     (mongo-find-command collection filter projection limit skip option-pairs)
     "firstBatch" timeout
     (mongo--cursor-get-more-options option-pairs))))

(provide 'mongo)
;;; mongo.el ends here
