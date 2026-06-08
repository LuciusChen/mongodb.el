;;; mongo-auth.el --- Authentication mechanisms -*- lexical-binding: t; -*-

;; Copyright (C) 2025-2026 Lucius Chen
;; SPDX-License-Identifier: GPL-3.0-or-later

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

;; Native MongoDB authentication mechanisms and related token helpers.

;;; Code:

(require 'cl-lib)
(require 'json)
(require 'mongo-bson)
(require 'mongo-params)
(require 'parse-time)
(require 'seq)
(require 'subr-x)
(require 'ucs-normalize)
(require 'url)
(require 'url-util)

(declare-function mongo-command "mongo" (conn database command &optional timeout sequences))
(declare-function mongo-conn-host "mongo" (conn))
(declare-function mongo-conn-p "mongo" (object))

(cl-defstruct mongo--aws-credentials
  access-key-id
  secret-access-key
  session-token
  expiration)

;;;; Authentication

(defconst mongo--scram-auth-mechanisms
  '("SCRAM-SHA-256" "SCRAM-SHA-1"))

(defconst mongo--supported-auth-mechanisms
  (append mongo--scram-auth-mechanisms
          '("MONGODB-X509" "PLAIN" "MONGODB-AWS" "MONGODB-OIDC")))

(defconst mongo--saslprep-map-to-nothing-ranges
  '((#x00AD . #x00AD)
    (#x034F . #x034F)
    (#x1806 . #x1806)
    (#x180B . #x180D)
    (#x200B . #x200D)
    (#x2060 . #x2060)
    (#xFE00 . #xFE0F)
    (#xFEFF . #xFEFF))
  "RFC 3454 table B.1 characters mapped to nothing by SASLprep.")

(defconst mongo--saslprep-space-ranges
  '((#x00A0 . #x00A0)
    (#x1680 . #x1680)
    (#x2000 . #x200A)
    (#x202F . #x202F)
    (#x205F . #x205F)
    (#x3000 . #x3000))
  "RFC 3454 table C.1.2 space characters mapped to ASCII space.")

(defconst mongo--saslprep-prohibited-ranges
  '((#x0000 . #x001F)
    (#x007F . #x009F)
    (#x06DD . #x06DD)
    (#x070F . #x070F)
    (#x180E . #x180E)
    (#x200C . #x200D)
    (#x2028 . #x2029)
    (#x2060 . #x2063)
    (#x206A . #x206F)
    (#x2FF0 . #x2FFB)
    (#xD800 . #xDFFF)
    (#xE000 . #xF8FF)
    (#xFDD0 . #xFDEF)
    (#xFEFF . #xFEFF)
    (#xFFF9 . #xFFFD)
    (#x1D173 . #x1D17A)
    (#xE0001 . #xE0001)
    (#xE0020 . #xE007F)
    (#xF0000 . #xFFFFD)
    (#x100000 . #x10FFFD))
  "RFC 4013 prohibited output ranges for SASLprep.")

(defun mongo--choose-auth-mechanism (credential hello)
  "Return the auth mechanism to use for CREDENTIAL from HELLO."
  (let ((mechanism
         (mongo--normalize-auth-mechanism
          (mongo--credential-mechanism credential)))
        (supported (cdr (assoc "saslSupportedMechs" hello))))
    (cond
     (mechanism
      (unless (member mechanism mongo--supported-auth-mechanisms)
        (signal 'mongo-error
                (list (format "Native MongoDB authentication supports SCRAM-SHA-256, SCRAM-SHA-1, MONGODB-X509, PLAIN, MONGODB-AWS, and MONGODB-OIDC, not %s"
                              mechanism))))
      (when (and (member mechanism mongo--scram-auth-mechanisms)
                 supported
                 (not (member mechanism supported)))
        (signal 'mongo-error
                (list (format "MongoDB server/user does not report support for %s"
                              mechanism))))
      mechanism)
     ((member "SCRAM-SHA-256" supported)
      "SCRAM-SHA-256")
     ((member "SCRAM-SHA-1" supported)
      "SCRAM-SHA-1")
     (supported
      (signal 'mongo-error
              (list "Native MongoDB authentication requires SCRAM-SHA-256 or SCRAM-SHA-1 support from the server/user")))
     (t
      "SCRAM-SHA-1"))))

(defun mongo--codepoint-in-ranges-p (codepoint ranges)
  "Return non-nil when CODEPOINT is included in RANGES."
  (cl-some (lambda (range)
             (and (<= (car range) codepoint)
                  (<= codepoint (cdr range))))
           ranges))

(defun mongo--saslprep-map-char (char)
  "Return SASLprep-mapped CHAR, or nil when CHAR maps to nothing."
  (cond
   ((mongo--codepoint-in-ranges-p
     char mongo--saslprep-map-to-nothing-ranges)
    nil)
   ((mongo--codepoint-in-ranges-p char mongo--saslprep-space-ranges)
    ?\s)
   (t
    char)))

(defun mongo--saslprep-non-character-codepoint-p (char)
  "Return non-nil when CHAR is a Unicode non-character code point."
  (or (and (<= #xFDD0 char)
           (<= char #xFDEF))
      (and (<= 0 char)
           (<= char #x10FFFF)
           (let ((low (logand char #xFFFF)))
             (or (= low #xFFFE)
                 (= low #xFFFF))))))

(defun mongo--saslprep-prohibited-p (char)
  "Return non-nil when CHAR is prohibited by SASLprep."
  (or (mongo--codepoint-in-ranges-p
       char mongo--saslprep-prohibited-ranges)
      (mongo--saslprep-non-character-codepoint-p char)))

(defun mongo--saslprep-randal-p (char)
  "Return non-nil when CHAR is in RFC 3454 RandALCat."
  (memq (get-char-code-property char 'bidi-class) '(R AL)))

(defun mongo--saslprep-lcat-p (char)
  "Return non-nil when CHAR is in RFC 3454 LCat."
  (eq (get-char-code-property char 'bidi-class) 'L))

(defun mongo--saslprep (string)
  "Prepare STRING with the SASLprep profile used by MongoDB SCRAM-SHA-256."
  (let* ((mapped-chars
          (cl-loop for char across string
                   for mapped = (mongo--saslprep-map-char char)
                   when mapped collect mapped))
         (normalized
          (ucs-normalize-NFKC-string
           (mapconcat #'char-to-string mapped-chars "")))
         (has-randal nil)
         (has-lcat nil))
    (cl-loop for char across normalized
             do
             (when (mongo--saslprep-prohibited-p char)
               (signal 'mongo-error
                       (list (format "MongoDB SCRAM password contains a prohibited SASLprep character: U+%04X"
                                     char))))
             (when (mongo--saslprep-randal-p char)
               (setq has-randal t))
             (when (mongo--saslprep-lcat-p char)
               (setq has-lcat t)))
    (when has-randal
      (when has-lcat
        (signal 'mongo-error
                (list "MongoDB SCRAM password violates SASLprep bidirectional text rules")))
      (unless (and (> (length normalized) 0)
                   (mongo--saslprep-randal-p (aref normalized 0))
                   (mongo--saslprep-randal-p
                    (aref normalized (1- (length normalized)))))
        (signal 'mongo-error
                (list "MongoDB SCRAM password violates SASLprep bidirectional text rules"))))
    normalized))

(defun mongo--scram-password-bytes (secret)
  "Return SASLprep-normalized SECRET bytes for SCRAM-SHA-256."
  (mongo--utf8-bytes (mongo--saslprep secret)))

(defun mongo--scram-sha1-password-bytes (username secret)
  "Return MongoDB SCRAM-SHA-1 password digest bytes for USERNAME and SECRET."
  (mongo--utf8-bytes
   (secure-hash
    'md5
    (mongo--utf8-bytes
     (format "%s:mongo:%s" username secret)))))

(defvar mongo--random-seeded nil
  "Non-nil after `random' has been seeded for MongoDB nonce generation.")

(defun mongo--random-bytes (count)
  "Return COUNT random bytes."
  (unless mongo--random-seeded
    (random t)
    (setq mongo--random-seeded t))
  (let ((bytes ""))
    (while (< (length bytes) count)
      (setq bytes
            (concat
             bytes
             (secure-hash
              'sha256
              (format "%S:%S:%S:%S"
                      (current-time)
                      (random)
                      (emacs-pid)
                      (garbage-collect))
              nil nil t))))
    (substring bytes 0 count)))

(defun mongo--scram-client-nonce ()
  "Return a printable SCRAM client nonce."
  (mongo--base64-encode (mongo--random-bytes 24)))

(defun mongo--uuid-v4-bytes ()
  "Return a locally generated RFC 4122 version 4 UUID as 16 bytes."
  (let ((bytes (copy-sequence (mongo--random-bytes 16))))
    (aset bytes 6 (logior #x40 (logand (aref bytes 6) #x0f)))
    (aset bytes 8 (logior #x80 (logand (aref bytes 8) #x3f)))
    bytes))

(defvar mongo--object-id-random nil
  "Five process-random bytes used when generating MongoDB ObjectIds.")

(defvar mongo--object-id-counter nil
  "Three-byte counter used when generating MongoDB ObjectIds.")

(defun mongo--uint24-value (bytes)
  "Return the unsigned 24-bit integer represented by BYTES."
  (logior (ash (aref bytes 0) 16)
          (ash (aref bytes 1) 8)
          (aref bytes 2)))

(defun mongo--pack-uint24-be (value)
  "Return VALUE packed as unsigned big-endian uint24."
  (unibyte-string
   (logand (ash value -16) #xff)
   (logand (ash value -8) #xff)
   (logand value #xff)))

(defun mongo-new-object-id (&optional time)
  "Return a newly generated MongoDB ObjectId.
TIME, when non-nil, supplies the timestamp component."
  (unless mongo--object-id-random
    (setq mongo--object-id-random (mongo--random-bytes 5)))
  (unless mongo--object-id-counter
    (setq mongo--object-id-counter
          (mongo--uint24-value (mongo--random-bytes 3))))
  (let* ((seconds (logand (floor (float-time (or time (current-time))))
                          #xffffffff))
         (counter mongo--object-id-counter)
         (bytes (concat
                 (mongo--pack-uint32-be seconds)
                 mongo--object-id-random
                 (mongo--pack-uint24-be counter))))
    (setq mongo--object-id-counter
          (mod (1+ mongo--object-id-counter) #x1000000))
    (mongo-object-id (mongo--bytes-to-hex bytes))))

(defun mongo--make-session-id ()
  "Return a MongoDB logical session id document."
  `(("id" . ,(mongo-binary 4 (mongo--uuid-v4-bytes)))))

(defun mongo--scram-escape-name (name)
  "Return SCRAM escaped NAME."
  (replace-regexp-in-string
   "," "=2C"
   (replace-regexp-in-string "=" "=3D" name t t)
   t t))

(defun mongo--scram-parse-attrs (message)
  "Parse a SCRAM MESSAGE into an alist of attribute strings."
  (let (attrs)
    (dolist (part (split-string message "," t))
      (unless (string-match "\\`\\([^=]+\\)=\\(.*\\)\\'" part)
        (signal 'mongo-error
                (list (format "Invalid MongoDB SCRAM message: %S" message))))
      (push (cons (match-string 1 part)
                  (match-string 2 part))
            attrs))
    (nreverse attrs)))

(defun mongo--scram-payload-string (payload)
  "Return SCRAM PAYLOAD decoded as a UTF-8 string."
  (cond
   ((stringp payload)
    payload)
   (t
    (decode-coding-string
     (mongo--binary-value-data payload)
     'utf-8 t))))

(defun mongo--scram-start-data (credential mechanism)
  "Return SCRAM client-first data for CREDENTIAL and MECHANISM."
  (let* ((username (mongo--credential-username credential))
         (source (mongo--credential-source credential))
         (client-nonce (mongo--scram-client-nonce))
         (client-first-bare
          (format "n=%s,r=%s"
                  (mongo--scram-escape-name username)
                  client-nonce))
         (client-first (concat "n,," client-first-bare)))
    (list :mechanism mechanism
          :source source
          :username username
          :client-nonce client-nonce
          :client-first-bare client-first-bare
          :client-first client-first)))

(defun mongo--scram-start-command (start-data &optional include-db)
  "Return a MongoDB saslStart command from START-DATA.
When INCLUDE-DB is non-nil, include the auth database as a top-level db field
for speculative authentication."
  `(("saslStart" . 1)
    ("mechanism" . ,(plist-get start-data :mechanism))
    ("options" . (("skipEmptyExchange" . t)))
    ("payload" . ,(mongo-binary
                   0
                   (mongo--utf8-bytes
                    (plist-get start-data :client-first))))
    ,@(when include-db
        `(("db" . ,(plist-get start-data :source))))
    ("autoAuthorize" . 1)))

(defun mongo--credential-scram-negotiation-p (credential)
  "Return non-nil when CREDENTIAL should request saslSupportedMechs."
  (when credential
    (let ((mechanism (mongo--normalize-auth-mechanism
                      (mongo--credential-mechanism credential))))
      (or (null mechanism)
          (member mechanism mongo--scram-auth-mechanisms)))))

(defun mongo--speculative-auth-state (credential)
  "Return SCRAM speculative authentication state for CREDENTIAL, or nil."
  (when credential
    (let ((mechanism (or (mongo--normalize-auth-mechanism
                          (mongo--credential-mechanism credential))
                         "SCRAM-SHA-256")))
      (when (member mechanism mongo--scram-auth-mechanisms)
        (mongo--scram-start-data credential mechanism)))))

(defun mongo--scram-client-final
    (mechanism username secret client-first-bare client-nonce server-first-message)
  "Return SCRAM final data for MECHANISM and SERVER-FIRST-MESSAGE.
The returned plist contains :message, :server-signature, and :server-nonce."
  (let* ((attrs (mongo--scram-parse-attrs server-first-message))
         (server-nonce (cdr (assoc "r" attrs)))
         (salt64 (cdr (assoc "s" attrs)))
         (iterations-text (cdr (assoc "i" attrs)))
         (iterations (and iterations-text
                          (string-to-number iterations-text))))
    (unless (and server-nonce
                 (string-prefix-p client-nonce server-nonce))
      (signal 'mongo-error
              (list "MongoDB SCRAM server nonce does not extend client nonce")))
    (unless salt64
      (signal 'mongo-error
              (list "MongoDB SCRAM server message is missing salt")))
    (unless (and iterations
                 (>= iterations 4096))
      (signal 'mongo-error
              (list "MongoDB SCRAM server message has invalid iteration count")))
    (let* ((salt (mongo--base64-decode salt64))
           (client-final-without-proof
            (format "c=biws,r=%s" server-nonce))
           (auth-message
            (mongo--utf8-bytes
             (mapconcat #'identity
                        (list client-first-bare
                              server-first-message
                              client-final-without-proof)
                        ",")))
           (salted-password
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongo--pbkdf2-hmac-sha256
                (mongo--scram-password-bytes secret)
                salt
                iterations))
              ("SCRAM-SHA-1"
               (mongo--pbkdf2-hmac-sha1
                (mongo--scram-sha1-password-bytes username secret)
                salt
                iterations))
              (_
               (signal 'mongo-error
                       (list (format "Unsupported MongoDB auth mechanism: %s"
                                     mechanism))))))
           (client-key
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongo--hmac-sha256 salted-password
                                   (mongo--utf8-bytes "Client Key")))
              ("SCRAM-SHA-1"
               (mongo--hmac-sha1 salted-password
                                  (mongo--utf8-bytes "Client Key")))))
           (stored-key
            (pcase mechanism
              ("SCRAM-SHA-256" (mongo--sha256 client-key))
              ("SCRAM-SHA-1" (mongo--sha1 client-key))))
           (client-signature
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongo--hmac-sha256 stored-key auth-message))
              ("SCRAM-SHA-1"
               (mongo--hmac-sha1 stored-key auth-message))))
           (client-proof
            (mongo--xor-bytes client-key client-signature))
           (server-key
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongo--hmac-sha256 salted-password
                                   (mongo--utf8-bytes "Server Key")))
              ("SCRAM-SHA-1"
               (mongo--hmac-sha1 salted-password
                                  (mongo--utf8-bytes "Server Key")))))
           (server-signature
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongo--hmac-sha256 server-key auth-message))
              ("SCRAM-SHA-1"
               (mongo--hmac-sha1 server-key auth-message)))))
      (list :message
            (format "%s,p=%s"
                    client-final-without-proof
                    (mongo--base64-encode client-proof))
            :server-signature server-signature
            :server-nonce server-nonce))))

(defun mongo--scram-sha256-client-final
    (secret client-first-bare client-nonce server-first-message)
  "Return SCRAM-SHA-256 final data for SERVER-FIRST-MESSAGE."
  (mongo--scram-client-final
   "SCRAM-SHA-256" nil secret client-first-bare client-nonce
   server-first-message))

(defun mongo--scram-sha1-client-final
    (username secret client-first-bare client-nonce server-first-message)
  "Return SCRAM-SHA-1 final data for SERVER-FIRST-MESSAGE."
  (mongo--scram-client-final
   "SCRAM-SHA-1" username secret client-first-bare client-nonce
   server-first-message))

(defun mongo--authenticate-scram
    (conn credential mechanism &optional start-data start-response)
  "Authenticate CONN with CREDENTIAL using SCRAM MECHANISM.
START-DATA and START-RESPONSE, when non-nil, continue a speculative
authentication exchange started in the initial handshake."
  (let* ((start-data (or start-data
                         (mongo--scram-start-data credential mechanism)))
         (username (mongo--credential-username credential))
         (secret (mongo--credential-password credential))
         (source (mongo--credential-source credential))
         (client-nonce (plist-get start-data :client-nonce))
         (client-first-bare (plist-get start-data :client-first-bare))
         (start-response
          (or start-response
              (mongo-command
               conn source
               (mongo--scram-start-command start-data))))
         (conversation-id (cdr (assoc "conversationId" start-response)))
         (server-first
          (mongo--scram-payload-string
           (cdr (assoc "payload" start-response)))))
    (when (eq (cdr (assoc "done" start-response)) t)
      (signal 'mongo-error
              (list "MongoDB SCRAM conversation ended before client proof")))
    (let* ((final-data
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongo--scram-sha256-client-final
                secret client-first-bare client-nonce server-first))
              ("SCRAM-SHA-1"
               (mongo--scram-sha1-client-final
                username secret client-first-bare client-nonce server-first))
              (_
               (signal 'mongo-error
                       (list (format "Unsupported MongoDB auth mechanism: %s"
                                     mechanism))))))
           (continue-response
            (mongo-command
             conn source
             `(("saslContinue" . 1)
               ("conversationId" . ,conversation-id)
               ("payload" . ,(mongo-binary
                               0
                               (mongo--utf8-bytes
                                (plist-get final-data :message)))))))
           (server-verified nil)
           (rounds 0))
      (while (and continue-response
                  (< rounds 5))
        (cl-incf rounds)
        (when-let* ((payload (cdr (assoc "payload" continue-response))))
          (let* ((server-final (mongo--scram-payload-string payload))
                 (server-final-attrs
                  (and (not (string-empty-p server-final))
                       (mongo--scram-parse-attrs server-final))))
            (when-let* ((error-text (cdr (assoc "e" server-final-attrs))))
              (signal 'mongo-error
                      (list (format "MongoDB SCRAM authentication failed: %s"
                                    error-text))))
            (when-let* ((verifier (cdr (assoc "v" server-final-attrs))))
              (unless (equal (mongo--base64-decode verifier)
                             (plist-get final-data :server-signature))
                (signal 'mongo-error
                        (list "MongoDB SCRAM server signature verification failed")))
              (setq server-verified t))))
        (if (eq (cdr (assoc "done" continue-response)) t)
            (setq continue-response nil)
          (setq continue-response
                (mongo-command
                 conn source
                 `(("saslContinue" . 1)
                   ("conversationId" . ,conversation-id)
                   ("payload" . ,(mongo-binary 0 "")))))))
      (unless server-verified
        (signal 'mongo-error
                (list "MongoDB SCRAM server signature was not returned")))
      (when continue-response
        (signal 'mongo-error
                (list "MongoDB SCRAM conversation did not complete"))))))

(defun mongo--authenticate-scram-sha256 (conn credential)
  "Authenticate CONN with CREDENTIAL using SCRAM-SHA-256."
  (mongo--authenticate-scram conn credential "SCRAM-SHA-256"))

(defun mongo--authenticate-scram-sha1 (conn credential)
  "Authenticate CONN with CREDENTIAL using SCRAM-SHA-1."
  (mongo--authenticate-scram conn credential "SCRAM-SHA-1"))

(defun mongo--authenticate-x509 (conn credential)
  "Authenticate CONN with CREDENTIAL using MONGODB-X509."
  (let ((username (mongo--credential-username credential)))
    (mongo-command
     conn
     "$external"
     `(("authenticate" . 1)
       ("mechanism" . "MONGODB-X509")
       ,@(when username
           `(("user" . ,username)))))))

(defconst mongo--aws-sts-body "Action=GetCallerIdentity&Version=2011-06-15"
  "AWS STS request body signed for MONGODB-AWS authentication.")

(defun mongo--aws-credential-field (value &rest keys)
  "Return the first field named by KEYS from AWS credential VALUE."
  (catch 'found
    (dolist (key keys)
      (cond
       ((and (listp value)
             (symbolp key)
             (plist-member value key))
        (throw 'found (plist-get value key)))
       ((and (listp value)
             (assoc key value))
        (throw 'found (cdr (assoc key value))))))
    nil))

(defun mongo--aws-expiration-time (value)
  "Return AWS credential expiration VALUE as float time, or nil."
  (when (mongo--nonempty-string value)
    (condition-case err
        (float-time (date-to-time value))
      (error
       (signal 'mongo-error
               (list (format "MongoDB MONGODB-AWS credential expiration is invalid: %s"
                             (error-message-string err))))))))

(defun mongo--aws-normalize-credentials (value context &optional require-expiration)
  "Return AWS credentials from VALUE for CONTEXT.
When REQUIRE-EXPIRATION is non-nil, VALUE must include an Expiration field."
  (let* ((access-key-id
          (or (and (mongo--aws-credentials-p value)
                   (mongo--aws-credentials-access-key-id value))
              (mongo--aws-credential-field
               value :access-key-id :accessKeyId 'access-key-id 'accessKeyId
               'AccessKeyId 'access_key_id
               "AccessKeyId" "accessKeyId" "access_key_id")))
         (secret-access-key
          (or (and (mongo--aws-credentials-p value)
                   (mongo--aws-credentials-secret-access-key value))
              (mongo--aws-credential-field
               value :secret-access-key :secretAccessKey
               'secret-access-key 'secretAccessKey
               'SecretAccessKey 'secret_access_key
               "SecretAccessKey" "secretAccessKey" "secret_access_key")))
         (session-token
          (or (and (mongo--aws-credentials-p value)
                   (mongo--aws-credentials-session-token value))
              (mongo--aws-credential-field
               value :session-token :sessionToken
               'session-token 'sessionToken
               'SessionToken 'session_token 'Token 'token
               "SessionToken" "sessionToken" "Token" "token")))
         (expiration
          (or (and (mongo--aws-credentials-p value)
                   (mongo--aws-credentials-expiration value))
              (mongo--aws-expiration-time
               (mongo--aws-credential-field
                value :expiration 'expiration 'Expiration
                "Expiration" "expiration")))))
    (unless (and (mongo--nonempty-string access-key-id)
                 (mongo--nonempty-string secret-access-key))
      (signal 'mongo-error
              (list (format "MongoDB MONGODB-AWS %s did not return access key id and secret access key"
                            context))))
    (when (and require-expiration
               (not expiration))
      (signal 'mongo-error
              (list (format "MongoDB MONGODB-AWS %s did not return credential expiration"
                            context))))
    (make-mongo--aws-credentials
     :access-key-id access-key-id
     :secret-access-key secret-access-key
     :session-token session-token
     :expiration expiration)))

(defun mongo--aws-cached-credentials-valid-p (credentials)
  "Return non-nil when cached AWS CREDENTIALS are still usable."
  (and (mongo--aws-credentials-p credentials)
       (let ((expiration (mongo--aws-credentials-expiration credentials)))
         (or (not expiration)
             (> (- expiration (float-time))
                mongo--aws-credential-expiry-skew-seconds)))))

(defun mongo--aws-json-object (body context)
  "Parse BODY as AWS JSON response for CONTEXT."
  (condition-case err
      (json-parse-string body
                         :object-type 'alist
                         :array-type 'list
                         :null-object nil
                         :false-object :false)
    (json-parse-error
     (signal 'mongo-error
             (list (format "MongoDB MONGODB-AWS %s returned invalid JSON: %s"
                           context
                           (error-message-string err)))))))

(defun mongo--aws-json-field (object key)
  "Return KEY from parsed AWS JSON OBJECT."
  (cdr (or (assoc key object)
           (assoc (intern key) object))))

(defun mongo--aws-http-request (method url headers)
  "Return response body for AWS credential HTTP METHOD URL with HEADERS."
  (let ((url-request-method method)
        (url-request-extra-headers headers)
        (timeout-seconds mongo--aws-credential-timeout-seconds)
        buffer)
    (setq buffer
          (url-retrieve-synchronously
           url t t timeout-seconds))
    (unless buffer
      (signal 'mongo-error
              (list (format "MongoDB MONGODB-AWS credential request timed out: %s"
                            url))))
    (unwind-protect
        (with-current-buffer buffer
          (goto-char (point-min))
          (unless (looking-at "HTTP/[0-9.]+ \\([0-9][0-9][0-9]\\)")
            (signal 'mongo-error
                    (list "MongoDB MONGODB-AWS credential response has no HTTP status")))
          (let ((status (string-to-number (match-string 1))))
            (unless (re-search-forward "\r?\n\r?\n" nil t)
              (signal 'mongo-error
                      (list "MongoDB MONGODB-AWS credential response has no body")))
            (let ((body (decode-coding-string
                         (buffer-substring-no-properties
                          (point) (point-max))
                         'utf-8 t)))
              (unless (and (>= status 200)
                           (< status 300))
                (signal 'mongo-error
                        (list (format "MongoDB MONGODB-AWS credential request failed with HTTP %s: %s"
                                      status body))))
              body)))
      (when (buffer-live-p buffer)
        (kill-buffer buffer)))))

(defun mongo--aws-query-string (pairs)
  "Return AWS query string from PAIRS."
  (mapconcat (lambda (pair)
               (concat (url-hexify-string (car pair))
                       "="
                       (url-hexify-string (cdr pair))))
             pairs
             "&"))

(defun mongo--aws-provider-credentials (credential)
  "Return credentials from CREDENTIAL's custom AWS provider, or nil."
  (when-let* ((provider (mongo--credential-aws-credential-provider credential)))
    (unless (functionp provider)
      (signal 'mongo-error
              (list "MongoDB MONGODB-AWS :aws-credential-provider must be a function")))
    (let ((result (funcall provider
                           (list :timeout-seconds
                                 mongo--aws-credential-timeout-seconds))))
      (mongo--aws-normalize-credentials result "credential provider"))))

(defun mongo--aws-env-credentials
    (credential explicit-credentials &optional explicit-only)
  "Return explicit or environment AWS credentials for CREDENTIAL.
When EXPLICIT-ONLY is non-nil, do not consult process environment variables."
  (let* ((explicit-access-key-id
          (mongo--nonempty-string
           (mongo--credential-username credential)))
         (explicit-secret-access-key
          (mongo--nonempty-string
           (mongo--credential-password credential)))
         (access-key-id (or explicit-access-key-id
                            (and (not explicit-only)
                                 (mongo--nonempty-string
                                  (getenv "AWS_ACCESS_KEY_ID")))))
         (secret-access-key (or explicit-secret-access-key
                                (and (not explicit-only)
                                     (mongo--nonempty-string
                                      (getenv "AWS_SECRET_ACCESS_KEY")))))
         (session-token (or (mongo--nonempty-string
                             (mongo--mechanism-property
                              (mongo--credential-mechanism-properties credential)
                              "AWS_SESSION_TOKEN"))
                            (and (not explicit-credentials)
                                 (not explicit-only)
                                 (mongo--nonempty-string
                                  (getenv "AWS_SESSION_TOKEN"))))))
    (when (or access-key-id secret-access-key)
      (unless (and access-key-id secret-access-key)
        (signal 'mongo-error
                (list "MongoDB MONGODB-AWS authentication requires both AWS access key id and secret access key")))
      (make-mongo--aws-credentials
       :access-key-id access-key-id
       :secret-access-key secret-access-key
       :session-token session-token))))

(defun mongo--aws-web-identity-credentials ()
  "Return AWS credentials from AssumeRoleWithWebIdentity, or nil."
  (let ((token-file (mongo--nonempty-string
                     (getenv "AWS_WEB_IDENTITY_TOKEN_FILE")))
        (role-arn (mongo--nonempty-string
                   (getenv "AWS_ROLE_ARN"))))
    (cond
     ((or token-file role-arn)
      (unless (and token-file role-arn)
        (signal 'mongo-error
                (list "MongoDB MONGODB-AWS AssumeRoleWithWebIdentity requires AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN")))
      (let* ((token (mongo--oidc-read-token-file token-file))
             (session-name
              (or (mongo--nonempty-string
                   (getenv "AWS_ROLE_SESSION_NAME"))
                  (concat "mongo-el-"
                          (mongo--bytes-to-hex
                           (mongo--random-bytes 8)))))
             (query (mongo--aws-query-string
                     `(("Action" . "AssumeRoleWithWebIdentity")
                       ("RoleSessionName" . ,session-name)
                       ("RoleArn" . ,role-arn)
                       ("WebIdentityToken" . ,token)
                       ("Version" . "2011-06-15"))))
             (body (mongo--aws-http-request
                    "POST"
                    (concat "https://sts.amazonaws.com/?" query)
                    '(("Accept" . "application/json"))))
             (document (mongo--aws-json-object
                        body "AssumeRoleWithWebIdentity response"))
             (credentials (mongo--aws-json-field document "Credentials")))
        (mongo--aws-normalize-credentials
         credentials "AssumeRoleWithWebIdentity response" t)))
     (t nil))))

(defun mongo--aws-ecs-credentials ()
  "Return AWS credentials from ECS task metadata, or nil."
  (when-let* ((relative-uri
               (mongo--nonempty-string
                (getenv "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"))))
    (let* ((path (if (string-prefix-p "/" relative-uri)
                     relative-uri
                   (concat "/" relative-uri)))
           (body (mongo--aws-http-request
                  "GET"
                  (concat "http://169.254.170.2" path)
                  '(("Accept" . "application/json"))))
           (document (mongo--aws-json-object
                      body "ECS credentials response")))
      (mongo--aws-normalize-credentials
       document "ECS credentials response" t))))

(defun mongo--aws-ec2-credentials ()
  "Return AWS credentials from EC2 IMDSv2."
  (let* ((token (string-trim
                 (mongo--aws-http-request
                  "PUT"
                  "http://169.254.169.254/latest/api/token"
                  '(("X-aws-ec2-metadata-token-ttl-seconds" . "21600")))))
         (headers `(("X-aws-ec2-metadata-token" . ,token)))
         (role-name (string-trim
                     (mongo--aws-http-request
                      "GET"
                      "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                      headers))))
    (unless (mongo--nonempty-string role-name)
      (signal 'mongo-error
              (list "MongoDB MONGODB-AWS EC2 metadata returned no IAM role name")))
    (let* ((body (mongo--aws-http-request
                  "GET"
                  (concat
                   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                   (url-hexify-string role-name))
                  headers))
           (document (mongo--aws-json-object
                      body "EC2 credentials response")))
      (mongo--aws-normalize-credentials
       document "EC2 credentials response" t))))

(defun mongo--aws-fetch-and-cache-credentials (credential)
  "Fetch temporary AWS credentials for CREDENTIAL and cache them."
  (let ((credentials (or (mongo--aws-web-identity-credentials)
                         (mongo--aws-ecs-credentials)
                         (mongo--aws-ec2-credentials))))
    (setf (mongo--credential-aws-cached-credentials credential)
          credentials)
    credentials))

(defun mongo--aws-credentials (credential)
  "Return AWS credentials for MONGODB-AWS CREDENTIAL."
  (let* ((explicit-access-key-id
          (mongo--nonempty-string
           (mongo--credential-username credential)))
         (explicit-secret-access-key
          (mongo--nonempty-string
           (mongo--credential-password credential)))
         (explicit-credentials
          (or explicit-access-key-id explicit-secret-access-key)))
    (or (and explicit-credentials
             (mongo--aws-env-credentials credential explicit-credentials t))
        (mongo--aws-provider-credentials credential)
        (when (mongo--aws-cached-credentials-valid-p
               (mongo--credential-aws-cached-credentials credential))
          (mongo--credential-aws-cached-credentials credential))
        (mongo--aws-env-credentials credential explicit-credentials)
        (mongo--aws-fetch-and-cache-credentials credential)
        (signal 'mongo-error
                (list "MongoDB MONGODB-AWS authentication requires AWS credentials from URI/params, :aws-credential-provider, environment variables, AssumeRoleWithWebIdentity, ECS, or EC2 IMDS")))))

(defun mongo--aws-date ()
  "Return the current AWS SigV4 timestamp."
  (format-time-string "%Y%m%dT%H%M%SZ" nil t))

(defun mongo--aws-validate-sts-host (host)
  "Validate AWS STS HOST from a MONGODB-AWS server-first message."
  (unless (mongo--nonempty-string host)
    (signal 'mongo-error
            (list "MongoDB MONGODB-AWS server returned an empty STS host")))
  (when (> (length (mongo--utf8-bytes host)) 255)
    (signal 'mongo-error
            (list "MongoDB MONGODB-AWS STS host exceeds 255 bytes")))
  (when (or (string-prefix-p "." host)
            (string-suffix-p "." host)
            (string-match-p "\\.\\." host))
    (signal 'mongo-error
            (list (format "MongoDB MONGODB-AWS STS host is invalid: %s"
                          host))))
  host)

(defun mongo--aws-region (host)
  "Return AWS SigV4 region derived from STS HOST."
  (setq host (mongo--aws-validate-sts-host host))
  (cond
   ((member host '("sts.amazonaws.com" "aws.amazonaws.com"))
    "us-east-1")
   ((string-match-p "\\." host)
    (let ((region (cadr (split-string host "\\."))))
      (unless (mongo--nonempty-string region)
        (signal 'mongo-error
                (list (format "MongoDB MONGODB-AWS STS host has no region label: %s"
                              host))))
      region))
   (t "us-east-1")))

(defun mongo--aws-signing-key (secret-access-key date-stamp region)
  "Return AWS SigV4 signing key for SECRET-ACCESS-KEY, DATE-STAMP, and REGION."
  (let* ((date-key (mongo--hmac-sha256
                    (mongo--utf8-bytes (concat "AWS4" secret-access-key))
                    (mongo--utf8-bytes date-stamp)))
         (region-key (mongo--hmac-sha256
                      date-key
                      (mongo--utf8-bytes region)))
         (service-key (mongo--hmac-sha256
                       region-key
                       (mongo--utf8-bytes "sts"))))
    (mongo--hmac-sha256 service-key
                        (mongo--utf8-bytes "aws4_request"))))

(defun mongo--aws-authorization-header
    (credentials host server-nonce amz-date)
  "Return AWS SigV4 Authorization header for MONGODB-AWS."
  (let* ((host (mongo--aws-validate-sts-host host))
         (region (mongo--aws-region host))
         (date-stamp (substring amz-date 0 8))
         (scope (format "%s/%s/sts/aws4_request" date-stamp region))
         (server-nonce64 (mongo--base64-encode server-nonce))
         (session-token
          (mongo--aws-credentials-session-token credentials))
         (headers
          `(("content-length" . ,(number-to-string
                                  (length mongo--aws-sts-body)))
            ("content-type" . "application/x-www-form-urlencoded")
            ("host" . ,host)
            ("x-amz-date" . ,amz-date)
            ,@(when session-token
                `(("x-amz-security-token" . ,session-token)))
            ("x-mongodb-gs2-cb-flag" . "n")
            ("x-mongodb-server-nonce" . ,server-nonce64)))
         (_sorted (setq headers
                        (sort headers
                              (lambda (left right)
                                (string< (car left) (car right))))))
         (canonical-headers
          (mapconcat (lambda (header)
                       (format "%s:%s\n" (car header) (cdr header)))
                     headers ""))
         (signed-headers (mapconcat #'car headers ";"))
         (canonical-request
          (mapconcat
           #'identity
           (list "POST"
                 "/"
                 ""
                 canonical-headers
                 signed-headers
                 (mongo--bytes-to-hex
                  (mongo--sha256
                   (mongo--utf8-bytes mongo--aws-sts-body))))
           "\n"))
         (string-to-sign
          (mapconcat
           #'identity
           (list "AWS4-HMAC-SHA256"
                 amz-date
                 scope
                 (mongo--bytes-to-hex
                  (mongo--sha256
                   (mongo--utf8-bytes canonical-request))))
           "\n"))
         (signing-key
          (mongo--aws-signing-key
           (mongo--aws-credentials-secret-access-key credentials)
           date-stamp
           region))
         (signature
          (mongo--bytes-to-hex
           (mongo--hmac-sha256 signing-key
                               (mongo--utf8-bytes string-to-sign)))))
    (format (concat "AWS4-HMAC-SHA256 Credential=%s/%s, "
                    "SignedHeaders=%s, Signature=%s")
            (mongo--aws-credentials-access-key-id credentials)
            scope
            signed-headers
            signature)))

(defun mongo--aws-client-first-command (client-nonce)
  "Return the MONGODB-AWS saslStart command for CLIENT-NONCE."
  `(("saslStart" . 1)
    ("mechanism" . "MONGODB-AWS")
    ("payload" . ,(mongo-binary
                   0
                   (mongo--encode-document
                    `(("r" . ,(mongo-binary 0 client-nonce))
                      ("p" . ,(mongo-int32 ?n))))))
    ("autoAuthorize" . 1)))

(defun mongo--aws-server-first (response client-nonce)
  "Return decoded MONGODB-AWS server-first data from RESPONSE."
  (let* ((payload (cdr (assoc "payload" response)))
         (document
          (and payload
               (mongo--decode-document-from-string
                (mongo--binary-value-data payload))))
         (server-nonce
          (and document
               (mongo--binary-value-data
                (cdr (assoc "s" document)))))
         (host (cdr (assoc "h" document)))
         (conversation-id (cdr (assoc "conversationId" response))))
    (unless conversation-id
      (signal 'mongo-error
              (list "MongoDB MONGODB-AWS server response is missing conversationId")))
    (unless (and server-nonce
                 (= (length server-nonce) 64))
      (signal 'mongo-error
              (list "MongoDB MONGODB-AWS server nonce must be exactly 64 bytes")))
    (unless (string-prefix-p client-nonce server-nonce)
      (signal 'mongo-error
              (list "MongoDB MONGODB-AWS server nonce does not begin with the client nonce")))
    (mongo--aws-validate-sts-host host)
    (list :server-nonce server-nonce
          :host host
          :conversation-id conversation-id)))

(defun mongo--aws-client-second-command (conversation-id credentials server-first)
  "Return the MONGODB-AWS saslContinue command."
  (let* ((amz-date (mongo--aws-date))
         (server-nonce (plist-get server-first :server-nonce))
         (host (plist-get server-first :host))
         (authorization
          (mongo--aws-authorization-header
           credentials host server-nonce amz-date))
         (session-token
          (mongo--aws-credentials-session-token credentials))
         (payload
          `(("a" . ,authorization)
            ("d" . ,amz-date)
            ,@(when session-token
                `(("t" . ,session-token))))))
    `(("saslContinue" . 1)
      ("conversationId" . ,conversation-id)
      ("payload" . ,(mongo-binary
                     0
                     (mongo--encode-document payload))))))

(defun mongo--authenticate-aws (conn credential)
  "Authenticate CONN with CREDENTIAL using MONGODB-AWS."
  (condition-case err
      (let* ((credentials (mongo--aws-credentials credential))
             (client-nonce (mongo--random-bytes 32))
             (start-response
              (mongo-command
               conn
               (mongo--credential-source credential)
               (mongo--aws-client-first-command client-nonce))))
        (when (eq (cdr (assoc "done" start-response)) t)
          (signal 'mongo-error
                  (list "MongoDB MONGODB-AWS conversation ended before client signature")))
        (let* ((server-first
                (mongo--aws-server-first start-response client-nonce))
               (conversation-id (plist-get server-first :conversation-id))
               (continue-response
                (mongo-command
                 conn
                 (mongo--credential-source credential)
                 (mongo--aws-client-second-command
                  conversation-id credentials server-first))))
          (unless (eq (cdr (assoc "done" continue-response)) t)
            (signal 'mongo-error
                    (list "MongoDB MONGODB-AWS SASL authentication did not complete")))
          continue-response))
    (error
     (setf (mongo--credential-aws-cached-credentials credential) nil)
     (signal (car err) (cdr err)))))

(defun mongo--oidc-read-token-file (file)
  "Return an OIDC access token read from FILE."
  (unless (mongo--nonempty-string file)
    (signal 'mongo-error
            (list "MongoDB MONGODB-OIDC token file path is empty")))
  (condition-case err
      (with-temp-buffer
        (set-buffer-multibyte nil)
        (insert-file-contents-literally file)
        (string-trim (decode-coding-string (buffer-string) 'utf-8 t)))
    (error
     (signal 'mongo-error
             (list (format "MongoDB MONGODB-OIDC token file could not be read: %s"
                           (error-message-string err)))))))

(defun mongo--oidc-http-get (url headers)
  "Return response body for OIDC metadata GET URL with HEADERS."
  (let ((url-request-method "GET")
        (url-request-extra-headers headers)
        (timeout-seconds (/ mongo--oidc-callback-timeout-ms 1000.0))
        buffer)
    (setq buffer
          (url-retrieve-synchronously
           url t t timeout-seconds))
    (unless buffer
      (signal 'mongo-error
              (list (format "MongoDB MONGODB-OIDC metadata request timed out: %s"
                            url))))
    (unwind-protect
        (with-current-buffer buffer
          (goto-char (point-min))
          (unless (looking-at "HTTP/[0-9.]+ \\([0-9][0-9][0-9]\\)")
            (signal 'mongo-error
                    (list "MongoDB MONGODB-OIDC metadata response has no HTTP status")))
          (let ((status (string-to-number (match-string 1))))
            (unless (re-search-forward "\r?\n\r?\n" nil t)
              (signal 'mongo-error
                      (list "MongoDB MONGODB-OIDC metadata response has no body")))
            (let ((body (decode-coding-string
                         (buffer-substring-no-properties
                          (point) (point-max))
                         'utf-8 t)))
              (unless (and (>= status 200)
                           (< status 300))
                (signal 'mongo-error
                        (list (format "MongoDB MONGODB-OIDC metadata request failed with HTTP %s: %s"
                                      status body))))
              body)))
      (when (buffer-live-p buffer)
        (kill-buffer buffer)))))

(defun mongo--oidc-json-object (body context)
  "Parse BODY as a JSON object for CONTEXT."
  (condition-case err
      (json-parse-string body
                         :object-type 'alist
                         :array-type 'list
                         :null-object nil
                         :false-object :false)
    (json-parse-error
     (signal 'mongo-error
             (list (format "MongoDB MONGODB-OIDC %s returned invalid JSON: %s"
                           context
                           (error-message-string err)))))))

(defun mongo--oidc-json-field (object key)
  "Return KEY from parsed JSON OBJECT."
  (cdr (or (assoc key object)
           (assoc (intern key) object))))

(defun mongo--oidc-resource-query (credential key)
  "Return OIDC metadata query parameter KEY for CREDENTIAL's TOKEN_RESOURCE."
  (let ((resource
         (mongo--oidc-token-resource
          (mongo--credential-mechanism-properties credential))))
    (concat key "=" (url-hexify-string resource))))

(defun mongo--oidc-azure-token (credential)
  "Return an access token from Azure IMDS for CREDENTIAL."
  (let* ((query (mongo--oidc-resource-query credential "resource"))
         (username (mongo--nonempty-string
                    (mongo--credential-username credential)))
         (url (concat
               "http://169.254.169.254/metadata/identity/oauth2/token"
               "?api-version=2018-02-01&"
               query
               (when username
                 (concat "&client_id="
                         (url-hexify-string username)))))
         (body (mongo--oidc-http-get
                url
                '(("Accept" . "application/json")
                  ("Metadata" . "true"))))
         (document (mongo--oidc-json-object body "Azure metadata endpoint"))
         (token (mongo--oidc-json-field document "access_token")))
    (unless (mongo--nonempty-string token)
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC Azure metadata response is missing access_token")))
    token))

(defun mongo--oidc-gcp-token (credential)
  "Return an access token from GCP metadata service for CREDENTIAL."
  (let* ((url (concat
               "http://metadata/computeMetadata/v1/instance/"
               "service-accounts/default/identity?"
               (mongo--oidc-resource-query credential "audience")))
         (body (mongo--oidc-http-get
                url
                '(("Metadata-Flavor" . "Google"))))
         (token (string-trim body)))
    (unless (mongo--nonempty-string token)
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC GCP metadata response is empty")))
    token))

(defun mongo--oidc-callback-result-field (result &rest keys)
  "Return the first field named by KEYS from OIDC callback RESULT."
  (catch 'found
    (dolist (key keys)
      (cond
       ((and (listp result)
             (symbolp key)
             (plist-member result key))
        (throw 'found (plist-get result key)))
       ((and (listp result)
             (assoc key result))
        (throw 'found (cdr (assoc key result))))))
    nil))

(defun mongo--oidc-callback-result-access-token (result)
  "Return an access token from OIDC callback RESULT, or nil."
  (if (stringp result)
      result
    (mongo--oidc-callback-result-field
     result :access-token :accessToken 'access-token 'accessToken
     "accessToken" "access_token")))

(defun mongo--oidc-callback-result-refresh-token (result)
  "Return a refresh token from OIDC callback RESULT, or nil."
  (mongo--oidc-callback-result-field
   result :refresh-token :refreshToken 'refresh-token 'refreshToken
   "refreshToken" "refresh_token"))

(defun mongo--oidc-callback-token (credential)
  "Return an OIDC access token from CREDENTIAL's callback."
  (when-let* ((callback (mongo--credential-oidc-callback credential)))
    (unless (functionp callback)
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC callback must be a function")))
    (let* ((result (funcall callback
                            (list :timeout-ms mongo--oidc-callback-timeout-ms
                                  :username
                                  (mongo--credential-username credential)
                                  :version 1)))
           (token (mongo--oidc-callback-result-access-token result)))
      (unless (mongo--nonempty-string token)
        (signal 'mongo-error
                (list "MongoDB MONGODB-OIDC callback did not return an access token")))
      token)))

(defun mongo--oidc-human-callback-token (credential idp-info)
  "Return an OIDC access token from CREDENTIAL's human callback."
  (let ((callback (mongo--credential-oidc-human-callback credential)))
    (unless (functionp callback)
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC human callback must be a function")))
    (let* ((result (funcall callback
                            (list :timeout-ms mongo--oidc-callback-timeout-ms
                                  :username
                                  (mongo--credential-username credential)
                                  :version 1
                                  :idp-info idp-info
                                  :refresh-token
                                  (mongo--credential-oidc-refresh-token
                                   credential))))
           (token (mongo--oidc-callback-result-access-token result))
           (refresh-token
            (mongo--oidc-callback-result-refresh-token result)))
      (unless (mongo--nonempty-string token)
        (signal 'mongo-error
                (list "MongoDB MONGODB-OIDC human callback did not return an access token")))
      (when (mongo--nonempty-string refresh-token)
        (setf (mongo--credential-oidc-refresh-token credential)
              refresh-token))
      token)))

(defun mongo--oidc-k8s-token-file ()
  "Return the Kubernetes OIDC token file path from the standard environment."
  (or (mongo--nonempty-string (getenv "AZURE_FEDERATED_TOKEN_FILE"))
      (mongo--nonempty-string (getenv "AWS_WEB_IDENTITY_TOKEN_FILE"))
      "/var/run/secrets/kubernetes.io/serviceaccount/token"))

(defun mongo--oidc-environment-token (credential)
  "Return an OIDC access token from CREDENTIAL's ENVIRONMENT, or nil."
  (when-let* ((environment
               (mongo--oidc-mechanism-environment
                (mongo--credential-mechanism-properties credential))))
    (pcase environment
      ("k8s"
       (mongo--oidc-read-token-file
        (mongo--oidc-k8s-token-file)))
      ("test"
       (mongo--oidc-read-token-file
        (or (mongo--nonempty-string (getenv "OIDC_TOKEN_FILE"))
            (signal 'mongo-error
                    (list "MongoDB MONGODB-OIDC ENVIRONMENT:test requires OIDC_TOKEN_FILE")))))
      ("azure"
       (mongo--oidc-azure-token credential))
      ("gcp"
       (mongo--oidc-gcp-token credential))
      (_
       (signal 'mongo-error
               (list (format "Unsupported MongoDB MONGODB-OIDC ENVIRONMENT: %s"
                             environment)))))))

(defun mongo--oidc-one-step-token (credential)
  "Return an OIDC one-step access token for CREDENTIAL, or nil."
  (or (mongo--nonempty-string
       (mongo--credential-oidc-token credential))
      (when-let* ((file (mongo--credential-oidc-token-file credential)))
        (mongo--oidc-read-token-file file))
      (mongo--oidc-environment-token credential)
      (mongo--oidc-callback-token credential)))

(defun mongo--oidc-token (credential)
  "Return the OIDC access token for CREDENTIAL."
  (let ((token (mongo--oidc-one-step-token credential)))
    (unless (mongo--nonempty-string token)
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC authentication requires :oidc-token, :oidc-token-file, :oidc-callback, :oidc-human-callback, or ENVIRONMENT:k8s/test/azure/gcp token configuration")))
    token))

(defun mongo--oidc-start-command (token)
  "Return a MongoDB MONGODB-OIDC one-step saslStart command for TOKEN."
  `(("saslStart" . 1)
    ("mechanism" . "MONGODB-OIDC")
    ("payload" . ,(mongo-binary
                   0
                   (mongo--encode-document
                    `(("jwt" . ,token)))))
    ("autoAuthorize" . 1)))

(defun mongo--oidc-principal-start-command (credential)
  "Return a MONGODB-OIDC two-step saslStart command for CREDENTIAL."
  `(("saslStart" . 1)
    ("mechanism" . "MONGODB-OIDC")
    ("payload" . ,(mongo-binary
                   0
                   (mongo--encode-document
                    `(,@(when (mongo--credential-username credential)
                          `(("n" . ,(mongo--credential-username
                                      credential))))))))
    ("autoAuthorize" . 1)))

(defun mongo--oidc-continue-command (conversation-id token)
  "Return a MONGODB-OIDC saslContinue command for TOKEN."
  `(("saslContinue" . 1)
    ("conversationId" . ,conversation-id)
    ("payload" . ,(mongo-binary
                   0
                   (mongo--encode-document
                    `(("jwt" . ,token)))))))

(defun mongo--oidc-response-payload-document (response)
  "Return decoded BSON payload document from OIDC RESPONSE."
  (when-let* ((payload (cdr (assoc "payload" response))))
    (mongo--decode-document-from-string
     (mongo--binary-value-data payload))))

(defun mongo--oidc-normalize-idp-info (idp-info)
  "Return IDP-INFO with array fields normalized for callbacks."
  (mapcar
   (lambda (pair)
     (if (and (consp pair)
              (equal (car pair) "requestScopes")
              (not (vectorp (cdr pair)))
              (listp (cdr pair)))
         (cons "requestScopes" (vconcat (cdr pair)))
       pair))
   idp-info))

(defun mongo--oidc-idp-info (credential response)
  "Return IdPInfo from OIDC two-step RESPONSE and cache it on CREDENTIAL."
  (let* ((conversation-id (cdr (assoc "conversationId" response)))
         (raw-idp-info (mongo--oidc-response-payload-document response))
         (idp-info (and raw-idp-info
                        (mongo--oidc-normalize-idp-info raw-idp-info))))
    (unless conversation-id
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC server response is missing conversationId")))
    (unless idp-info
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC server response is missing IdPInfo payload")))
    (unless (cdr (assoc "issuer" idp-info))
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC IdPInfo is missing issuer")))
    (setf (mongo--credential-oidc-idp-info credential) idp-info)
    (list :conversation-id conversation-id
          :idp-info idp-info)))

(defun mongo--oidc-normalize-host (host)
  "Return HOST normalized for MONGODB-OIDC allowed-host matching."
  (when host
    (let ((normalized (downcase (format "%s" host))))
      (when (and (string-prefix-p "[" normalized)
                 (string-suffix-p "]" normalized))
        (setq normalized (substring normalized 1 -1)))
      (string-remove-suffix "." normalized))))

(defun mongo--oidc-host-matches-allowed-p (host allowed)
  "Return non-nil when HOST matches one ALLOWED host pattern."
  (let ((host (mongo--oidc-normalize-host host))
        (allowed (mongo--oidc-normalize-host allowed)))
    (cond
     ((not (and host allowed)) nil)
     ((string-prefix-p "*." allowed)
      (let ((suffix (substring allowed 1)))
        (and (> (length host) (length suffix))
             (string-suffix-p suffix host))))
     (t
      (equal host allowed)))))

(defun mongo--oidc-allowed-host-p (host allowed-hosts)
  "Return non-nil when HOST is allowed for a human OIDC callback."
  (seq-some (lambda (allowed)
              (mongo--oidc-host-matches-allowed-p host allowed))
            (or allowed-hosts mongo--oidc-default-allowed-hosts)))

(defun mongo--validate-oidc-human-callback-host (conn credential)
  "Validate CONN host before invoking CREDENTIAL's human OIDC callback."
  (when (mongo-conn-p conn)
    (let ((host (mongo-conn-host conn)))
      (unless (mongo--oidc-allowed-host-p
               host
               (mongo--credential-oidc-allowed-hosts credential))
        (signal 'mongo-error
                (list (format "MongoDB MONGODB-OIDC human callback is not allowed for host %s; configure :oidc-allowed-hosts if this host is expected"
                              (or host "<unknown>"))))))))

(defun mongo--authenticate-oidc-two-step (conn credential)
  "Authenticate CONN with CREDENTIAL using two-step MONGODB-OIDC."
  (let* ((start-response
          (mongo-command
           conn
           (mongo--credential-source credential)
           (mongo--oidc-principal-start-command credential)))
         (server-first (mongo--oidc-idp-info credential start-response))
         (conversation-id (plist-get server-first :conversation-id))
         (idp-info (plist-get server-first :idp-info))
         (token (mongo--oidc-human-callback-token credential idp-info))
         (continue-response
          (mongo-command
           conn
           (mongo--credential-source credential)
           (mongo--oidc-continue-command conversation-id token))))
    (unless (eq (cdr (assoc "done" continue-response)) t)
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC two-step conversation did not complete")))
    continue-response))

(defun mongo--authenticate-oidc (conn credential)
  "Authenticate CONN with CREDENTIAL using MONGODB-OIDC."
  (if-let* ((token (mongo--oidc-one-step-token credential)))
      (let ((response
             (mongo-command
              conn
              (mongo--credential-source credential)
              (mongo--oidc-start-command token))))
        (unless (eq (cdr (assoc "done" response)) t)
          (signal 'mongo-error
                  (list "MongoDB MONGODB-OIDC one-step conversation did not complete")))
        response)
    (if (mongo--credential-oidc-human-callback credential)
        (progn
          (mongo--validate-oidc-human-callback-host conn credential)
          (mongo--authenticate-oidc-two-step conn credential))
      (mongo--oidc-token credential))))

(defun mongo--plain-payload (credential)
  "Return the SASL PLAIN payload for CREDENTIAL."
  (mongo--utf8-bytes
   (concat "\0"
           (mongo--credential-username credential)
           "\0"
           (mongo--credential-password credential))))

(defun mongo--plain-start-command (credential)
  "Return a MongoDB saslStart command for PLAIN CREDENTIAL."
  `(("saslStart" . 1)
    ("mechanism" . "PLAIN")
    ("payload" . ,(mongo-binary 0 (mongo--plain-payload credential)))
    ("autoAuthorize" . 1)))

(defun mongo--authenticate-plain (conn credential)
  "Authenticate CONN with CREDENTIAL using PLAIN SASL."
  (let ((response
         (mongo-command
          conn
          (mongo--credential-source credential)
          (mongo--plain-start-command credential))))
    (unless (eq (cdr (assoc "done" response)) t)
      (signal 'mongo-error
              (list "MongoDB PLAIN SASL authentication did not complete")))
    response))

(defun mongo--authenticate (conn credential hello &optional speculative-auth)
  "Authenticate CONN with CREDENTIAL using data from HELLO.
SPECULATIVE-AUTH is the SCRAM start data sent in the initial handshake."
  (let ((speculative-response (cdr (assoc "speculativeAuthenticate" hello))))
    (if (and speculative-auth
             speculative-response
             (assoc "payload" speculative-response))
        (mongo--authenticate-scram
         conn credential
         (plist-get speculative-auth :mechanism)
         speculative-auth speculative-response)
      (pcase (mongo--choose-auth-mechanism credential hello)
        ("SCRAM-SHA-256"
         (mongo--authenticate-scram-sha256 conn credential))
        ("SCRAM-SHA-1"
         (mongo--authenticate-scram-sha1 conn credential))
        ("MONGODB-X509"
         (mongo--authenticate-x509 conn credential))
        ("PLAIN"
         (mongo--authenticate-plain conn credential))
        ("MONGODB-AWS"
         (mongo--authenticate-aws conn credential))
        ("MONGODB-OIDC"
         (mongo--authenticate-oidc conn credential))
        (mechanism
         (signal 'mongo-error
                 (list (format "Unsupported MongoDB auth mechanism: %s"
                               mechanism))))))))

(provide 'mongo-auth)

;;; mongo-auth.el ends here
