;;; mongodb-auth.el --- Authentication mechanisms -*- lexical-binding: t; -*-

;; Copyright (C) 2025-2026 Lucius Chen
;; SPDX-License-Identifier: GPL-3.0-or-later

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

;; Native MongoDB authentication mechanisms and related token helpers.

;;; Code:

(require 'cl-lib)
(require 'json)
(require 'mongodb-bson)
(require 'mongodb-params)
(require 'parse-time)
(require 'seq)
(require 'subr-x)
(require 'ucs-normalize)
(require 'url)
(require 'url-util)

(declare-function mongodb-command "mongodb" (conn database command &optional timeout sequences))
(declare-function mongodb-conn-host "mongodb" (conn))
(declare-function mongodb-conn-p "mongodb" (object))

(cl-defstruct mongodb--aws-credentials
  access-key-id
  secret-access-key
  session-token
  expiration)

;;;; Authentication

(defconst mongodb--scram-auth-mechanisms
  '("SCRAM-SHA-256" "SCRAM-SHA-1"))

(defconst mongodb--supported-auth-mechanisms
  (append mongodb--scram-auth-mechanisms
          '("MONGODB-X509" "PLAIN" "MONGODB-AWS" "MONGODB-OIDC")))

(defconst mongodb--saslprep-map-to-nothing-ranges
  '((#x00AD . #x00AD)
    (#x034F . #x034F)
    (#x1806 . #x1806)
    (#x180B . #x180D)
    (#x200B . #x200D)
    (#x2060 . #x2060)
    (#xFE00 . #xFE0F)
    (#xFEFF . #xFEFF))
  "RFC 3454 table B.1 characters mapped to nothing by SASLprep.")

(defconst mongodb--saslprep-space-ranges
  '((#x00A0 . #x00A0)
    (#x1680 . #x1680)
    (#x2000 . #x200A)
    (#x202F . #x202F)
    (#x205F . #x205F)
    (#x3000 . #x3000))
  "RFC 3454 table C.1.2 space characters mapped to ASCII space.")

(defconst mongodb--saslprep-prohibited-ranges
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

(defun mongodb--choose-auth-mechanism (credential hello)
  "Return the auth mechanism to use for CREDENTIAL from HELLO."
  (let ((mechanism
         (mongodb--normalize-auth-mechanism
          (mongodb--credential-mechanism credential)))
        (supported (cdr (assoc "saslSupportedMechs" hello))))
    (cond
     (mechanism
      (unless (member mechanism mongodb--supported-auth-mechanisms)
        (signal 'mongodb-error
                (list (format "Native MongoDB authentication supports SCRAM-SHA-256, SCRAM-SHA-1, MONGODB-X509, PLAIN, MONGODB-AWS, and MONGODB-OIDC, not %s"
                              mechanism))))
      (when (and (member mechanism mongodb--scram-auth-mechanisms)
                 supported
                 (not (member mechanism supported)))
        (signal 'mongodb-error
                (list (format "MongoDB server/user does not report support for %s"
                              mechanism))))
      mechanism)
     ((member "SCRAM-SHA-256" supported)
      "SCRAM-SHA-256")
     ((member "SCRAM-SHA-1" supported)
      "SCRAM-SHA-1")
     (supported
      (signal 'mongodb-error
              (list "Native MongoDB authentication requires SCRAM-SHA-256 or SCRAM-SHA-1 support from the server/user")))
     (t
      "SCRAM-SHA-1"))))

(defun mongodb--codepoint-in-ranges-p (codepoint ranges)
  "Return non-nil when CODEPOINT is included in RANGES."
  (cl-some (lambda (range)
             (and (<= (car range) codepoint)
                  (<= codepoint (cdr range))))
           ranges))

(defun mongodb--saslprep-map-char (char)
  "Return SASLprep-mapped CHAR, or nil when CHAR maps to nothing."
  (cond
   ((mongodb--codepoint-in-ranges-p
     char mongodb--saslprep-map-to-nothing-ranges)
    nil)
   ((mongodb--codepoint-in-ranges-p char mongodb--saslprep-space-ranges)
    ?\s)
   (t
    char)))

(defun mongodb--saslprep-non-character-codepoint-p (char)
  "Return non-nil when CHAR is a Unicode non-character code point."
  (or (and (<= #xFDD0 char)
           (<= char #xFDEF))
      (and (<= 0 char)
           (<= char #x10FFFF)
           (let ((low (logand char #xFFFF)))
             (or (= low #xFFFE)
                 (= low #xFFFF))))))

(defun mongodb--saslprep-prohibited-p (char)
  "Return non-nil when CHAR is prohibited by SASLprep."
  (or (mongodb--codepoint-in-ranges-p
       char mongodb--saslprep-prohibited-ranges)
      (mongodb--saslprep-non-character-codepoint-p char)))

(defun mongodb--saslprep-randal-p (char)
  "Return non-nil when CHAR is in RFC 3454 RandALCat."
  (memq (get-char-code-property char 'bidi-class) '(R AL)))

(defun mongodb--saslprep-lcat-p (char)
  "Return non-nil when CHAR is in RFC 3454 LCat."
  (eq (get-char-code-property char 'bidi-class) 'L))

(defun mongodb--saslprep (string)
  "Prepare STRING with the SASLprep profile used by MongoDB SCRAM-SHA-256."
  (let* ((mapped-chars
          (cl-loop for char across string
                   for mapped = (mongodb--saslprep-map-char char)
                   when mapped collect mapped))
         (normalized
          (ucs-normalize-NFKC-string
           (mapconcat #'char-to-string mapped-chars "")))
         (has-randal nil)
         (has-lcat nil))
    (cl-loop for char across normalized
             do
             (when (mongodb--saslprep-prohibited-p char)
               (signal 'mongodb-error
                       (list (format "MongoDB SCRAM password contains a prohibited SASLprep character: U+%04X"
                                     char))))
             (when (mongodb--saslprep-randal-p char)
               (setq has-randal t))
             (when (mongodb--saslprep-lcat-p char)
               (setq has-lcat t)))
    (when has-randal
      (when has-lcat
        (signal 'mongodb-error
                (list "MongoDB SCRAM password violates SASLprep bidirectional text rules")))
      (unless (and (> (length normalized) 0)
                   (mongodb--saslprep-randal-p (aref normalized 0))
                   (mongodb--saslprep-randal-p
                    (aref normalized (1- (length normalized)))))
        (signal 'mongodb-error
                (list "MongoDB SCRAM password violates SASLprep bidirectional text rules"))))
    normalized))

(defun mongodb--scram-password-bytes (secret)
  "Return SASLprep-normalized SECRET bytes for SCRAM-SHA-256."
  (mongodb--utf8-bytes (mongodb--saslprep secret)))

(defun mongodb--scram-sha1-password-bytes (username secret)
  "Return MongoDB SCRAM-SHA-1 password digest bytes for USERNAME and SECRET."
  (mongodb--utf8-bytes
   (secure-hash
    'md5
    (mongodb--utf8-bytes
     (format "%s:mongodb:%s" username secret)))))

(defvar mongodb--random-seeded nil
  "Non-nil after `random' has been seeded for MongoDB nonce generation.")

(defun mongodb--random-bytes (count)
  "Return COUNT random bytes."
  (unless mongodb--random-seeded
    (random t)
    (setq mongodb--random-seeded t))
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

(defun mongodb--scram-client-nonce ()
  "Return a printable SCRAM client nonce."
  (mongodb--base64-encode (mongodb--random-bytes 24)))

(defun mongodb--uuid-v4-bytes ()
  "Return a locally generated RFC 4122 version 4 UUID as 16 bytes."
  (let ((bytes (copy-sequence (mongodb--random-bytes 16))))
    (aset bytes 6 (logior #x40 (logand (aref bytes 6) #x0f)))
    (aset bytes 8 (logior #x80 (logand (aref bytes 8) #x3f)))
    bytes))

(defvar mongodb--object-id-random nil
  "Five process-random bytes used when generating MongoDB ObjectIds.")

(defvar mongodb--object-id-counter nil
  "Three-byte counter used when generating MongoDB ObjectIds.")

(defun mongodb--uint24-value (bytes)
  "Return the unsigned 24-bit integer represented by BYTES."
  (logior (ash (aref bytes 0) 16)
          (ash (aref bytes 1) 8)
          (aref bytes 2)))

(defun mongodb--pack-uint24-be (value)
  "Return VALUE packed as unsigned big-endian uint24."
  (unibyte-string
   (logand (ash value -16) #xff)
   (logand (ash value -8) #xff)
   (logand value #xff)))

(defun mongodb-new-object-id (&optional time)
  "Return a newly generated MongoDB ObjectId.
TIME, when non-nil, supplies the timestamp component."
  (unless mongodb--object-id-random
    (setq mongodb--object-id-random (mongodb--random-bytes 5)))
  (unless mongodb--object-id-counter
    (setq mongodb--object-id-counter
          (mongodb--uint24-value (mongodb--random-bytes 3))))
  (let* ((seconds (logand (floor (float-time (or time (current-time))))
                          #xffffffff))
         (counter mongodb--object-id-counter)
         (bytes (concat
                 (mongodb--pack-uint32-be seconds)
                 mongodb--object-id-random
                 (mongodb--pack-uint24-be counter))))
    (setq mongodb--object-id-counter
          (mod (1+ mongodb--object-id-counter) #x1000000))
    (mongodb-object-id (mongodb--bytes-to-hex bytes))))

(defun mongodb--make-session-id ()
  "Return a MongoDB logical session id document."
  `(("id" . ,(mongodb-binary 4 (mongodb--uuid-v4-bytes)))))

(defun mongodb--scram-escape-name (name)
  "Return SCRAM escaped NAME."
  (replace-regexp-in-string
   "," "=2C"
   (replace-regexp-in-string "=" "=3D" name t t)
   t t))

(defun mongodb--scram-parse-attrs (message)
  "Parse a SCRAM MESSAGE into an alist of attribute strings."
  (let (attrs)
    (dolist (part (split-string message "," t))
      (unless (string-match "\\`\\([^=]+\\)=\\(.*\\)\\'" part)
        (signal 'mongodb-error
                (list (format "Invalid MongoDB SCRAM message: %S" message))))
      (push (cons (match-string 1 part)
                  (match-string 2 part))
            attrs))
    (nreverse attrs)))

(defun mongodb--scram-payload-string (payload)
  "Return SCRAM PAYLOAD decoded as a UTF-8 string."
  (cond
   ((stringp payload)
    payload)
   (t
    (decode-coding-string
     (mongodb--binary-value-data payload)
     'utf-8 t))))

(defun mongodb--scram-start-data (credential mechanism)
  "Return SCRAM client-first data for CREDENTIAL and MECHANISM."
  (let* ((username (mongodb--credential-username credential))
         (source (mongodb--credential-source credential))
         (client-nonce (mongodb--scram-client-nonce))
         (client-first-bare
          (format "n=%s,r=%s"
                  (mongodb--scram-escape-name username)
                  client-nonce))
         (client-first (concat "n,," client-first-bare)))
    (list :mechanism mechanism
          :source source
          :username username
          :client-nonce client-nonce
          :client-first-bare client-first-bare
          :client-first client-first)))

(defun mongodb--scram-start-command (start-data &optional include-db)
  "Return a MongoDB saslStart command from START-DATA.
When INCLUDE-DB is non-nil, include the auth database as a top-level db field
for speculative authentication."
  `(("saslStart" . 1)
    ("mechanism" . ,(plist-get start-data :mechanism))
    ("options" . (("skipEmptyExchange" . t)))
    ("payload" . ,(mongodb-binary
                   0
                   (mongodb--utf8-bytes
                    (plist-get start-data :client-first))))
    ,@(when include-db
        `(("db" . ,(plist-get start-data :source))))
    ("autoAuthorize" . 1)))

(defun mongodb--credential-scram-negotiation-p (credential)
  "Return non-nil when CREDENTIAL should request saslSupportedMechs."
  (when credential
    (let ((mechanism (mongodb--normalize-auth-mechanism
                      (mongodb--credential-mechanism credential))))
      (or (null mechanism)
          (member mechanism mongodb--scram-auth-mechanisms)))))

(defun mongodb--speculative-auth-state (credential)
  "Return SCRAM speculative authentication state for CREDENTIAL, or nil."
  (when credential
    (let ((mechanism (or (mongodb--normalize-auth-mechanism
                          (mongodb--credential-mechanism credential))
                         "SCRAM-SHA-256")))
      (when (member mechanism mongodb--scram-auth-mechanisms)
        (mongodb--scram-start-data credential mechanism)))))

(defun mongodb--scram-client-final
    (mechanism username secret client-first-bare client-nonce server-first-message)
  "Return SCRAM final data for MECHANISM and SERVER-FIRST-MESSAGE.
The returned plist contains :message, :server-signature, and :server-nonce.

Arguments: MECHANISM, USERNAME, SECRET, CLIENT-FIRST-BARE, CLIENT-NONCE,
SERVER-FIRST-MESSAGE."
  (let* ((attrs (mongodb--scram-parse-attrs server-first-message))
         (server-nonce (cdr (assoc "r" attrs)))
         (salt64 (cdr (assoc "s" attrs)))
         (iterations-text (cdr (assoc "i" attrs)))
         (iterations (and iterations-text
                          (string-to-number iterations-text))))
    (unless (and server-nonce
                 (string-prefix-p client-nonce server-nonce))
      (signal 'mongodb-error
              (list "MongoDB SCRAM server nonce does not extend client nonce")))
    (unless salt64
      (signal 'mongodb-error
              (list "MongoDB SCRAM server message is missing salt")))
    (unless (and iterations
                 (>= iterations 4096))
      (signal 'mongodb-error
              (list "MongoDB SCRAM server message has invalid iteration count")))
    (let* ((salt (mongodb--base64-decode salt64))
           (client-final-without-proof
            (format "c=biws,r=%s" server-nonce))
           (auth-message
            (mongodb--utf8-bytes
             (mapconcat #'identity
                        (list client-first-bare
                              server-first-message
                              client-final-without-proof)
                        ",")))
           (salted-password
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongodb--pbkdf2-hmac-sha256
                (mongodb--scram-password-bytes secret)
                salt
                iterations))
              ("SCRAM-SHA-1"
               (mongodb--pbkdf2-hmac-sha1
                (mongodb--scram-sha1-password-bytes username secret)
                salt
                iterations))
              (_
               (signal 'mongodb-error
                       (list (format "Unsupported MongoDB auth mechanism: %s"
                                     mechanism))))))
           (client-key
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongodb--hmac-sha256 salted-password
                                   (mongodb--utf8-bytes "Client Key")))
              ("SCRAM-SHA-1"
               (mongodb--hmac-sha1 salted-password
                                  (mongodb--utf8-bytes "Client Key")))))
           (stored-key
            (pcase mechanism
              ("SCRAM-SHA-256" (mongodb--sha256 client-key))
              ("SCRAM-SHA-1" (mongodb--sha1 client-key))))
           (client-signature
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongodb--hmac-sha256 stored-key auth-message))
              ("SCRAM-SHA-1"
               (mongodb--hmac-sha1 stored-key auth-message))))
           (client-proof
            (mongodb--xor-bytes client-key client-signature))
           (server-key
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongodb--hmac-sha256 salted-password
                                   (mongodb--utf8-bytes "Server Key")))
              ("SCRAM-SHA-1"
               (mongodb--hmac-sha1 salted-password
                                  (mongodb--utf8-bytes "Server Key")))))
           (server-signature
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongodb--hmac-sha256 server-key auth-message))
              ("SCRAM-SHA-1"
               (mongodb--hmac-sha1 server-key auth-message)))))
      (list :message
            (format "%s,p=%s"
                    client-final-without-proof
                    (mongodb--base64-encode client-proof))
            :server-signature server-signature
            :server-nonce server-nonce))))

(defun mongodb--scram-sha256-client-final
    (secret client-first-bare client-nonce server-first-message)
  "Return SCRAM-SHA-256 final data for SERVER-FIRST-MESSAGE.

Arguments: SECRET, CLIENT-FIRST-BARE, CLIENT-NONCE, SERVER-FIRST-MESSAGE."
  (mongodb--scram-client-final
   "SCRAM-SHA-256" nil secret client-first-bare client-nonce
   server-first-message))

(defun mongodb--scram-sha1-client-final
    (username secret client-first-bare client-nonce server-first-message)
  "Return SCRAM-SHA-1 final data for SERVER-FIRST-MESSAGE.

Arguments: USERNAME, SECRET, CLIENT-FIRST-BARE, CLIENT-NONCE,
SERVER-FIRST-MESSAGE."
  (mongodb--scram-client-final
   "SCRAM-SHA-1" username secret client-first-bare client-nonce
   server-first-message))

(defun mongodb--authenticate-scram
    (conn credential mechanism &optional start-data start-response)
  "Authenticate CONN with CREDENTIAL using SCRAM MECHANISM.
START-DATA and START-RESPONSE, when non-nil, continue a speculative
authentication exchange started in the initial handshake."
  (let* ((start-data (or start-data
                         (mongodb--scram-start-data credential mechanism)))
         (username (mongodb--credential-username credential))
         (secret (mongodb--credential-password credential))
         (source (mongodb--credential-source credential))
         (client-nonce (plist-get start-data :client-nonce))
         (client-first-bare (plist-get start-data :client-first-bare))
         (start-response
          (or start-response
              (mongodb-command
               conn source
               (mongodb--scram-start-command start-data))))
         (conversation-id (cdr (assoc "conversationId" start-response)))
         (server-first
          (mongodb--scram-payload-string
           (cdr (assoc "payload" start-response)))))
    (when (eq (cdr (assoc "done" start-response)) t)
      (signal 'mongodb-error
              (list "MongoDB SCRAM conversation ended before client proof")))
    (let* ((final-data
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongodb--scram-sha256-client-final
                secret client-first-bare client-nonce server-first))
              ("SCRAM-SHA-1"
               (mongodb--scram-sha1-client-final
                username secret client-first-bare client-nonce server-first))
              (_
               (signal 'mongodb-error
                       (list (format "Unsupported MongoDB auth mechanism: %s"
                                     mechanism))))))
           (continue-response
            (mongodb-command
             conn source
             `(("saslContinue" . 1)
               ("conversationId" . ,conversation-id)
               ("payload" . ,(mongodb-binary
                               0
                               (mongodb--utf8-bytes
                                (plist-get final-data :message)))))))
           (server-verified nil)
           (rounds 0))
      (while (and continue-response
                  (< rounds 5))
        (cl-incf rounds)
        (when-let* ((payload (cdr (assoc "payload" continue-response))))
          (let* ((server-final (mongodb--scram-payload-string payload))
                 (server-final-attrs
                  (and (not (string-empty-p server-final))
                       (mongodb--scram-parse-attrs server-final))))
            (when-let* ((error-text (cdr (assoc "e" server-final-attrs))))
              (signal 'mongodb-error
                      (list (format "MongoDB SCRAM authentication failed: %s"
                                    error-text))))
            (when-let* ((verifier (cdr (assoc "v" server-final-attrs))))
              (unless (equal (mongodb--base64-decode verifier)
                             (plist-get final-data :server-signature))
                (signal 'mongodb-error
                        (list "MongoDB SCRAM server signature verification failed")))
              (setq server-verified t))))
        (if (eq (cdr (assoc "done" continue-response)) t)
            (setq continue-response nil)
          (setq continue-response
                (mongodb-command
                 conn source
                 `(("saslContinue" . 1)
                   ("conversationId" . ,conversation-id)
                   ("payload" . ,(mongodb-binary 0 "")))))))
      (unless server-verified
        (signal 'mongodb-error
                (list "MongoDB SCRAM server signature was not returned")))
      (when continue-response
        (signal 'mongodb-error
                (list "MongoDB SCRAM conversation did not complete"))))))

(defun mongodb--authenticate-scram-sha256 (conn credential)
  "Authenticate CONN with CREDENTIAL using SCRAM-SHA-256."
  (mongodb--authenticate-scram conn credential "SCRAM-SHA-256"))

(defun mongodb--authenticate-scram-sha1 (conn credential)
  "Authenticate CONN with CREDENTIAL using SCRAM-SHA-1."
  (mongodb--authenticate-scram conn credential "SCRAM-SHA-1"))

(defun mongodb--authenticate-x509 (conn credential)
  "Authenticate CONN with CREDENTIAL using MONGODB-X509."
  (let ((username (mongodb--credential-username credential)))
    (mongodb-command
     conn
     "$external"
     `(("authenticate" . 1)
       ("mechanism" . "MONGODB-X509")
       ,@(when username
           `(("user" . ,username)))))))

(defconst mongodb--aws-sts-body "Action=GetCallerIdentity&Version=2011-06-15"
  "AWS STS request body signed for MONGODB-AWS authentication.")

(defun mongodb--aws-credential-field (value &rest keys)
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

(defun mongodb--aws-expiration-time (value)
  "Return AWS credential expiration VALUE as float time, or nil."
  (when (mongodb--nonempty-string value)
    (condition-case err
        (float-time (date-to-time value))
      (error
       (signal 'mongodb-error
               (list (format "MongoDB MONGODB-AWS credential expiration is invalid: %s"
                             (error-message-string err))))))))

(defun mongodb--aws-normalize-credentials (value context &optional require-expiration)
  "Return AWS credentials from VALUE for CONTEXT.
When REQUIRE-EXPIRATION is non-nil, VALUE must include an Expiration field."
  (let* ((access-key-id
          (or (and (mongodb--aws-credentials-p value)
                   (mongodb--aws-credentials-access-key-id value))
              (mongodb--aws-credential-field
               value :access-key-id :accessKeyId 'access-key-id 'accessKeyId
               'AccessKeyId 'access_key_id
               "AccessKeyId" "accessKeyId" "access_key_id")))
         (secret-access-key
          (or (and (mongodb--aws-credentials-p value)
                   (mongodb--aws-credentials-secret-access-key value))
              (mongodb--aws-credential-field
               value :secret-access-key :secretAccessKey
               'secret-access-key 'secretAccessKey
               'SecretAccessKey 'secret_access_key
               "SecretAccessKey" "secretAccessKey" "secret_access_key")))
         (session-token
          (or (and (mongodb--aws-credentials-p value)
                   (mongodb--aws-credentials-session-token value))
              (mongodb--aws-credential-field
               value :session-token :sessionToken
               'session-token 'sessionToken
               'SessionToken 'session_token 'Token 'token
               "SessionToken" "sessionToken" "Token" "token")))
         (expiration
          (or (and (mongodb--aws-credentials-p value)
                   (mongodb--aws-credentials-expiration value))
              (mongodb--aws-expiration-time
               (mongodb--aws-credential-field
                value :expiration 'expiration 'Expiration
                "Expiration" "expiration")))))
    (unless (and (mongodb--nonempty-string access-key-id)
                 (mongodb--nonempty-string secret-access-key))
      (signal 'mongodb-error
              (list (format "MongoDB MONGODB-AWS %s did not return access key id and secret access key"
                            context))))
    (when (and require-expiration
               (not expiration))
      (signal 'mongodb-error
              (list (format "MongoDB MONGODB-AWS %s did not return credential expiration"
                            context))))
    (make-mongodb--aws-credentials
     :access-key-id access-key-id
     :secret-access-key secret-access-key
     :session-token session-token
     :expiration expiration)))

(defun mongodb--aws-cached-credentials-valid-p (credentials)
  "Return non-nil when cached AWS CREDENTIALS are still usable."
  (and (mongodb--aws-credentials-p credentials)
       (let ((expiration (mongodb--aws-credentials-expiration credentials)))
         (or (not expiration)
             (> (- expiration (float-time))
                mongodb--aws-credential-expiry-skew-seconds)))))

(defun mongodb--aws-json-object (body context)
  "Parse BODY as AWS JSON response for CONTEXT."
  (condition-case err
      (json-parse-string body
                         :object-type 'alist
                         :array-type 'list
                         :null-object nil
                         :false-object :false)
    (json-parse-error
     (signal 'mongodb-error
             (list (format "MongoDB MONGODB-AWS %s returned invalid JSON: %s"
                           context
                           (error-message-string err)))))))

(defun mongodb--aws-json-field (object key)
  "Return KEY from parsed AWS JSON OBJECT."
  (cdr (or (assoc key object)
           (assoc (intern key) object))))

(defun mongodb--aws-http-request (method url headers)
  "Return response body for AWS credential HTTP METHOD URL with HEADERS."
  (let ((url-request-method method)
        (url-request-extra-headers headers)
        (timeout-seconds mongodb--aws-credential-timeout-seconds)
        buffer)
    (setq buffer
          (url-retrieve-synchronously
           url t t timeout-seconds))
    (unless buffer
      (signal 'mongodb-error
              (list (format "MongoDB MONGODB-AWS credential request timed out: %s"
                            url))))
    (unwind-protect
        (with-current-buffer buffer
          (goto-char (point-min))
          (unless (looking-at "HTTP/[0-9.]+ \\([0-9][0-9][0-9]\\)")
            (signal 'mongodb-error
                    (list "MongoDB MONGODB-AWS credential response has no HTTP status")))
          (let ((status (string-to-number (match-string 1))))
            (unless (re-search-forward "\r?\n\r?\n" nil t)
              (signal 'mongodb-error
                      (list "MongoDB MONGODB-AWS credential response has no body")))
            (let ((body (decode-coding-string
                         (buffer-substring-no-properties
                          (point) (point-max))
                         'utf-8 t)))
              (unless (and (>= status 200)
                           (< status 300))
                (signal 'mongodb-error
                        (list (format "MongoDB MONGODB-AWS credential request failed with HTTP %s: %s"
                                      status body))))
              body)))
      (when (buffer-live-p buffer)
        (kill-buffer buffer)))))

(defun mongodb--aws-query-string (pairs)
  "Return AWS query string from PAIRS."
  (mapconcat (lambda (pair)
               (concat (url-hexify-string (car pair))
                       "="
                       (url-hexify-string (cdr pair))))
             pairs
             "&"))

(defun mongodb--aws-provider-credentials (credential)
  "Return credentials from CREDENTIAL's custom AWS provider, or nil."
  (when-let* ((provider (mongodb--credential-aws-credential-provider credential)))
    (unless (functionp provider)
      (signal 'mongodb-error
              (list "MongoDB MONGODB-AWS :aws-credential-provider must be a function")))
    (let ((result (funcall provider
                           (list :timeout-seconds
                                 mongodb--aws-credential-timeout-seconds))))
      (mongodb--aws-normalize-credentials result "credential provider"))))

(defun mongodb--aws-env-credentials
    (credential explicit-credentials &optional explicit-only)
  "Return explicit or environment AWS credentials for CREDENTIAL.
When EXPLICIT-ONLY is non-nil, do not consult process environment variables.

Arguments: CREDENTIAL, EXPLICIT-CREDENTIALS, EXPLICIT-ONLY."
  (let* ((explicit-access-key-id
          (mongodb--nonempty-string
           (mongodb--credential-username credential)))
         (explicit-secret-access-key
          (mongodb--nonempty-string
           (mongodb--credential-password credential)))
         (access-key-id (or explicit-access-key-id
                            (and (not explicit-only)
                                 (mongodb--nonempty-string
                                  (getenv "AWS_ACCESS_KEY_ID")))))
         (secret-access-key (or explicit-secret-access-key
                                (and (not explicit-only)
                                     (mongodb--nonempty-string
                                      (getenv "AWS_SECRET_ACCESS_KEY")))))
         (session-token (or (mongodb--nonempty-string
                             (mongodb--mechanism-property
                              (mongodb--credential-mechanism-properties credential)
                              "AWS_SESSION_TOKEN"))
                            (and (not explicit-credentials)
                                 (not explicit-only)
                                 (mongodb--nonempty-string
                                  (getenv "AWS_SESSION_TOKEN"))))))
    (when (or access-key-id secret-access-key)
      (unless (and access-key-id secret-access-key)
        (signal 'mongodb-error
                (list "MongoDB MONGODB-AWS authentication requires both AWS access key id and secret access key")))
      (make-mongodb--aws-credentials
       :access-key-id access-key-id
       :secret-access-key secret-access-key
       :session-token session-token))))

(defun mongodb--aws-web-identity-credentials ()
  "Return AWS credentials from AssumeRoleWithWebIdentity, or nil."
  (let ((token-file (mongodb--nonempty-string
                     (getenv "AWS_WEB_IDENTITY_TOKEN_FILE")))
        (role-arn (mongodb--nonempty-string
                   (getenv "AWS_ROLE_ARN"))))
    (cond
     ((or token-file role-arn)
      (unless (and token-file role-arn)
        (signal 'mongodb-error
                (list "MongoDB MONGODB-AWS AssumeRoleWithWebIdentity requires AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN")))
      (let* ((token (mongodb--oidc-read-token-file token-file))
             (session-name
              (or (mongodb--nonempty-string
                   (getenv "AWS_ROLE_SESSION_NAME"))
                  (concat "mongodb-el-"
                          (mongodb--bytes-to-hex
                           (mongodb--random-bytes 8)))))
             (query (mongodb--aws-query-string
                     `(("Action" . "AssumeRoleWithWebIdentity")
                       ("RoleSessionName" . ,session-name)
                       ("RoleArn" . ,role-arn)
                       ("WebIdentityToken" . ,token)
                       ("Version" . "2011-06-15"))))
             (body (mongodb--aws-http-request
                    "POST"
                    (concat "https://sts.amazonaws.com/?" query)
                    '(("Accept" . "application/json"))))
             (document (mongodb--aws-json-object
                        body "AssumeRoleWithWebIdentity response"))
             (credentials (mongodb--aws-json-field document "Credentials")))
        (mongodb--aws-normalize-credentials
         credentials "AssumeRoleWithWebIdentity response" t)))
     (t nil))))

(defun mongodb--aws-ecs-credentials ()
  "Return AWS credentials from ECS task metadata, or nil."
  (when-let* ((relative-uri
               (mongodb--nonempty-string
                (getenv "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"))))
    (let* ((path (if (string-prefix-p "/" relative-uri)
                     relative-uri
                   (concat "/" relative-uri)))
           (body (mongodb--aws-http-request
                  "GET"
                  (concat "http://169.254.170.2" path)
                  '(("Accept" . "application/json"))))
           (document (mongodb--aws-json-object
                      body "ECS credentials response")))
      (mongodb--aws-normalize-credentials
       document "ECS credentials response" t))))

(defun mongodb--aws-ec2-credentials ()
  "Return AWS credentials from EC2 IMDSv2."
  (let* ((token (string-trim
                 (mongodb--aws-http-request
                  "PUT"
                  "http://169.254.169.254/latest/api/token"
                  '(("X-aws-ec2-metadata-token-ttl-seconds" . "21600")))))
         (headers `(("X-aws-ec2-metadata-token" . ,token)))
         (role-name (string-trim
                     (mongodb--aws-http-request
                      "GET"
                      "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                      headers))))
    (unless (mongodb--nonempty-string role-name)
      (signal 'mongodb-error
              (list "MongoDB MONGODB-AWS EC2 metadata returned no IAM role name")))
    (let* ((body (mongodb--aws-http-request
                  "GET"
                  (concat
                   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                   (url-hexify-string role-name))
                  headers))
           (document (mongodb--aws-json-object
                      body "EC2 credentials response")))
      (mongodb--aws-normalize-credentials
       document "EC2 credentials response" t))))

(defun mongodb--aws-fetch-and-cache-credentials (credential)
  "Fetch temporary AWS credentials for CREDENTIAL and cache them."
  (let ((credentials (or (mongodb--aws-web-identity-credentials)
                         (mongodb--aws-ecs-credentials)
                         (mongodb--aws-ec2-credentials))))
    (setf (mongodb--credential-aws-cached-credentials credential)
          credentials)
    credentials))

(defun mongodb--aws-credentials (credential)
  "Return AWS credentials for MONGODB-AWS CREDENTIAL."
  (let* ((explicit-access-key-id
          (mongodb--nonempty-string
           (mongodb--credential-username credential)))
         (explicit-secret-access-key
          (mongodb--nonempty-string
           (mongodb--credential-password credential)))
         (explicit-credentials
          (or explicit-access-key-id explicit-secret-access-key)))
    (or (and explicit-credentials
             (mongodb--aws-env-credentials credential explicit-credentials t))
        (mongodb--aws-provider-credentials credential)
        (when (mongodb--aws-cached-credentials-valid-p
               (mongodb--credential-aws-cached-credentials credential))
          (mongodb--credential-aws-cached-credentials credential))
        (mongodb--aws-env-credentials credential explicit-credentials)
        (mongodb--aws-fetch-and-cache-credentials credential)
        (signal 'mongodb-error
                (list "MongoDB MONGODB-AWS authentication requires AWS credentials from URI/params, :aws-credential-provider, environment variables, AssumeRoleWithWebIdentity, ECS, or EC2 IMDS")))))

(defun mongodb--aws-date ()
  "Return the current AWS SigV4 timestamp."
  (format-time-string "%Y%m%dT%H%M%SZ" nil t))

(defun mongodb--aws-validate-sts-host (host)
  "Validate AWS STS HOST from a MONGODB-AWS server-first message."
  (unless (mongodb--nonempty-string host)
    (signal 'mongodb-error
            (list "MongoDB MONGODB-AWS server returned an empty STS host")))
  (when (> (length (mongodb--utf8-bytes host)) 255)
    (signal 'mongodb-error
            (list "MongoDB MONGODB-AWS STS host exceeds 255 bytes")))
  (when (or (string-prefix-p "." host)
            (string-suffix-p "." host)
            (string-match-p "\\.\\." host))
    (signal 'mongodb-error
            (list (format "MongoDB MONGODB-AWS STS host is invalid: %s"
                          host))))
  host)

(defun mongodb--aws-region (host)
  "Return AWS SigV4 region derived from STS HOST."
  (setq host (mongodb--aws-validate-sts-host host))
  (cond
   ((member host '("sts.amazonaws.com" "aws.amazonaws.com"))
    "us-east-1")
   ((string-match-p "\\." host)
    (let ((region (cadr (split-string host "\\."))))
      (unless (mongodb--nonempty-string region)
        (signal 'mongodb-error
                (list (format "MongoDB MONGODB-AWS STS host has no region label: %s"
                              host))))
      region))
   (t "us-east-1")))

(defun mongodb--aws-signing-key (secret-access-key date-stamp region)
  "Return AWS SigV4 signing key for SECRET-ACCESS-KEY, DATE-STAMP, and REGION."
  (let* ((date-key (mongodb--hmac-sha256
                    (mongodb--utf8-bytes (concat "AWS4" secret-access-key))
                    (mongodb--utf8-bytes date-stamp)))
         (region-key (mongodb--hmac-sha256
                      date-key
                      (mongodb--utf8-bytes region)))
         (service-key (mongodb--hmac-sha256
                       region-key
                       (mongodb--utf8-bytes "sts"))))
    (mongodb--hmac-sha256 service-key
                        (mongodb--utf8-bytes "aws4_request"))))

(defun mongodb--aws-authorization-header
    (credentials host server-nonce amz-date)
  "Return AWS SigV4 Authorization header for MONGODB-AWS.

Arguments: CREDENTIALS, HOST, SERVER-NONCE, AMZ-DATE."
  (let* ((host (mongodb--aws-validate-sts-host host))
         (region (mongodb--aws-region host))
         (date-stamp (substring amz-date 0 8))
         (scope (format "%s/%s/sts/aws4_request" date-stamp region))
         (server-nonce64 (mongodb--base64-encode server-nonce))
         (session-token
          (mongodb--aws-credentials-session-token credentials))
         (headers
          `(("content-length" . ,(number-to-string
                                  (length mongodb--aws-sts-body)))
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
                 (mongodb--bytes-to-hex
                  (mongodb--sha256
                   (mongodb--utf8-bytes mongodb--aws-sts-body))))
           "\n"))
         (string-to-sign
          (mapconcat
           #'identity
           (list "AWS4-HMAC-SHA256"
                 amz-date
                 scope
                 (mongodb--bytes-to-hex
                  (mongodb--sha256
                   (mongodb--utf8-bytes canonical-request))))
           "\n"))
         (signing-key
          (mongodb--aws-signing-key
           (mongodb--aws-credentials-secret-access-key credentials)
           date-stamp
           region))
         (signature
          (mongodb--bytes-to-hex
           (mongodb--hmac-sha256 signing-key
                               (mongodb--utf8-bytes string-to-sign)))))
    (format (concat "AWS4-HMAC-SHA256 Credential=%s/%s, "
                    "SignedHeaders=%s, Signature=%s")
            (mongodb--aws-credentials-access-key-id credentials)
            scope
            signed-headers
            signature)))

(defun mongodb--aws-client-first-command (client-nonce)
  "Return the MONGODB-AWS saslStart command for CLIENT-NONCE."
  `(("saslStart" . 1)
    ("mechanism" . "MONGODB-AWS")
    ("payload" . ,(mongodb-binary
                   0
                   (mongodb--encode-document
                    `(("r" . ,(mongodb-binary 0 client-nonce))
                      ("p" . ,(mongodb-int32 ?n))))))
    ("autoAuthorize" . 1)))

(defun mongodb--aws-server-first (response client-nonce)
  "Return decoded MONGODB-AWS server-first data from RESPONSE.

Arguments: RESPONSE, CLIENT-NONCE."
  (let* ((payload (cdr (assoc "payload" response)))
         (document
          (and payload
               (mongodb--decode-document-from-string
                (mongodb--binary-value-data payload))))
         (server-nonce
          (and document
               (mongodb--binary-value-data
                (cdr (assoc "s" document)))))
         (host (cdr (assoc "h" document)))
         (conversation-id (cdr (assoc "conversationId" response))))
    (unless conversation-id
      (signal 'mongodb-error
              (list "MongoDB MONGODB-AWS server response is missing conversationId")))
    (unless (and server-nonce
                 (= (length server-nonce) 64))
      (signal 'mongodb-error
              (list "MongoDB MONGODB-AWS server nonce must be exactly 64 bytes")))
    (unless (string-prefix-p client-nonce server-nonce)
      (signal 'mongodb-error
              (list "MongoDB MONGODB-AWS server nonce does not begin with the client nonce")))
    (mongodb--aws-validate-sts-host host)
    (list :server-nonce server-nonce
          :host host
          :conversation-id conversation-id)))

(defun mongodb--aws-client-second-command (conversation-id credentials server-first)
  "Return the MONGODB-AWS saslContinue command.

Arguments: CONVERSATION-ID, CREDENTIALS, SERVER-FIRST."
  (let* ((amz-date (mongodb--aws-date))
         (server-nonce (plist-get server-first :server-nonce))
         (host (plist-get server-first :host))
         (authorization
          (mongodb--aws-authorization-header
           credentials host server-nonce amz-date))
         (session-token
          (mongodb--aws-credentials-session-token credentials))
         (payload
          `(("a" . ,authorization)
            ("d" . ,amz-date)
            ,@(when session-token
                `(("t" . ,session-token))))))
    `(("saslContinue" . 1)
      ("conversationId" . ,conversation-id)
      ("payload" . ,(mongodb-binary
                     0
                     (mongodb--encode-document payload))))))

(defun mongodb--authenticate-aws (conn credential)
  "Authenticate CONN with CREDENTIAL using MONGODB-AWS."
  (condition-case err
      (let* ((credentials (mongodb--aws-credentials credential))
             (client-nonce (mongodb--random-bytes 32))
             (start-response
              (mongodb-command
               conn
               (mongodb--credential-source credential)
               (mongodb--aws-client-first-command client-nonce))))
        (when (eq (cdr (assoc "done" start-response)) t)
          (signal 'mongodb-error
                  (list "MongoDB MONGODB-AWS conversation ended before client signature")))
        (let* ((server-first
                (mongodb--aws-server-first start-response client-nonce))
               (conversation-id (plist-get server-first :conversation-id))
               (continue-response
                (mongodb-command
                 conn
                 (mongodb--credential-source credential)
                 (mongodb--aws-client-second-command
                  conversation-id credentials server-first))))
          (unless (eq (cdr (assoc "done" continue-response)) t)
            (signal 'mongodb-error
                    (list "MongoDB MONGODB-AWS SASL authentication did not complete")))
          continue-response))
    (error
     (setf (mongodb--credential-aws-cached-credentials credential) nil)
     (signal (car err) (cdr err)))))

(defun mongodb--oidc-read-token-file (file)
  "Return an OIDC access token read from FILE."
  (unless (mongodb--nonempty-string file)
    (signal 'mongodb-error
            (list "MongoDB MONGODB-OIDC token file path is empty")))
  (condition-case err
      (with-temp-buffer
        (set-buffer-multibyte nil)
        (insert-file-contents-literally file)
        (string-trim (decode-coding-string (buffer-string) 'utf-8 t)))
    (error
     (signal 'mongodb-error
             (list (format "MongoDB MONGODB-OIDC token file could not be read: %s"
                           (error-message-string err)))))))

(defun mongodb--oidc-http-get (url headers)
  "Return response body for OIDC metadata GET URL with HEADERS."
  (let ((url-request-method "GET")
        (url-request-extra-headers headers)
        (timeout-seconds (/ mongodb--oidc-callback-timeout-ms 1000.0))
        buffer)
    (setq buffer
          (url-retrieve-synchronously
           url t t timeout-seconds))
    (unless buffer
      (signal 'mongodb-error
              (list (format "MongoDB MONGODB-OIDC metadata request timed out: %s"
                            url))))
    (unwind-protect
        (with-current-buffer buffer
          (goto-char (point-min))
          (unless (looking-at "HTTP/[0-9.]+ \\([0-9][0-9][0-9]\\)")
            (signal 'mongodb-error
                    (list "MongoDB MONGODB-OIDC metadata response has no HTTP status")))
          (let ((status (string-to-number (match-string 1))))
            (unless (re-search-forward "\r?\n\r?\n" nil t)
              (signal 'mongodb-error
                      (list "MongoDB MONGODB-OIDC metadata response has no body")))
            (let ((body (decode-coding-string
                         (buffer-substring-no-properties
                          (point) (point-max))
                         'utf-8 t)))
              (unless (and (>= status 200)
                           (< status 300))
                (signal 'mongodb-error
                        (list (format "MongoDB MONGODB-OIDC metadata request failed with HTTP %s: %s"
                                      status body))))
              body)))
      (when (buffer-live-p buffer)
        (kill-buffer buffer)))))

(defun mongodb--oidc-json-object (body context)
  "Parse BODY as a JSON object for CONTEXT."
  (condition-case err
      (json-parse-string body
                         :object-type 'alist
                         :array-type 'list
                         :null-object nil
                         :false-object :false)
    (json-parse-error
     (signal 'mongodb-error
             (list (format "MongoDB MONGODB-OIDC %s returned invalid JSON: %s"
                           context
                           (error-message-string err)))))))

(defun mongodb--oidc-json-field (object key)
  "Return KEY from parsed JSON OBJECT."
  (cdr (or (assoc key object)
           (assoc (intern key) object))))

(defun mongodb--oidc-resource-query (credential key)
  "Return OIDC metadata query parameter KEY for CREDENTIAL's TOKEN_RESOURCE."
  (let ((resource
         (mongodb--oidc-token-resource
          (mongodb--credential-mechanism-properties credential))))
    (concat key "=" (url-hexify-string resource))))

(defun mongodb--oidc-azure-token (credential)
  "Return an access token from Azure IMDS for CREDENTIAL."
  (let* ((query (mongodb--oidc-resource-query credential "resource"))
         (username (mongodb--nonempty-string
                    (mongodb--credential-username credential)))
         (url (concat
               "http://169.254.169.254/metadata/identity/oauth2/token"
               "?api-version=2018-02-01&"
               query
               (when username
                 (concat "&client_id="
                         (url-hexify-string username)))))
         (body (mongodb--oidc-http-get
                url
                '(("Accept" . "application/json")
                  ("Metadata" . "true"))))
         (document (mongodb--oidc-json-object body "Azure metadata endpoint"))
         (token (mongodb--oidc-json-field document "access_token")))
    (unless (mongodb--nonempty-string token)
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC Azure metadata response is missing access_token")))
    token))

(defun mongodb--oidc-gcp-token (credential)
  "Return an access token from GCP metadata service for CREDENTIAL."
  (let* ((url (concat
               "http://metadata/computeMetadata/v1/instance/"
               "service-accounts/default/identity?"
               (mongodb--oidc-resource-query credential "audience")))
         (body (mongodb--oidc-http-get
                url
                '(("Metadata-Flavor" . "Google"))))
         (token (string-trim body)))
    (unless (mongodb--nonempty-string token)
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC GCP metadata response is empty")))
    token))

(defun mongodb--oidc-callback-result-field (result &rest keys)
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

(defun mongodb--oidc-callback-result-access-token (result)
  "Return an access token from OIDC callback RESULT, or nil."
  (if (stringp result)
      result
    (mongodb--oidc-callback-result-field
     result :access-token :accessToken 'access-token 'accessToken
     "accessToken" "access_token")))

(defun mongodb--oidc-callback-result-refresh-token (result)
  "Return a refresh token from OIDC callback RESULT, or nil."
  (mongodb--oidc-callback-result-field
   result :refresh-token :refreshToken 'refresh-token 'refreshToken
   "refreshToken" "refresh_token"))

(defun mongodb--oidc-callback-token (credential)
  "Return an OIDC access token from CREDENTIAL's callback."
  (when-let* ((callback (mongodb--credential-oidc-callback credential)))
    (unless (functionp callback)
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC callback must be a function")))
    (let* ((result (funcall callback
                            (list :timeout-ms mongodb--oidc-callback-timeout-ms
                                  :username
                                  (mongodb--credential-username credential)
                                  :version 1)))
           (token (mongodb--oidc-callback-result-access-token result)))
      (unless (mongodb--nonempty-string token)
        (signal 'mongodb-error
                (list "MongoDB MONGODB-OIDC callback did not return an access token")))
      token)))

(defun mongodb--oidc-human-callback-token (credential idp-info)
  "Return an OIDC access token from CREDENTIAL's human callback.

Arguments: CREDENTIAL, IDP-INFO."
  (let ((callback (mongodb--credential-oidc-human-callback credential)))
    (unless (functionp callback)
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC human callback must be a function")))
    (let* ((result (funcall callback
                            (list :timeout-ms mongodb--oidc-callback-timeout-ms
                                  :username
                                  (mongodb--credential-username credential)
                                  :version 1
                                  :idp-info idp-info
                                  :refresh-token
                                  (mongodb--credential-oidc-refresh-token
                                   credential))))
           (token (mongodb--oidc-callback-result-access-token result))
           (refresh-token
            (mongodb--oidc-callback-result-refresh-token result)))
      (unless (mongodb--nonempty-string token)
        (signal 'mongodb-error
                (list "MongoDB MONGODB-OIDC human callback did not return an access token")))
      (when (mongodb--nonempty-string refresh-token)
        (setf (mongodb--credential-oidc-refresh-token credential)
              refresh-token))
      token)))

(defun mongodb--oidc-k8s-token-file ()
  "Return the Kubernetes OIDC token file path from the standard environment."
  (or (mongodb--nonempty-string (getenv "AZURE_FEDERATED_TOKEN_FILE"))
      (mongodb--nonempty-string (getenv "AWS_WEB_IDENTITY_TOKEN_FILE"))
      "/var/run/secrets/kubernetes.io/serviceaccount/token"))

(defun mongodb--oidc-environment-token (credential)
  "Return an OIDC access token from CREDENTIAL's ENVIRONMENT, or nil."
  (when-let* ((environment
               (mongodb--oidc-mechanism-environment
                (mongodb--credential-mechanism-properties credential))))
    (pcase environment
      ("k8s"
       (mongodb--oidc-read-token-file
        (mongodb--oidc-k8s-token-file)))
      ("test"
       (mongodb--oidc-read-token-file
        (or (mongodb--nonempty-string (getenv "OIDC_TOKEN_FILE"))
            (signal 'mongodb-error
                    (list "MongoDB MONGODB-OIDC ENVIRONMENT:test requires OIDC_TOKEN_FILE")))))
      ("azure"
       (mongodb--oidc-azure-token credential))
      ("gcp"
       (mongodb--oidc-gcp-token credential))
      (_
       (signal 'mongodb-error
               (list (format "Unsupported MongoDB MONGODB-OIDC ENVIRONMENT: %s"
                             environment)))))))

(defun mongodb--oidc-one-step-token (credential)
  "Return an OIDC one-step access token for CREDENTIAL, or nil."
  (or (mongodb--nonempty-string
       (mongodb--credential-oidc-token credential))
      (when-let* ((file (mongodb--credential-oidc-token-file credential)))
        (mongodb--oidc-read-token-file file))
      (mongodb--oidc-environment-token credential)
      (mongodb--oidc-callback-token credential)))

(defun mongodb--oidc-token (credential)
  "Return the OIDC access token for CREDENTIAL."
  (let ((token (mongodb--oidc-one-step-token credential)))
    (unless (mongodb--nonempty-string token)
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC authentication requires :oidc-token, :oidc-token-file, :oidc-callback, :oidc-human-callback, or ENVIRONMENT:k8s/test/azure/gcp token configuration")))
    token))

(defun mongodb--oidc-start-command (token)
  "Return a MongoDB MONGODB-OIDC one-step saslStart command for TOKEN."
  `(("saslStart" . 1)
    ("mechanism" . "MONGODB-OIDC")
    ("payload" . ,(mongodb-binary
                   0
                   (mongodb--encode-document
                    `(("jwt" . ,token)))))
    ("autoAuthorize" . 1)))

(defun mongodb--oidc-principal-start-command (credential)
  "Return a MONGODB-OIDC two-step saslStart command for CREDENTIAL."
  `(("saslStart" . 1)
    ("mechanism" . "MONGODB-OIDC")
    ("payload" . ,(mongodb-binary
                   0
                   (mongodb--encode-document
                    `(,@(when (mongodb--credential-username credential)
                          `(("n" . ,(mongodb--credential-username
                                      credential))))))))
    ("autoAuthorize" . 1)))

(defun mongodb--oidc-continue-command (conversation-id token)
  "Return a MONGODB-OIDC saslContinue command for TOKEN.

Arguments: CONVERSATION-ID, TOKEN."
  `(("saslContinue" . 1)
    ("conversationId" . ,conversation-id)
    ("payload" . ,(mongodb-binary
                   0
                   (mongodb--encode-document
                    `(("jwt" . ,token)))))))

(defun mongodb--oidc-response-payload-document (response)
  "Return decoded BSON payload document from OIDC RESPONSE."
  (when-let* ((payload (cdr (assoc "payload" response))))
    (mongodb--decode-document-from-string
     (mongodb--binary-value-data payload))))

(defun mongodb--oidc-normalize-idp-info (idp-info)
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

(defun mongodb--oidc-idp-info (credential response)
  "Return IdPInfo from OIDC two-step RESPONSE and cache it on CREDENTIAL."
  (let* ((conversation-id (cdr (assoc "conversationId" response)))
         (raw-idp-info (mongodb--oidc-response-payload-document response))
         (idp-info (and raw-idp-info
                        (mongodb--oidc-normalize-idp-info raw-idp-info))))
    (unless conversation-id
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC server response is missing conversationId")))
    (unless idp-info
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC server response is missing IdPInfo payload")))
    (unless (cdr (assoc "issuer" idp-info))
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC IdPInfo is missing issuer")))
    (setf (mongodb--credential-oidc-idp-info credential) idp-info)
    (list :conversation-id conversation-id
          :idp-info idp-info)))

(defun mongodb--oidc-normalize-host (host)
  "Return HOST normalized for MONGODB-OIDC allowed-host matching."
  (when host
    (let ((normalized (downcase (format "%s" host))))
      (when (and (string-prefix-p "[" normalized)
                 (string-suffix-p "]" normalized))
        (setq normalized (substring normalized 1 -1)))
      (string-remove-suffix "." normalized))))

(defun mongodb--oidc-host-matches-allowed-p (host allowed)
  "Return non-nil when HOST matches one ALLOWED host pattern."
  (let ((host (mongodb--oidc-normalize-host host))
        (allowed (mongodb--oidc-normalize-host allowed)))
    (cond
     ((not (and host allowed)) nil)
     ((string-prefix-p "*." allowed)
      (let ((suffix (substring allowed 1)))
        (and (> (length host) (length suffix))
             (string-suffix-p suffix host))))
     (t
      (equal host allowed)))))

(defun mongodb--oidc-allowed-host-p (host allowed-hosts)
  "Return non-nil when HOST is allowed for a human OIDC callback.

Arguments: HOST, ALLOWED-HOSTS."
  (seq-some (lambda (allowed)
              (mongodb--oidc-host-matches-allowed-p host allowed))
            (or allowed-hosts mongodb--oidc-default-allowed-hosts)))

(defun mongodb--validate-oidc-human-callback-host (conn credential)
  "Validate CONN host before invoking CREDENTIAL's human OIDC callback."
  (when (mongodb-conn-p conn)
    (let ((host (mongodb-conn-host conn)))
      (unless (mongodb--oidc-allowed-host-p
               host
               (mongodb--credential-oidc-allowed-hosts credential))
        (signal 'mongodb-error
                (list (format "MongoDB MONGODB-OIDC human callback is not allowed for host %s; configure :oidc-allowed-hosts if this host is expected"
                              (or host "<unknown>"))))))))

(defun mongodb--authenticate-oidc-two-step (conn credential)
  "Authenticate CONN with CREDENTIAL using two-step MONGODB-OIDC."
  (let* ((start-response
          (mongodb-command
           conn
           (mongodb--credential-source credential)
           (mongodb--oidc-principal-start-command credential)))
         (server-first (mongodb--oidc-idp-info credential start-response))
         (conversation-id (plist-get server-first :conversation-id))
         (idp-info (plist-get server-first :idp-info))
         (token (mongodb--oidc-human-callback-token credential idp-info))
         (continue-response
          (mongodb-command
           conn
           (mongodb--credential-source credential)
           (mongodb--oidc-continue-command conversation-id token))))
    (unless (eq (cdr (assoc "done" continue-response)) t)
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC two-step conversation did not complete")))
    continue-response))

(defun mongodb--authenticate-oidc (conn credential)
  "Authenticate CONN with CREDENTIAL using MONGODB-OIDC."
  (if-let* ((token (mongodb--oidc-one-step-token credential)))
      (let ((response
             (mongodb-command
              conn
              (mongodb--credential-source credential)
              (mongodb--oidc-start-command token))))
        (unless (eq (cdr (assoc "done" response)) t)
          (signal 'mongodb-error
                  (list "MongoDB MONGODB-OIDC one-step conversation did not complete")))
        response)
    (if (mongodb--credential-oidc-human-callback credential)
        (progn
          (mongodb--validate-oidc-human-callback-host conn credential)
          (mongodb--authenticate-oidc-two-step conn credential))
      (mongodb--oidc-token credential))))

(defun mongodb--plain-payload (credential)
  "Return the SASL PLAIN payload for CREDENTIAL."
  (mongodb--utf8-bytes
   (concat "\0"
           (mongodb--credential-username credential)
           "\0"
           (mongodb--credential-password credential))))

(defun mongodb--plain-start-command (credential)
  "Return a MongoDB saslStart command for PLAIN CREDENTIAL."
  `(("saslStart" . 1)
    ("mechanism" . "PLAIN")
    ("payload" . ,(mongodb-binary 0 (mongodb--plain-payload credential)))
    ("autoAuthorize" . 1)))

(defun mongodb--authenticate-plain (conn credential)
  "Authenticate CONN with CREDENTIAL using PLAIN SASL."
  (let ((response
         (mongodb-command
          conn
          (mongodb--credential-source credential)
          (mongodb--plain-start-command credential))))
    (unless (eq (cdr (assoc "done" response)) t)
      (signal 'mongodb-error
              (list "MongoDB PLAIN SASL authentication did not complete")))
    response))

(defun mongodb--authenticate (conn credential hello &optional speculative-auth)
  "Authenticate CONN with CREDENTIAL using data from HELLO.
SPECULATIVE-AUTH is the SCRAM start data sent in the initial handshake."
  (let ((speculative-response (cdr (assoc "speculativeAuthenticate" hello))))
    (if (and speculative-auth
             speculative-response
             (assoc "payload" speculative-response))
        (mongodb--authenticate-scram
         conn credential
         (plist-get speculative-auth :mechanism)
         speculative-auth speculative-response)
      (pcase (mongodb--choose-auth-mechanism credential hello)
        ("SCRAM-SHA-256"
         (mongodb--authenticate-scram-sha256 conn credential))
        ("SCRAM-SHA-1"
         (mongodb--authenticate-scram-sha1 conn credential))
        ("MONGODB-X509"
         (mongodb--authenticate-x509 conn credential))
        ("PLAIN"
         (mongodb--authenticate-plain conn credential))
        ("MONGODB-AWS"
         (mongodb--authenticate-aws conn credential))
        ("MONGODB-OIDC"
         (mongodb--authenticate-oidc conn credential))
        (mechanism
         (signal 'mongodb-error
                 (list (format "Unsupported MongoDB auth mechanism: %s"
                               mechanism))))))))

(provide 'mongodb-auth)

;;; mongodb-auth.el ends here
