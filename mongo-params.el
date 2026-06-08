;;; mongo-params.el --- Connection params and URI parsing -*- lexical-binding: t; -*-

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

;; MongoDB URI parsing, connection params normalization, TLS params,
;; credentials, read/write concern, server API, and pool option helpers.

;;; Code:

(require 'cl-lib)
(require 'dns)
(require 'gnutls)
(require 'mongo-bson)
(require 'mongo-wire)
(require 'seq)
(require 'subr-x)
(require 'url)
(require 'url-util)

(defvar mongo-connect-timeout-seconds)
(defvar mongo-local-threshold-seconds)
(defvar mongo-monitor-heartbeat-seconds)
(defvar mongo-server-selection-timeout-seconds)
(defvar mongo-tls-keylist)
(defvar mongo-tls-trustfiles)
(defvar mongo-tls-verify-server)

(cl-defstruct mongo--credential
  username
  password
  source
  mechanism
  mechanism-properties
  aws-credential-provider
  aws-cached-credentials
  oidc-token
  oidc-token-file
  oidc-callback
  oidc-human-callback
  oidc-refresh-token
  oidc-idp-info
  oidc-allowed-hosts)

(cl-defstruct mongo--srv-resolution
  endpoints
  options)

(defconst mongo--unset :mongo-unset)

(defconst mongo--oidc-callback-timeout-ms 60000)

(defconst mongo--aws-credential-timeout-seconds 10)

(defconst mongo--aws-credential-expiry-skew-seconds 300)

(defconst mongo--default-max-pool-size 100)

(defconst mongo--default-min-pool-size 0)

(defconst mongo--default-max-connecting 2)

(defconst mongo--idle-write-period-seconds 10
  "MongoDB replica-set idle write period used for maxStalenessSeconds.")

(defconst mongo--oidc-default-allowed-hosts
  '("*.mongodb.net"
    "*.mongodb-qa.net"
    "*.mongodb-dev.net"
    "*.mongodbgov.net"
    "localhost"
    "127.0.0.1"
    "::1"
    "*.mongo.com")
  "Default hosts allowed for MONGODB-OIDC human callbacks.")

(cl-defstruct mongo--server-api
  version
  (strict mongo--unset)
  (deprecation-errors mongo--unset))

(cl-defstruct mongo--read-preference
  mode
  tags
  max-staleness-seconds)

(cl-defstruct mongo--read-concern
  pairs)

(cl-defstruct mongo--write-concern
  pairs)

(defvar mongo--srv-resolution-cache nil
  "Connection-local cache of MongoDB SRV DNS resolution results.")

;;;; Connection parameters

(defun mongo--nonempty-string (value)
  "Return VALUE when it is a non-empty string, otherwise nil."
  (and (stringp value)
       (> (length value) 0)
       value))

(defun mongo--normalize-auth-mechanism (mechanism)
  "Return normalized MongoDB auth MECHANISM, or nil."
  (when mechanism
    (let ((normalized (upcase (format "%s" mechanism))))
      (unless (string= normalized "DEFAULT")
        normalized))))

(defun mongo--url-parts (url)
  "Return parsed parts for MongoDB URL, or nil."
  (when (and (stringp url)
             (string-match
              "\\`\\(mongodb\\(?:\\+srv\\)?\\)://\\([^/?@]*@\\)?\\([^/?]+\\)\\(?:/\\([^?]*\\)\\)?\\(?:\\?\\(.*\\)\\)?\\'"
              url))
    (let ((scheme (match-string 1 url))
          (userinfo (match-string 2 url))
          (hosts (match-string 3 url))
          (database (match-string 4 url))
          (query (match-string 5 url)))
      (list :scheme scheme
            :userinfo userinfo
            :hosts hosts
            :database (and database
                           (not (string-empty-p database))
                           (url-unhex-string database))
            :options (mongo--url-query-options query)))))

(defun mongo--url-query-options (query)
  "Return normalized MongoDB URI QUERY options as an alist."
  (apply
   #'append
   (mapcar (lambda (entry)
             (let ((key (downcase (car entry))))
               (mapcar (lambda (value)
                         (cons key value))
                       (nreverse (cdr entry)))))
           (and query
                (url-parse-query-string query)))))

(defun mongo--url-option (options key)
  "Return MongoDB URI OPTIONS value for KEY, case-insensitively."
  (cdr (assoc (downcase key) options)))

(defun mongo--url-options (options key)
  "Return all MongoDB URI OPTIONS values for KEY, case-insensitively."
  (let ((normalized (downcase key))
        values)
    (dolist (option options)
      (when (equal (car option) normalized)
        (push (cdr option) values)))
    (nreverse values)))

(defun mongo--url-userinfo (userinfo)
  "Return parsed MongoDB URI USERINFO as a plist, or nil.
The returned plist contains :user, :password, and :explicit.  A present
credential delimiter is explicit even if the user name or password is empty."
  (when userinfo
    (let* ((info (substring userinfo 0 -1))
           (colon (cl-position ?: info))
           (user (if colon
                     (substring info 0 colon)
                   info))
           (secret (when colon
                     (substring info (1+ colon)))))
      (list :user (url-unhex-string user)
            :password (and colon
                           (url-unhex-string secret))
            :explicit t))))

(defun mongo--truthy-url-option-p (value)
  "Return non-nil when URL option VALUE means true."
  (and value
       (member (downcase value) '("true" "1" "yes"))))

(defun mongo--falsey-url-option-p (value)
  "Return non-nil when URL option VALUE means false."
  (and value
       (member (downcase value) '("false" "0" "no"))))

(defconst mongo--recognized-url-options
  '("apideprecationerrors"
    "apistrict"
    "apiversion"
    "appname"
    "authmechanism"
    "authmechanismproperties"
    "authsource"
    "compressors"
    "connecttimeoutms"
    "directconnection"
    "heartbeatfrequencyms"
    "journal"
    "localthresholdms"
    "loadbalanced"
    "maxconnecting"
    "maxidletimems"
    "maxpoolsize"
    "maxstalenessseconds"
    "minpoolsize"
    "proxyhost"
    "proxypassword"
    "proxyport"
    "proxyusername"
    "readconcernlevel"
    "readpreference"
    "readpreferencetags"
    "replicaset"
    "retryreads"
    "retrywrites"
    "serverapi"
    "servermonitoringmode"
    "serverselectiontimeoutms"
    "serverselectiontryonce"
    "sockettimeoutms"
    "srvmaxhosts"
    "srvservicename"
    "timeoutms"
    "ssl"
    "tls"
    "tlsallowinvalidcertificates"
    "tlsallowinvalidhostnames"
    "tlscafile"
    "tlscertificatekeyfile"
    "tlsdisablecertificaterevocationcheck"
    "tlsdisableocspendpointcheck"
    "tlsinsecure"
    "waitqueuetimeoutms"
    "w"
    "wtimeoutms"
    "zlibcompressionlevel")
  "MongoDB URI options recognized by the native client.
Some recognized options, such as retryWrites, are accepted so standard MongoDB
URIs keep working, but currently do not enable write retry logic.")

(defconst mongo--boolean-url-options
  '("apideprecationerrors"
    "apistrict"
    "directconnection"
    "journal"
    "loadbalanced"
    "retryreads"
    "retrywrites"
    "serverselectiontryonce"
    "ssl"
    "tls"
    "tlsallowinvalidcertificates"
    "tlsallowinvalidhostnames"
    "tlsdisablecertificaterevocationcheck"
    "tlsdisableocspendpointcheck"
    "tlsinsecure")
  "MongoDB URI options that must use boolean values.")

(defun mongo--url-bool-option-value (value name)
  "Return VALUE parsed as a boolean URL option NAME."
  (cond
   ((mongo--truthy-url-option-p value) t)
   ((mongo--falsey-url-option-p value) nil)
   (t
    (signal 'mongo-error
            (list (format "MongoDB URI option %s must be a boolean, got %S"
                          name value))))))

(defun mongo--url-option-present-p (options key)
  "Return non-nil when URI OPTIONS include KEY."
  (assoc (downcase key) options))

(defun mongo--url-bool-option-values (options key)
  "Return all boolean URI option values for KEY from OPTIONS."
  (mapcar (lambda (value)
            (mongo--url-bool-option-value value key))
          (mongo--url-options options key)))

(defun mongo--reject-conflicting-tls-url-options (options)
  "Signal when MongoDB TLS URI OPTIONS contain forbidden combinations."
  (let ((tls-values (append
                     (mongo--url-bool-option-values options "tls")
                     (mongo--url-bool-option-values options "ssl"))))
    (when (and tls-values
               (cl-some (lambda (value)
                          (not (eq value (car tls-values))))
                        (cdr tls-values)))
      (signal 'mongo-error
              (list "MongoDB URI options tls and ssl must not conflict"))))
  (dolist (pair '(("tlsInsecure" "tlsAllowInvalidCertificates")
                  ("tlsInsecure" "tlsAllowInvalidHostnames")
                  ("tlsInsecure" "tlsDisableOCSPEndpointCheck")
                  ("tlsInsecure" "tlsDisableCertificateRevocationCheck")
                  ("tlsAllowInvalidCertificates" "tlsDisableOCSPEndpointCheck")
                  ("tlsAllowInvalidCertificates" "tlsDisableCertificateRevocationCheck")
                  ("tlsDisableOCSPEndpointCheck" "tlsDisableCertificateRevocationCheck")))
    (when (and (mongo--url-option-present-p options (car pair))
               (mongo--url-option-present-p options (cadr pair)))
      (signal 'mongo-error
              (list (format "MongoDB URI options %s and %s must not be combined"
                            (car pair)
                            (cadr pair)))))))

(defun mongo--reject-unsupported-url-options (options)
  "Signal when MongoDB URI OPTIONS require unsupported native features."
  (dolist (option options)
    (let ((name (car option))
          (value (cdr option)))
      (unless (member name mongo--recognized-url-options)
        (signal 'mongo-error
                (list (format "Unsupported MongoDB URI option: %s" name))))
      (when (member name mongo--boolean-url-options)
        (mongo--url-bool-option-value value name))))
  (mongo--reject-conflicting-tls-url-options options))

(defun mongo--params-url-parts (params)
  "Return parsed MongoDB URL parts from PARAMS, or nil."
  (when-let* ((url (plist-get params :url)))
    (or (mongo--url-parts url)
        (signal 'mongo-error
                (list (format "Native MongoDB expects mongodb:// URLs, not %S; use :surface sql-interface for JDBC SQL Interface URLs"
                              url))))))

(defun mongo--srv-scheme-p (parts)
  "Return non-nil when MongoDB URL PARTS use mongodb+srv."
  (equal (plist-get parts :scheme) "mongodb+srv"))

(defun mongo--normalize-dns-name (name)
  "Return normalized DNS NAME without a trailing dot."
  (string-remove-suffix "." (downcase name)))

(defun mongo--srv-parent-domain (host)
  "Return the parent domain for SRV HOST."
  (let ((labels (split-string (mongo--normalize-dns-name host) "\\." t)))
    (when (< (length labels) 3)
      (signal 'mongo-error
              (list "Native MongoDB SRV URLs require a hostname with a domain and TLD")))
    (mapconcat #'identity (cdr labels) ".")))

(defun mongo--validate-srv-host (host)
  "Validate HOST for a MongoDB SRV URL."
  (when (or (string-match-p "," host)
            (string-match-p ":" host))
    (signal 'mongo-error
            (list "MongoDB SRV URLs must contain exactly one hostname and no port")))
  (mongo--srv-parent-domain host))

(defun mongo--validate-srv-service-name (name)
  "Return validated MongoDB SRV service NAME."
  (setq name (or name "mongodb"))
  (unless (and (stringp name)
               (string-match-p "\\`[[:alnum:]][[:alnum:]-]*\\'" name))
    (signal 'mongo-error
            (list (format "MongoDB srvServiceName must be a DNS service label, got %S"
                          name))))
  name)

(defun mongo--srv-target-valid-p (target parent-domain)
  "Return non-nil when SRV TARGET belongs to PARENT-DOMAIN."
  (let ((target (mongo--normalize-dns-name target))
        (suffix (concat "." (mongo--normalize-dns-name parent-domain))))
    (string-suffix-p suffix target)))

(defun mongo--dns-response-code (response)
  "Return DNS RESPONSE response code."
  (cadr (assoc 'response-code response)))

(defun mongo--dns-answers (name type &optional required)
  "Return DNS answers for NAME and TYPE.
When REQUIRED is non-nil, signal `mongo-error' if the query fails or returns no
answers."
  (condition-case err
      (let* ((response (dns-query name type t))
             (code (mongo--dns-response-code response))
             (answers (cl-remove-if-not
                       (lambda (answer)
                         (eq (cadr (assoc 'type answer)) type))
                       (cadr (assoc 'answers response)))))
        (cond
         ((and required (not (eq code 'no-error)))
          (signal 'mongo-error
                  (list (format "MongoDB SRV DNS lookup for %s returned %s"
                                name code))))
         ((and required (not answers))
          (signal 'mongo-error
                  (list (format "MongoDB SRV DNS lookup for %s returned no %s records"
                                name type))))
         (t answers)))
    (error
     (when required
       (if (eq (car err) 'mongo-error)
           (signal (car err) (cdr err))
         (signal 'mongo-error
                 (list (format "MongoDB DNS lookup for %s failed: %s"
                               name (error-message-string err)))))))))

(defun mongo--srv-answer-endpoint (answer parent-domain)
  "Return (HOST PORT) from SRV ANSWER, validating PARENT-DOMAIN."
  (let* ((data (cadr (assoc 'data answer)))
         (target (mongo--normalize-dns-name
                  (cadr (assoc 'target data))))
         (port (cadr (assoc 'port data))))
    (when (or (string-empty-p target)
              (equal target "."))
      (signal 'mongo-error
              (list "MongoDB SRV DNS lookup returned an empty target")))
    (unless (mongo--srv-target-valid-p target parent-domain)
      (signal 'mongo-error
              (list (format "MongoDB SRV target %s is outside parent domain %s"
                            target parent-domain))))
    (list target port)))

(defun mongo--srv-text (answer)
  "Return TXT data from DNS ANSWER as a string."
  (dns-read-txt (cadr (assoc 'data answer))))

(defun mongo--srv-txt-options (host)
  "Return MongoDB SRV TXT options for HOST."
  (let* ((answers (mongo--dns-answers host 'TXT nil))
         (txt-answers (cl-remove-if-not
                       (lambda (answer)
                         (eq (cadr (assoc 'type answer)) 'TXT))
                       answers)))
    (when (> (length txt-answers) 1)
      (signal 'mongo-error
              (list "MongoDB SRV TXT lookup returned multiple TXT records")))
    (when-let* ((text (and txt-answers
                           (mongo--srv-text (car txt-answers)))))
      (let ((options (mongo--url-query-options text)))
        (dolist (option options)
          (unless (member (car option) '("authsource" "replicaset"
                                         "loadbalanced"))
            (signal 'mongo-error
                    (list (format "MongoDB SRV TXT option %s is not supported"
                                  (car option))))))
        options))))

(defun mongo--resolve-srv (host &optional service-name)
  "Resolve MongoDB SRV HOST and return a `mongo--srv-resolution'."
  (let* ((host (mongo--normalize-dns-name host))
         (parent-domain (mongo--validate-srv-host host))
         (service-name (mongo--validate-srv-service-name service-name))
         (srv-name (format "_%s._tcp.%s" service-name host))
         (answers (mongo--dns-answers srv-name 'SRV t))
         (sorted (sort (copy-sequence answers)
                       (lambda (left right)
                         (< (or (cadr (assoc 'priority
                                             (cadr (assoc 'data left))))
                                0)
                            (or (cadr (assoc 'priority
                                             (cadr (assoc 'data right))))
                                0)))))
         (endpoints (mapcar (lambda (answer)
                              (mongo--srv-answer-endpoint
                               answer parent-domain))
                            sorted)))
    (make-mongo--srv-resolution
     :endpoints endpoints
     :options (mongo--srv-txt-options host))))

(defun mongo--srv-resolution (host &optional service-name)
  "Return cached MongoDB SRV resolution for HOST."
  (let* ((host (mongo--normalize-dns-name host))
         (service-name (mongo--validate-srv-service-name service-name))
         (cache-key (cons host service-name))
         (cached (assoc cache-key mongo--srv-resolution-cache)))
    (if cached
        (cdr cached)
      (let ((resolution (mongo--resolve-srv host service-name)))
        (push (cons cache-key resolution) mongo--srv-resolution-cache)
        resolution))))

(defun mongo--params-effective-url-options (params)
  "Return effective MongoDB URL options for PARAMS.
For mongodb+srv URLs, URI options override DNS TXT options."
  (when-let* ((parts (mongo--params-url-parts params)))
    (let ((options (plist-get parts :options)))
      (if (mongo--srv-scheme-p parts)
          (append options
                  (mongo--srv-resolution-options
                   (mongo--srv-resolution
                    (plist-get parts :hosts)
                    (mongo--params-srv-service-name params))))
        options))))

(defun mongo--limit-srv-endpoints (endpoints limit)
  "Return MongoDB SRV ENDPOINTS limited by LIMIT."
  (if (and limit
           (> (length endpoints) limit))
      (seq-take endpoints limit)
    endpoints))

(defun mongo--host-port (hostspec &optional default-port)
  "Return (HOST PORT) parsed from HOSTSPEC.
DEFAULT-PORT defaults to 27017.  URL-encoded absolute paths are returned as
UNIX-domain socket endpoints with PORT nil."
  (let ((default-port (or default-port 27017)))
    (cond
     ((mongo--local-socket-hostspec hostspec)
      (list (mongo--local-socket-hostspec hostspec) nil))
     ((string-match "\\`\\[\\([^]]+\\)\\]\\(?::\\([0-9]+\\)\\)?\\'" hostspec)
      (list (match-string 1 hostspec)
            (if-let* ((port (match-string 2 hostspec)))
                (string-to-number port)
              default-port)))
     ((string-match "\\`\\([^:]+\\):\\([0-9]+\\)\\'" hostspec)
      (list (match-string 1 hostspec)
            (string-to-number (match-string 2 hostspec))))
     (t
      (list hostspec default-port)))))

(defun mongo--local-socket-hostspec (hostspec)
  "Return HOSTSPEC as a UNIX-domain socket path, or nil.
MongoDB URI syntax represents local sockets as URL-encoded absolute paths in
the host list, for example %2Ftmp%2Fmongodb-27017.sock."
  (let ((decoded (and (stringp hostspec)
                      (url-unhex-string hostspec))))
    (and decoded
         (file-name-absolute-p decoded)
         decoded)))

(defun mongo--host-ports (hostspec &optional default-port)
  "Return a list of (HOST PORT) endpoints parsed from HOSTSPEC.
HOSTSPEC may be a MongoDB comma-separated seed list."
  (mapcar (lambda (item)
            (mongo--host-port item default-port))
          (split-string hostspec "," t "[[:space:]\n\r\t]*")))

(defun mongo--params-endpoints (params)
  "Return a list of (HOST PORT DATABASE) endpoints from PARAMS.
UNIX-domain socket endpoints use a nil PORT."
  (if-let* ((parts (mongo--params-url-parts params)))
      (let ((options (mongo--params-effective-url-options params)))
        (mongo--reject-unsupported-url-options
         options)
        (let ((database (or (plist-get params :database)
                            (plist-get parts :database)
                            "admin")))
          (if (mongo--srv-scheme-p parts)
              (let ((hosts (plist-get parts :hosts)))
                (mongo--validate-srv-host hosts)
                (let ((endpoints
                       (mongo--limit-srv-endpoints
                        (mongo--srv-resolution-endpoints
                         (mongo--srv-resolution
                          hosts
                          (mongo--params-srv-service-name params)))
                        (mongo--params-srv-max-hosts params))))
                  (mapcar (lambda (endpoint)
                            (append endpoint (list database)))
                          endpoints)))
            (mapcar (lambda (endpoint)
                      (append endpoint (list database)))
                    (mongo--host-ports
                     (plist-get parts :hosts))))))
    (let ((database (or (plist-get params :database) "admin"))
          (default-port (or (plist-get params :port) 27017)))
      (mapcar (lambda (endpoint)
                (append endpoint (list database)))
              (mongo--host-ports
               (format "%s" (or (plist-get params :host) "127.0.0.1"))
               default-port)))))

(defun mongo--params-endpoint (params)
  "Return (HOST PORT DATABASE) from MongoDB connection PARAMS."
  (car (mongo--params-endpoints params)))

(defun mongo--params-replica-set-name (params)
  "Return the requested replica set name from PARAMS, or nil."
  (let ((options (mongo--params-effective-url-options params)))
    (or (plist-get params :replica-set)
        (plist-get params :replicaSet)
        (mongo--url-option options "replicaSet"))))

(defun mongo--params-raw-replica-set-name (params)
  "Return requested replica set name without SRV TXT merging."
  (mongo--params-raw-option-value
   params '(:replica-set :replicaSet) "replicaSet"))

(defun mongo--params-direct-connection-p (params)
  "Return non-nil when PARAMS request direct MongoDB connection mode."
  (mongo--params-bool-option-p
   params '(:direct-connection :directConnection) "directConnection"))

(defun mongo--params-raw-direct-connection-p (params)
  "Return directConnection without SRV TXT merging."
  (mongo--params-raw-bool-option-p
   params '(:direct-connection :directConnection) "directConnection"))

(defun mongo--params-load-balanced-p (params)
  "Return non-nil when PARAMS request MongoDB load-balanced mode."
  (mongo--params-bool-option-p
   params '(:load-balanced :loadBalanced) "loadBalanced"))

(defun mongo--params-raw-load-balanced-p (params)
  "Return loadBalanced without SRV TXT merging."
  (mongo--params-raw-bool-option-p
   params '(:load-balanced :loadBalanced) "loadBalanced"))

(defun mongo--params-replica-discovery-p (params endpoints)
  "Return non-nil when PARAMS and ENDPOINTS should use replica discovery."
  (and (not (mongo--params-direct-connection-p params))
       (not (mongo--params-load-balanced-p params))
       (or (mongo--params-replica-set-name params)
           (> (length endpoints) 1))))

(defun mongo--params-auth-mechanism (params options)
  "Return authentication mechanism from PARAMS or URI OPTIONS."
  (or (plist-get params :auth-mechanism)
      (plist-get params :authMechanism)
      (mongo--url-option options "authMechanism")))

(defun mongo--x509-auth-mechanism-p (mechanism)
  "Return non-nil when MECHANISM names MongoDB X.509 authentication."
  (equal (mongo--normalize-auth-mechanism mechanism) "MONGODB-X509"))

(defun mongo--plain-auth-mechanism-p (mechanism)
  "Return non-nil when MECHANISM names MongoDB PLAIN SASL authentication."
  (equal (mongo--normalize-auth-mechanism mechanism) "PLAIN"))

(defun mongo--aws-auth-mechanism-p (mechanism)
  "Return non-nil when MECHANISM names MongoDB AWS IAM authentication."
  (equal (mongo--normalize-auth-mechanism mechanism) "MONGODB-AWS"))

(defun mongo--oidc-auth-mechanism-p (mechanism)
  "Return non-nil when MECHANISM names MongoDB OIDC authentication."
  (equal (mongo--normalize-auth-mechanism mechanism) "MONGODB-OIDC"))

(defun mongo--mechanism-property-name (name)
  "Return normalized auth mechanism property NAME."
  (let ((text (if (symbolp name)
                  (symbol-name name)
                (format "%s" name))))
    (setq text (string-remove-prefix ":" text))
    (upcase (replace-regexp-in-string "-" "_" text t t))))

(defun mongo--mechanism-property-pair (name value)
  "Return a normalized auth mechanism property pair."
  (let ((name (mongo--mechanism-property-name name)))
    (when (string-empty-p name)
      (signal 'mongo-error
              (list "MongoDB authMechanismProperties contains an empty property name")))
    (cons name (format "%s" value))))

(defun mongo--parse-mechanism-properties-string (value)
  "Parse authMechanismProperties string VALUE into an alist."
  (let (properties)
    (dolist (entry (split-string value "," t "[[:space:]\n\r\t]*"))
      (let ((colon (cl-position ?: entry)))
        (unless colon
          (signal 'mongo-error
                  (list (format "MongoDB authMechanismProperties entry lacks ':' in %S"
                                entry))))
        (push (mongo--mechanism-property-pair
               (substring entry 0 colon)
               (substring entry (1+ colon)))
              properties)))
    (nreverse properties)))

(defun mongo--mechanism-properties-from-plist (plist)
  "Return auth mechanism properties from PLIST."
  (let (properties)
    (while plist
      (unless (cdr plist)
        (signal 'mongo-error
                (list "MongoDB auth mechanism property plist has an odd length")))
      (push (mongo--mechanism-property-pair
             (car plist)
             (cadr plist))
            properties)
      (setq plist (cddr plist)))
    (nreverse properties)))

(defun mongo--mechanism-properties-value (value)
  "Return normalized auth mechanism properties from VALUE."
  (cond
   ((null value) nil)
   ((stringp value)
    (mongo--parse-mechanism-properties-string value))
   ((and (listp value)
         (consp (car value)))
    (mapcar (lambda (pair)
              (mongo--mechanism-property-pair
               (car pair)
               (cdr pair)))
            value))
   ((listp value)
    (mongo--mechanism-properties-from-plist value))
   (t
    (signal 'mongo-error
            (list (format "Invalid MongoDB auth mechanism properties: %S"
                          value))))))

(defun mongo--params-mechanism-properties (params options)
  "Return auth mechanism properties from PARAMS or URI OPTIONS."
  (mongo--mechanism-properties-value
   (or (plist-get params :auth-mechanism-properties)
       (plist-get params :authMechanismProperties)
       (plist-get params :mechanism-properties)
       (mongo--url-option options "authMechanismProperties"))))

(defun mongo--mechanism-property (properties name)
  "Return auth mechanism property NAME from PROPERTIES."
  (cdr (assoc (mongo--mechanism-property-name name) properties)))

(defun mongo--oidc-mechanism-environment (properties)
  "Return normalized MONGODB-OIDC ENVIRONMENT from PROPERTIES, or nil."
  (when-let* ((environment (mongo--mechanism-property properties "ENVIRONMENT")))
    (downcase environment)))

(defun mongo--oidc-token-resource (properties)
  "Return MONGODB-OIDC TOKEN_RESOURCE from PROPERTIES, or nil."
  (mongo--mechanism-property properties "TOKEN_RESOURCE"))

(defun mongo--validate-mechanism-properties (mechanism properties)
  "Validate auth mechanism PROPERTIES for MECHANISM."
  (when properties
    (cond
     ((mongo--aws-auth-mechanism-p mechanism)
      (dolist (property properties)
        (unless (member (car property) '("AWS_SESSION_TOKEN"))
          (signal 'mongo-error
                  (list (format "Unsupported MongoDB MONGODB-AWS auth mechanism property: %s"
                                (car property)))))))
     ((mongo--oidc-auth-mechanism-p mechanism)
      (dolist (property properties)
        (unless (member (car property) '("ENVIRONMENT" "TOKEN_RESOURCE"))
          (signal 'mongo-error
                  (list (format "Unsupported MongoDB MONGODB-OIDC auth mechanism property: %s"
                                (car property)))))))
     (t
      (signal 'mongo-error
              (list "MongoDB authMechanismProperties are currently supported only for MONGODB-AWS and MONGODB-OIDC"))))))

(defun mongo--validate-oidc-configuration
    (properties oidc-callback oidc-human-callback)
  "Validate MONGODB-OIDC PROPERTIES and callback configuration."
  (let ((environment (mongo--oidc-mechanism-environment properties))
        (token-resource (mongo--oidc-token-resource properties)))
    (when (and environment
               (not (member environment '("test" "azure" "gcp" "k8s"))))
      (signal 'mongo-error
              (list (format "Unsupported MongoDB MONGODB-OIDC ENVIRONMENT: %s"
                            environment))))
    (when (and environment
               (or oidc-callback oidc-human-callback))
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC ENVIRONMENT cannot be combined with :oidc-callback or :oidc-human-callback")))
    (when (and oidc-callback oidc-human-callback)
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC cannot use both :oidc-callback and :oidc-human-callback")))
    (cond
     ((and token-resource
           (not (member environment '("azure" "gcp"))))
      (signal 'mongo-error
              (list "MongoDB MONGODB-OIDC TOKEN_RESOURCE requires ENVIRONMENT:azure or ENVIRONMENT:gcp")))
     ((and (member environment '("azure" "gcp"))
           (not (mongo--nonempty-string token-resource)))
      (signal 'mongo-error
              (list (format "MongoDB MONGODB-OIDC ENVIRONMENT:%s requires TOKEN_RESOURCE"
                            environment)))))))

(defun mongo--oidc-allowed-hosts-value (value)
  "Return normalized MONGODB-OIDC allowed hosts from VALUE."
  (let ((hosts (cond
                ((stringp value)
                 (list value))
                ((vectorp value)
                 (append value nil))
                ((listp value)
                 value)
                (t
                 (signal 'mongo-error
                         (list (format "MongoDB MONGODB-OIDC :oidc-allowed-hosts must be a string or sequence of strings, got %S"
                                       value)))))))
    (dolist (host hosts)
      (unless (and (stringp host)
                   (not (string-empty-p host)))
        (signal 'mongo-error
                (list (format "MongoDB MONGODB-OIDC allowed host must be a non-empty string, got %S"
                              host)))))
    hosts))

(defun mongo--params-oidc-allowed-hosts (params)
  "Return MONGODB-OIDC human callback allowed hosts for PARAMS."
  (let ((specified nil)
        value)
    (dolist (key '(:oidc-allowed-hosts :oidcAllowedHosts))
      (when (and (not specified)
                 (plist-member params key))
        (setq specified t
              value (plist-get params key))))
    (if specified
        (mongo--oidc-allowed-hosts-value value)
      mongo--oidc-default-allowed-hosts)))

(defun mongo--params-api-bool (params options keys option-key)
  "Return (SPECIFIED . VALUE) for boolean KEYS or URL OPTION-KEY."
  (let ((found nil)
        value)
    (dolist (key keys)
      (when (and (not found)
                 (plist-member params key))
        (setq found t
              value (plist-get params key))))
    (if found
        (cons t value)
      (when-let* ((option (mongo--url-option options option-key)))
        (cons t (mongo--truthy-url-option-p option))))))

(defun mongo--params-server-api-version (params options)
  "Return requested MongoDB Stable API version from PARAMS or OPTIONS."
  (let ((value (or (plist-get params :server-api)
                   (plist-get params :serverApi)
                   (plist-get params :server-api-version)
                   (plist-get params :api-version)
                   (plist-get params :apiVersion)
                   (mongo--url-option options "serverApi")
                   (mongo--url-option options "apiVersion"))))
    (when value
      (format "%s" value))))

(defun mongo--params-server-api (params)
  "Return a `mongo--server-api' from PARAMS, or nil."
  (let* ((options (mongo--params-effective-url-options params))
         (version (mongo--params-server-api-version params options))
         (strict (mongo--params-api-bool
                  params options
                  '(:api-strict :apiStrict :server-api-strict)
                  "apiStrict"))
         (deprecation-errors
          (mongo--params-api-bool
           params options
           '(:api-deprecation-errors :apiDeprecationErrors
             :server-api-deprecation-errors)
           "apiDeprecationErrors")))
    (when (and (not version)
               (or strict deprecation-errors))
      (signal 'mongo-error
              (list "MongoDB Stable API requires :server-api or :api-version when apiStrict/apiDeprecationErrors is set")))
    (when version
      (make-mongo--server-api
       :version version
       :strict (if strict (cdr strict) mongo--unset)
       :deprecation-errors (if deprecation-errors
                               (cdr deprecation-errors)
                             mongo--unset)))))

(defun mongo--validate-app-name (app-name)
  "Return valid MongoDB handshake APP-NAME, or signal."
  (when app-name
    (unless (stringp app-name)
      (signal 'mongo-error
              (list (format "MongoDB appName must be a string, got %S"
                            app-name))))
    (when (> (length (mongo--utf8-bytes app-name)) 128)
      (signal 'mongo-error
              (list "MongoDB appName cannot exceed 128 UTF-8 bytes")))
    app-name))

(defun mongo--params-app-name (params)
  "Return MongoDB handshake appName from PARAMS or URI options, or nil."
  (let* ((options (mongo--params-effective-url-options params))
         (value (or (plist-get params :app-name)
                    (plist-get params :appName)
                    (plist-get params :application-name)
                    (plist-get params :applicationName)
                    (mongo--url-option options "appName"))))
    (mongo--validate-app-name value)))

(defun mongo--server-api-fields (server-api)
  "Return command fields for SERVER-API."
  (when server-api
    `(("apiVersion" . ,(mongo--server-api-version server-api))
      ,@(unless (eq (mongo--server-api-strict server-api)
                    mongo--unset)
          `(("apiStrict" . ,(if (mongo--server-api-strict server-api)
                                t :false))))
      ,@(unless (eq (mongo--server-api-deprecation-errors server-api)
            mongo--unset)
        `(("apiDeprecationErrors" .
           ,(if (mongo--server-api-deprecation-errors server-api)
                t :false)))))))

(defun mongo--normalize-read-preference-mode (mode)
  "Return canonical MongoDB read preference MODE, or signal."
  (let ((normalized (and mode
                         (replace-regexp-in-string
                          "[-_]" ""
                          (downcase (format "%s" mode))))))
    (pcase normalized
      ((or 'nil "" "primary") "primary")
      ("primarypreferred" "primaryPreferred")
      ("secondary" "secondary")
      ("secondarypreferred" "secondaryPreferred")
      ("nearest" "nearest")
      (_
       (signal 'mongo-error
               (list (format "Unsupported MongoDB readPreference: %s"
                             mode)))))))

(defun mongo--params-read-preference-mode (params options)
  "Return requested MongoDB read preference mode from PARAMS or OPTIONS."
  (mongo--normalize-read-preference-mode
   (or (plist-get params :read-preference)
       (plist-get params :readPreference)
       (mongo--url-option options "readPreference")
       "primary")))

(defun mongo--parse-integer-option (value name)
  "Return VALUE parsed as an integer for MongoDB option NAME."
  (cond
   ((null value) nil)
   ((integerp value) value)
   ((and (stringp value)
         (string-match-p "\\`-?[0-9]+\\'" value))
    (string-to-number value))
   (t
    (signal 'mongo-error
            (list (format "MongoDB %s must be an integer, got %S"
                          name value))))))

(defun mongo--params-option-value (params keys url-name)
  "Return PARAMS option from KEYS or URL-NAME."
  (or (seq-some (lambda (key)
                  (and (plist-member params key)
                       (plist-get params key)))
                keys)
      (let ((options (mongo--params-effective-url-options params)))
        (mongo--url-option options url-name))))

(defun mongo--params-raw-url-option (params key)
  "Return raw URL option KEY from PARAMS without SRV TXT merging."
  (when-let* ((parts (mongo--params-url-parts params)))
    (mongo--url-option (plist-get parts :options) key)))

(defun mongo--params-raw-option-value (params keys url-name)
  "Return PARAMS option from KEYS or raw URL-NAME without SRV TXT merging."
  (catch 'found
    (dolist (key keys)
      (when (plist-member params key)
        (throw 'found (plist-get params key))))
    (mongo--params-raw-url-option params url-name)))

(defun mongo--params-raw-bool-option-p (params keys url-name)
  "Return raw boolean option URL-NAME from PARAMS.
Structured PARAMS values are used as booleans directly; URI values are parsed
with MongoDB URI boolean rules."
  (let ((value (mongo--params-raw-option-value params keys url-name)))
    (if (stringp value)
        (mongo--url-bool-option-value value url-name)
      value)))

(defun mongo--params-bool-option-p (params keys url-name)
  "Return boolean option URL-NAME from PARAMS or effective URL options."
  (let ((value (mongo--params-option-value params keys url-name)))
    (if (stringp value)
        (mongo--url-bool-option-value value url-name)
      value)))

(defun mongo--params-nonnegative-integer-option
    (params keys url-name display-name)
  "Return non-negative integer option DISPLAY-NAME from PARAMS."
  (let ((value (mongo--params-option-value params keys url-name)))
    (when-let* ((number (mongo--parse-integer-option value display-name)))
      (when (< number 0)
        (signal 'mongo-error
                (list (format "MongoDB %s must be non-negative"
                              display-name))))
      number)))

(defun mongo--params-connect-timeout (params)
  "Return MongoDB connect timeout seconds for PARAMS."
  (or (plist-get params :connect-timeout)
      (let* ((options (mongo--params-effective-url-options params))
             (millis (mongo--parse-integer-option
                      (mongo--url-option options "connectTimeoutMS")
                      "connectTimeoutMS")))
        (when millis
          (when (< millis 0)
            (signal 'mongo-error
                    (list "MongoDB connectTimeoutMS must be non-negative")))
          (/ millis 1000.0)))
      mongo-connect-timeout-seconds))

(defun mongo--params-server-selection-timeout (params)
  "Return MongoDB server selection timeout seconds for PARAMS."
  (cond
   ((plist-member params :server-selection-timeout)
    (let ((value (plist-get params :server-selection-timeout)))
      (when (or (not (numberp value))
                (< value 0))
        (signal 'mongo-error
                (list "MongoDB serverSelectionTimeout must be a non-negative number")))
      value))
   ((plist-member params :serverSelectionTimeout)
    (let ((value (plist-get params :serverSelectionTimeout)))
      (when (or (not (numberp value))
                (< value 0))
        (signal 'mongo-error
                (list "MongoDB serverSelectionTimeout must be a non-negative number")))
      value))
   (t
    (let* ((options (mongo--params-effective-url-options params))
           (millis (mongo--parse-integer-option
                    (mongo--url-option options "serverSelectionTimeoutMS")
                    "serverSelectionTimeoutMS")))
      (if millis
          (progn
            (when (< millis 0)
              (signal 'mongo-error
                      (list "MongoDB serverSelectionTimeoutMS must be non-negative")))
            (/ millis 1000.0))
        mongo-server-selection-timeout-seconds)))))

(defun mongo--params-server-selection-try-once-p (params)
  "Return non-nil when MongoDB server selection scans only once.
This single-threaded driver option defaults to true, matching the MongoDB URI
option semantics for single-threaded drivers."
  (let ((options (mongo--params-effective-url-options params)))
    (cond
     ((plist-member params :server-selection-try-once)
      (mongo--boolean-param-value
       (plist-get params :server-selection-try-once)
       "serverSelectionTryOnce"))
     ((plist-member params :serverSelectionTryOnce)
      (mongo--boolean-param-value
       (plist-get params :serverSelectionTryOnce)
       "serverSelectionTryOnce"))
     ((mongo--url-option options "serverSelectionTryOnce")
      (mongo--url-bool-option-value
       (mongo--url-option options "serverSelectionTryOnce")
       "serverSelectionTryOnce"))
     (t t))))

(defun mongo--params-socket-timeout (params)
  "Return MongoDB socket timeout seconds for PARAMS, or nil."
  (or (plist-get params :socket-timeout)
      (plist-get params :socketTimeout)
      (let* ((options (mongo--params-effective-url-options params))
             (millis (mongo--parse-integer-option
                      (or (plist-get params :socket-timeout-ms)
                          (plist-get params :socketTimeoutMS)
                          (mongo--url-option options "socketTimeoutMS"))
                      "socketTimeoutMS")))
        (when millis
          (when (< millis 0)
            (signal 'mongo-error
                    (list "MongoDB socketTimeoutMS must be non-negative")))
          (/ millis 1000.0)))))

(defun mongo--params-proxy-option-present-p (params keys url-name options)
  "Return non-nil when PARAMS or OPTIONS explicitly include URL-NAME."
  (or (seq-some (lambda (key)
                  (plist-member params key))
                keys)
      (mongo--url-option-present-p options url-name)))

(defun mongo--params-proxy-string (value name &optional empty-is-nil)
  "Return validated MongoDB SOCKS5 proxy string VALUE for NAME."
  (cond
   ((null value) nil)
   ((not (stringp value))
    (signal 'mongo-error
            (list (format "MongoDB %s must be a string, got %S"
                          name value))))
   ((string-empty-p value)
    (if empty-is-nil
        nil
      (signal 'mongo-error
              (list (format "MongoDB %s must not be empty" name)))))
   (t value)))

(defun mongo--params-proxy-auth-part (value name)
  "Return validated SOCKS5 username/password VALUE for NAME."
  (when-let* ((string (mongo--params-proxy-string value name t)))
    (when (> (length (mongo--utf8-bytes string)) 255)
      (signal 'mongo-error
              (list (format "MongoDB SOCKS5 %s cannot exceed 255 UTF-8 bytes"
                            name))))
    string))

(defun mongo--params-proxy (params)
  "Return SOCKS5 proxy settings from MongoDB PARAMS, or nil.
The returned plist contains :host, :port, :username, and :password.  MongoDB
SOCKS5 URI options use proxyHost, proxyPort, proxyUsername, and proxyPassword."
  (let* ((options (mongo--params-effective-url-options params))
         (host (mongo--params-proxy-string
                (mongo--params-option-value
                 params '(:proxy-host :proxyHost) "proxyHost")
                "proxyHost"))
         (port-present
          (mongo--params-proxy-option-present-p
           params '(:proxy-port :proxyPort) "proxyPort" options))
         (username-present
          (mongo--params-proxy-option-present-p
           params '(:proxy-username :proxyUsername) "proxyUsername" options))
         (password-present
          (mongo--params-proxy-option-present-p
           params '(:proxy-password :proxyPassword) "proxyPassword" options))
         (port-value (mongo--params-option-value
                      params '(:proxy-port :proxyPort) "proxyPort"))
         (username (mongo--params-proxy-auth-part
                    (mongo--params-option-value
                     params '(:proxy-username :proxyUsername) "proxyUsername")
                    "proxyUsername"))
         (password (mongo--params-proxy-auth-part
                    (mongo--params-option-value
                     params '(:proxy-password :proxyPassword) "proxyPassword")
                    "proxyPassword"))
         (port (mongo--parse-integer-option port-value "proxyPort")))
    (when (and (not host)
               (or port-present username-present password-present))
      (signal 'mongo-error
              (list "MongoDB SOCKS5 proxy options require proxyHost")))
    (when (and host port
               (or (<= port 0)
                   (> port 65535)))
      (signal 'mongo-error
              (list "MongoDB proxyPort must be an integer between 1 and 65535")))
    (when (and username (not password))
      (signal 'mongo-error
              (list "MongoDB SOCKS5 proxyUsername requires proxyPassword")))
    (when (and password (not username))
      (signal 'mongo-error
              (list "MongoDB SOCKS5 proxyPassword requires proxyUsername")))
    (when host
      (list :host host
            :port (or port 1080)
            :username username
            :password password))))

(defun mongo--params-operation-timeout (params)
  "Return MongoDB default operation timeout seconds for PARAMS, or nil."
  (or (plist-get params :operation-timeout)
      (plist-get params :operationTimeout)
      (let* ((options (mongo--params-effective-url-options params))
             (millis (mongo--parse-integer-option
                      (or (plist-get params :timeout-ms)
                          (plist-get params :timeoutMS)
                          (plist-get params :operation-timeout-ms)
                          (plist-get params :operationTimeoutMS)
                          (mongo--url-option options "timeoutMS"))
                      "timeoutMS")))
        (when millis
          (when (< millis 0)
            (signal 'mongo-error
                    (list "MongoDB timeoutMS must be non-negative")))
          (/ millis 1000.0)))))

(defun mongo--params-local-threshold (params)
  "Return MongoDB localThresholdMS for PARAMS in seconds."
  (cond
   ((plist-member params :local-threshold)
    (let ((value (plist-get params :local-threshold)))
      (when (or (not (numberp value))
                (< value 0))
        (signal 'mongo-error
                (list "MongoDB localThreshold must be a non-negative number")))
      value))
   (t
    (let ((millis (mongo--params-nonnegative-integer-option
                   params
                   '(:local-threshold-ms :localThresholdMS)
                   "localThresholdMS"
                   "localThresholdMS")))
      (if millis
          (/ millis 1000.0)
        mongo-local-threshold-seconds)))))

(defun mongo--params-heartbeat-frequency (params)
  "Return MongoDB heartbeatFrequencyMS for PARAMS in seconds, or nil."
  (or (plist-get params :heartbeat-frequency)
      (let ((millis (mongo--params-nonnegative-integer-option
                     params
                     '(:heartbeat-frequency-ms :heartbeatFrequencyMS)
                     "heartbeatFrequencyMS"
                     "heartbeatFrequencyMS")))
        (when millis
          (when (zerop millis)
            (signal 'mongo-error
                    (list "MongoDB heartbeatFrequencyMS must be greater than zero")))
          (/ millis 1000.0)))))

(defun mongo--params-server-monitoring-mode (params)
  "Return MongoDB serverMonitoringMode for PARAMS as a symbol."
  (let* ((options (mongo--params-effective-url-options params))
         (mode (or (plist-get params :server-monitoring-mode)
                   (plist-get params :serverMonitoringMode)
                   (mongo--url-option options "serverMonitoringMode"))))
    (when mode
      (pcase (downcase (format "%s" mode))
        ("auto" 'auto)
        ("stream" 'stream)
        ("poll" 'poll)
        (_
         (signal 'mongo-error
                 (list (format "Unsupported MongoDB serverMonitoringMode: %s"
                               mode))))))))

(defun mongo--params-srv-service-name (params)
  "Return MongoDB srvServiceName for PARAMS."
  (mongo--validate-srv-service-name
   (or (plist-get params :srv-service-name)
       (plist-get params :srvServiceName)
       (mongo--params-raw-url-option params "srvServiceName")
       "mongodb")))

(defun mongo--params-srv-max-hosts (params)
  "Return MongoDB srvMaxHosts for PARAMS, or nil when unbounded."
  (let ((value (or (and (plist-member params :srv-max-hosts)
                        (plist-get params :srv-max-hosts))
                   (and (plist-member params :srvMaxHosts)
                        (plist-get params :srvMaxHosts))
                   (mongo--params-raw-url-option params "srvMaxHosts"))))
    (when-let* ((hosts (mongo--parse-integer-option value "srvMaxHosts")))
      (when (< hosts 0)
        (signal 'mongo-error
                (list "MongoDB srvMaxHosts must be non-negative")))
      (and (not (zerop hosts))
           hosts))))

(defun mongo--params-max-pool-size (params)
  "Return MongoDB maxPoolSize for PARAMS.
A nil return value means the pool is unbounded."
  (let ((size (mongo--params-nonnegative-integer-option
               params
               '(:max-pool-size :maxPoolSize)
               "maxPoolSize"
               "maxPoolSize")))
    (cond
     ((null size) mongo--default-max-pool-size)
     ((zerop size) nil)
     (t size))))

(defun mongo--params-min-pool-size (params)
  "Return MongoDB minPoolSize for PARAMS."
  (or (mongo--params-nonnegative-integer-option
       params
       '(:min-pool-size :minPoolSize)
       "minPoolSize"
       "minPoolSize")
      mongo--default-min-pool-size))

(defun mongo--params-max-connecting (params)
  "Return MongoDB maxConnecting for PARAMS."
  (let ((value (mongo--params-nonnegative-integer-option
                params
                '(:max-connecting :maxConnecting)
                "maxConnecting"
                "maxConnecting")))
    (cond
     ((null value) mongo--default-max-connecting)
     ((zerop value)
      (signal 'mongo-error
              (list "MongoDB maxConnecting must be greater than zero")))
     (t value))))

(defun mongo--params-max-idle-time (params)
  "Return MongoDB maxIdleTimeMS for PARAMS in seconds, or nil."
  (or (plist-get params :max-idle-time)
      (let ((millis (mongo--params-nonnegative-integer-option
                     params
                     '(:max-idle-time-ms :maxIdleTimeMS)
                     "maxIdleTimeMS"
                     "maxIdleTimeMS")))
        (and millis
             (not (zerop millis))
             (/ millis 1000.0)))))

(defun mongo--params-wait-queue-timeout (params)
  "Return MongoDB waitQueueTimeoutMS for PARAMS in seconds, or nil.
A nil return value means the wait queue has no configured deadline."
  (or (when (plist-member params :wait-queue-timeout)
        (let ((value (plist-get params :wait-queue-timeout)))
          (when (or (not (numberp value))
                    (< value 0))
            (signal 'mongo-error
                    (list "MongoDB waitQueueTimeoutMS must be non-negative")))
          (and (not (zerop value))
               value)))
      (let ((millis (mongo--params-nonnegative-integer-option
                     params
                     '(:wait-queue-timeout-ms :waitQueueTimeoutMS)
                     "waitQueueTimeoutMS"
                     "waitQueueTimeoutMS")))
        (and millis
             (not (zerop millis))
             (/ millis 1000.0)))))

(defun mongo--params-validate-pool-options (params)
  "Validate MongoDB connection pool options in PARAMS."
  (let ((max-size (mongo--params-max-pool-size params))
        (min-size (mongo--params-min-pool-size params)))
    (when (and max-size
               (> min-size max-size))
      (signal 'mongo-error
              (list "MongoDB minPoolSize must be less than or equal to maxPoolSize")))))

(defun mongo--boolean-param-value (value name)
  "Return VALUE parsed as a boolean MongoDB option NAME."
  (cond
   ((or (eq value t) (eq value :true)) t)
   ((or (null value) (eq value :false)) nil)
   ((stringp value)
    (mongo--url-bool-option-value value name))
   (t
    (signal 'mongo-error
            (list (format "MongoDB %s must be a boolean, got %S"
                          name value))))))

(defun mongo--params-retry-reads-p (params)
  "Return non-nil when PARAMS enable MongoDB retryable reads.
The MongoDB driver option defaults to enabled unless explicitly disabled."
  (let ((options (mongo--params-effective-url-options params)))
    (cond
     ((plist-member params :retry-reads)
      (mongo--boolean-param-value
       (plist-get params :retry-reads)
       "retryReads"))
     ((plist-member params :retryReads)
      (mongo--boolean-param-value
       (plist-get params :retryReads)
       "retryReads"))
     ((mongo--url-option options "retryReads")
      (mongo--url-bool-option-value
       (mongo--url-option options "retryReads")
       "retryReads"))
     (t t))))

(defun mongo--params-retry-writes-p (params)
  "Return non-nil when PARAMS enable MongoDB retryable writes.
The MongoDB driver option defaults to enabled unless explicitly disabled."
  (let ((options (mongo--params-effective-url-options params)))
    (cond
     ((plist-member params :retry-writes)
      (mongo--boolean-param-value
       (plist-get params :retry-writes)
       "retryWrites"))
     ((plist-member params :retryWrites)
      (mongo--boolean-param-value
       (plist-get params :retryWrites)
       "retryWrites"))
     ((mongo--url-option options "retryWrites")
      (mongo--url-bool-option-value
       (mongo--url-option options "retryWrites")
       "retryWrites"))
     (t t))))

(defun mongo--params-with-connect-timeout-limit (params timeout)
  "Return PARAMS with :connect-timeout capped to TIMEOUT seconds."
  (let* ((base-timeout (mongo--params-connect-timeout params))
         (effective (min base-timeout timeout))
         (copy (copy-sequence params)))
    (plist-put copy :connect-timeout effective)
    copy))

(defun mongo--read-preference-tag-document (value)
  "Return VALUE as a MongoDB read preference tag document."
  (cond
   ((or (null value)
        (and (stringp value)
             (string-empty-p value)))
    (mongo-document nil))
   ((mongo-document-p value) value)
   ((and (consp value)
         (consp (car value)))
    value)
   ((stringp value)
    (let (pairs)
      (dolist (part (split-string value "," t "[[:space:]\n\r\t]+"))
        (let ((colon (cl-position ?: part)))
          (unless colon
            (signal 'mongo-error
                    (list (format "MongoDB readPreferenceTags entry lacks ':' in %S"
                                  part))))
          (push (cons (substring part 0 colon)
                      (substring part (1+ colon)))
                pairs)))
      (nreverse pairs)))
   (t
    (signal 'mongo-error
            (list (format "Invalid MongoDB readPreferenceTags value: %S"
                          value))))))

(defun mongo--params-read-preference-tags (params options)
  "Return read preference tag sets from PARAMS or URI OPTIONS."
  (let* ((plist-value (or (plist-get params :read-preference-tags)
                          (plist-get params :readPreferenceTags)))
         (values (cond
                  ((null plist-value)
                   (mongo--url-options options "readPreferenceTags"))
                  ((vectorp plist-value)
                   (append plist-value nil))
                  ((and (consp plist-value)
                        (consp (car plist-value))
                        (consp (caar plist-value)))
                   (append plist-value nil))
                  (t
                   (list plist-value)))))
    (when values
      (vconcat
       (mapcar #'mongo--read-preference-tag-document values)))))

(defun mongo--params-max-staleness-seconds (params options)
  "Return maxStalenessSeconds from PARAMS and OPTIONS.
MongoDB drivers treat -1 as unset and require positive values to be at least
90 seconds."
  (let ((value (mongo--parse-integer-option
                (or (plist-get params :max-staleness-seconds)
                    (plist-get params :maxStalenessSeconds)
                    (mongo--url-option options "maxStalenessSeconds"))
                "maxStalenessSeconds")))
    (when value
      (cond
       ((= value -1) nil)
       ((or (< value 0)
            (< value 90))
        (signal 'mongo-error
                (list "MongoDB maxStalenessSeconds must be -1 or at least 90 seconds")))
       (t value)))))

(defun mongo--params-read-preference (params)
  "Return a `mongo--read-preference' from PARAMS."
  (let* ((options (mongo--params-effective-url-options params))
         (mode (mongo--params-read-preference-mode params options))
         (tags (mongo--params-read-preference-tags params options))
         (max-staleness (mongo--params-max-staleness-seconds
                         params options))
         (heartbeat (or (mongo--params-heartbeat-frequency params)
                        mongo-monitor-heartbeat-seconds)))
    (when (and (equal mode "primary")
               (or tags max-staleness))
      (signal 'mongo-error
              (list "MongoDB readPreference=primary cannot use readPreferenceTags or maxStalenessSeconds")))
    (when (and max-staleness
               (< max-staleness
                  (+ heartbeat mongo--idle-write-period-seconds)))
      (signal 'mongo-error
              (list "MongoDB maxStalenessSeconds must be at least heartbeatFrequencyMS plus 10 seconds")))
    (make-mongo--read-preference
     :mode mode
     :tags tags
     :max-staleness-seconds max-staleness)))

(defun mongo--read-preference-document (read-preference)
  "Return READ-PREFERENCE as a MongoDB $readPreference document."
  (when (and read-preference
             (not (equal (mongo--read-preference-mode read-preference)
                         "primary")))
    `(("mode" . ,(mongo--read-preference-mode read-preference))
      ,@(when (mongo--read-preference-tags read-preference)
          `(("tags" . ,(mongo--read-preference-tags read-preference))))
      ,@(when (mongo--read-preference-max-staleness-seconds
               read-preference)
          `(("maxStalenessSeconds" .
             ,(mongo--read-preference-max-staleness-seconds
               read-preference)))))))

(defun mongo--read-concern-document-value (value)
  "Return VALUE as a MongoDB readConcern document."
  (cond
   ((null value) nil)
   ((mongo-document-p value) value)
   ((and (consp value)
         (consp (car value)))
    value)
   (t
    `(("level" . ,(format "%s" value))))))

(defun mongo--params-read-concern (params)
  "Return a `mongo--read-concern' from PARAMS, or nil."
  (let* ((options (mongo--params-effective-url-options params))
         (value (or (plist-get params :read-concern)
                    (plist-get params :readConcern)))
         (level (or (plist-get params :read-concern-level)
                    (plist-get params :readConcernLevel)
                    (mongo--url-option options "readConcernLevel")))
         (document (or (mongo--read-concern-document-value value)
                       (and level
                            `(("level" . ,(format "%s" level)))))))
    (when document
      (make-mongo--read-concern :pairs document))))

(defun mongo--read-concern-document (read-concern)
  "Return READ-CONCERN as a MongoDB readConcern document."
  (and read-concern
       (mongo--read-concern-pairs read-concern)))

(defun mongo--read-concern-command-document (read-concern)
  "Return READ-CONCERN as a MongoDB command document."
  (cond
   ((null read-concern) nil)
   ((mongo--read-concern-p read-concern)
    (mongo--read-concern-document read-concern))
   (t
    (mongo--read-concern-document-value read-concern))))

(defun mongo--write-concern-w-value (value)
  "Return MongoDB write concern w VALUE normalized for BSON."
  (cond
   ((null value) nil)
   ((integerp value) value)
   ((and (stringp value)
         (string-match-p "\\`[0-9]+\\'" value))
    (string-to-number value))
   (t (format "%s" value))))

(defun mongo--params-bool-option (params options keys option-key)
  "Return (SPECIFIED . VALUE) for boolean KEYS or URL OPTION-KEY."
  (let ((found nil)
        value)
    (dolist (key keys)
      (when (and (not found)
                 (plist-member params key))
        (setq found t
              value (plist-get params key))))
    (cond
     (found (cons t (if value t :false)))
     ((mongo--url-option options option-key)
      (let ((option (mongo--url-option options option-key)))
        (cond
         ((mongo--truthy-url-option-p option)
          (cons t t))
         ((mongo--falsey-url-option-p option)
          (cons t :false))
         (t
          (signal 'mongo-error
                  (list (format "MongoDB %s must be a boolean, got %S"
                                option-key option))))))))))

(defun mongo--write-concern-document-value (value)
  "Return VALUE as a MongoDB writeConcern document, or nil."
  (cond
   ((null value) nil)
   ((mongo-document-p value) value)
   ((and (consp value)
         (consp (car value)))
    value)
   (t
    (signal 'mongo-error
            (list (format "Invalid MongoDB writeConcern value: %S"
                          value))))))

(defun mongo--params-write-concern (params)
  "Return a `mongo--write-concern' from PARAMS, or nil."
  (let* ((options (mongo--params-effective-url-options params))
         (value (or (plist-get params :write-concern)
                    (plist-get params :writeConcern)))
         (w (mongo--write-concern-w-value
             (or (plist-get params :w)
                 (mongo--url-option options "w"))))
         (wtimeout
          (mongo--parse-integer-option
           (or (plist-get params :w-timeout-ms)
               (plist-get params :wtimeoutms)
               (plist-get params :wTimeoutMS)
               (mongo--url-option options "wTimeoutMS"))
           "wTimeoutMS"))
         (journal (mongo--params-bool-option
                   params options
                   '(:journal :j)
                   "journal"))
         (document (copy-sequence
                    (mongo--write-concern-document-value value))))
    (when (and wtimeout
               (< wtimeout 0))
      (signal 'mongo-error
              (list "MongoDB wTimeoutMS must be non-negative")))
    (when (and w
               (not (assoc "w" document)))
      (setq document (append document (list (cons "w" w)))))
    (when (and wtimeout
               (not (assoc "wtimeout" document)))
      (setq document
            (append document (list (cons "wtimeout" wtimeout)))))
    (when (and journal
               (not (assoc "j" document)))
      (setq document
            (append document (list (cons "j" (cdr journal))))))
    (when document
      (make-mongo--write-concern :pairs document))))

(defun mongo--write-concern-document (write-concern)
  "Return WRITE-CONCERN as a MongoDB writeConcern document."
  (and write-concern
       (mongo--write-concern-pairs write-concern)))

(defun mongo--normalize-compressor (compressor)
  "Return normalized MongoDB wire COMPRESSOR name."
  (downcase (format "%s" compressor)))

(defun mongo--compressor-values (value)
  "Return a list of compressor names parsed from VALUE."
  (cond
   ((null value) nil)
   ((listp value)
    (mapcar #'mongo--normalize-compressor value))
   ((vectorp value)
    (mapcar #'mongo--normalize-compressor (append value nil)))
   (t
    (mapcar #'mongo--normalize-compressor
            (split-string (format "%s" value) "," t "[[:space:]\n\r\t]*")))))

(defun mongo--params-zlib-compression-level (params)
  "Return zlibCompressionLevel from PARAMS, or nil when omitted.
MongoDB defines valid zlib compression levels as -1 through 9."
  (let* ((options (mongo--params-effective-url-options params))
         (value (mongo--parse-integer-option
                 (or (plist-get params :zlib-compression-level)
                     (plist-get params :zlibCompressionLevel)
                     (mongo--url-option options "zlibCompressionLevel"))
                 "zlibCompressionLevel")))
    (when value
      (when (or (< value -1)
                (> value 9))
        (signal 'mongo-error
                (list "MongoDB zlibCompressionLevel must be between -1 and 9")))
      value)))

(defun mongo--validate-zlib-compression-level (params compressors)
  "Validate zlibCompressionLevel in PARAMS for requested COMPRESSORS.
Emacs exposes zlib decompression but not compression-level control.  The
native encoder can emit valid zlib stored-block streams, equivalent to level 0;
explicit non-zero levels are rejected rather than silently ignored."
  (when-let* ((level (mongo--params-zlib-compression-level params)))
    (when (and (member "zlib" compressors)
               (not (zerop level)))
      (signal 'mongo-error
              (list "MongoDB zlibCompressionLevel values other than 0 require zlib compression support not available in Emacs")))))

(defun mongo--params-compressors (params)
  "Return requested MongoDB wire compressors for PARAMS."
  (let* ((options (mongo--params-effective-url-options params))
         (values (mongo--compressor-values
                  (or (plist-get params :compressors)
                      (plist-get params :compression)
                      (mongo--url-option options "compressors"))))
         compressors)
    (dolist (compressor values)
      (pcase compressor
        ((or "disabled" "none" "")
         nil)
        ((or "zlib" "snappy" "noop" "zstd")
         (push compressor compressors))
        (_
         (signal 'mongo-error
                 (list (format "Unknown MongoDB wire compressor: %s"
                               compressor))))))
    (setq compressors (nreverse (delete-dups compressors)))
    (when (member "zlib" compressors)
      (unless (and (fboundp 'zlib-available-p)
                   (zlib-available-p))
        (signal 'mongo-error
                (list "MongoDB zlib wire compression requires zlib support in Emacs"))))
    (when (member "zstd" compressors)
      (unless (mongo--zstd-available-p)
        (signal 'mongo-error
                (list "MongoDB zstd wire compression requires `mongo-zstd-program' executable"))))
    (mongo--validate-zlib-compression-level params compressors)
    compressors))

(defun mongo--negotiated-compressors (requested server)
  "Return compressors common to REQUESTED and SERVER, preserving REQUESTED order."
  (let ((server (cond
                 ((vectorp server) (append server nil))
                 ((listp server) server)
                 (server (list server)))))
    (cl-remove-if-not (lambda (compressor)
                        (member compressor server))
                      requested)))

(defun mongo--params-tls-enabled-p (params)
  "Return non-nil when PARAMS request MongoDB TLS."
  (let* ((parts (mongo--params-url-parts params))
         (options (mongo--params-effective-url-options params))
         (tls-option (mongo--url-option options "tls"))
         (ssl-option (mongo--url-option options "ssl")))
    (cond
     ((plist-member params :tls)
      (plist-get params :tls))
     (tls-option
      (not (mongo--falsey-url-option-p tls-option)))
     (ssl-option
      (not (mongo--falsey-url-option-p ssl-option)))
     ((and parts (mongo--srv-scheme-p parts))
      t)
     (t nil))))

(defun mongo--params-tls-bool (params options param-key option-key default)
  "Return a TLS boolean from PARAMS, OPTIONS, or DEFAULT."
  (cond
   ((plist-member params param-key)
    (plist-get params param-key))
   ((mongo--url-option options option-key)
    (not (mongo--truthy-url-option-p
          (mongo--url-option options option-key))))
   (t default)))

(defun mongo--params-tls-trustfiles (params options)
  "Return TLS trustfiles from PARAMS or URI OPTIONS."
  (or (plist-get params :tls-trustfiles)
      (plist-get params :trustfiles)
      (when-let* ((file (mongo--url-option options "tlsCAFile")))
        (list file))
      mongo-tls-trustfiles))

(defun mongo--params-tls-keylist (params options)
  "Return TLS client keylist from PARAMS or URI OPTIONS."
  (or (plist-get params :tls-keylist)
      (plist-get params :keylist)
      (when-let* ((file (mongo--url-option options "tlsCertificateKeyFile")))
        (list (list file file)))
      mongo-tls-keylist))

(defun mongo--params-tls-insecure-p (params options)
  "Return non-nil when PARAMS or OPTIONS disable TLS verification."
  (cond
   ((plist-member params :tls-insecure)
    (plist-get params :tls-insecure))
   ((mongo--url-option options "tlsInsecure")
    (mongo--url-bool-option-value
     (mongo--url-option options "tlsInsecure")
     "tlsInsecure"))))

(defun mongo--params-tls-spec (params host)
  "Return TLS negotiation plist for PARAMS and HOST, or nil."
  (when (mongo--params-tls-enabled-p params)
    (let* ((options (mongo--params-effective-url-options params))
           (tls-insecure (mongo--params-tls-insecure-p params options))
           (verify-certificate
            (and (not tls-insecure)
                 (mongo--params-tls-bool
                  params options :tls-verify "tlsAllowInvalidCertificates"
                  mongo-tls-verify-server)))
           (verify-hostname
            (and (not tls-insecure)
                 (mongo--params-tls-bool
                  params options :tls-verify-hostname "tlsAllowInvalidHostnames"
                  verify-certificate)))
           (verify-error (delq nil
                               (list (and verify-certificate :trustfiles)
                                     (and verify-hostname :hostname)))))
      (list :hostname (or (plist-get params :tls-hostname) host)
            :trustfiles (mongo--params-tls-trustfiles params options)
            :keylist (mongo--params-tls-keylist params options)
            :verify-error (and verify-error verify-error)
            :verify-hostname-error verify-hostname))))

(defun mongo--params-credential (params)
  "Return a MongoDB credential from PARAMS, or nil for no auth."
  (let* ((parts (mongo--params-url-parts params))
         (options (mongo--params-effective-url-options params))
         (userinfo (mongo--url-userinfo (plist-get parts :userinfo)))
         (raw-user (or (plist-get params :user)
                       (plist-get userinfo :user)))
         (user (and (stringp raw-user)
                    (> (length raw-user) 0)
                    raw-user))
         (secret (or (plist-get params :password)
                     (plist-get userinfo :password)))
         (mechanism (mongo--params-auth-mechanism params options))
         (x509 (mongo--x509-auth-mechanism-p mechanism))
         (plain (mongo--plain-auth-mechanism-p mechanism))
         (aws (mongo--aws-auth-mechanism-p mechanism))
         (oidc (mongo--oidc-auth-mechanism-p mechanism))
         (mechanism-properties
          (mongo--params-mechanism-properties params options))
         (explicit-source (or (plist-get params :auth-database)
                              (plist-get params :auth-source)
                              (mongo--url-option options "authSource")))
         (source (or explicit-source
                     (and x509 "$external")
                     (and plain "$external")
                     (and aws "$external")
                     (and oidc "$external")
                     (plist-get parts :database)
                     (plist-get params :database)
                     "admin"))
         (aws-credential-provider
          (and aws
               (or (plist-get params :aws-credential-provider)
                   (plist-get params :awsCredentialProvider))))
         (oidc-token (plist-get params :oidc-token))
         (oidc-token-file (or (plist-get params :oidc-token-file)
                              (plist-get params :oidcTokenFile)))
         (oidc-callback (or (plist-get params :oidc-callback)
                            (plist-get params :oidcCallback)))
         (oidc-human-callback
          (or (plist-get params :oidc-human-callback)
              (plist-get params :oidcHumanCallback)))
         (oidc-refresh-token
          (or (plist-get params :oidc-refresh-token)
              (plist-get params :oidcRefreshToken)))
         (oidc-allowed-hosts
          (and oidc
               (mongo--params-oidc-allowed-hosts params)))
         (auth-requested (or (plist-get userinfo :explicit)
                             user
                             secret
                             mechanism)))
    (mongo--validate-mechanism-properties mechanism mechanism-properties)
    (when oidc
      (mongo--validate-oidc-configuration
       mechanism-properties oidc-callback oidc-human-callback))
    (when auth-requested
      (if x509
          (progn
            (when secret
              (signal 'mongo-error
                      (list "MongoDB MONGODB-X509 authentication must not include a password")))
            (unless (equal source "$external")
              (signal 'mongo-error
                      (list "MongoDB MONGODB-X509 authentication requires authSource=$external")))
            (unless (mongo--params-tls-enabled-p params)
              (signal 'mongo-error
                      (list "MongoDB MONGODB-X509 authentication requires TLS with a client certificate"))))
        (when oidc
          (when secret
            (signal 'mongo-error
                    (list "MongoDB MONGODB-OIDC authentication must not include a password")))
          (unless (equal source "$external")
            (signal 'mongo-error
                    (list "MongoDB MONGODB-OIDC authentication requires authSource=$external"))))
        (when (and plain
                   (not (equal source "$external")))
          (signal 'mongo-error
                  (list "MongoDB PLAIN authentication requires authSource=$external")))
        (when (and aws
                   (not (equal source "$external")))
          (signal 'mongo-error
                  (list "MongoDB MONGODB-AWS authentication requires authSource=$external")))
        (if (or aws oidc)
            (when (or user secret)
              (unless (or oidc
                          (and user (stringp secret)))
                (signal 'mongo-error
                        (list "MongoDB MONGODB-AWS authentication requires both AWS access key id and secret access key when credentials are supplied in the URI or params"))))
          (unless user
            (signal 'mongo-error
                    (list "Native MongoDB authentication requires :user or URI username")))
          (unless (stringp secret)
            (signal 'mongo-error
                    (list "Native MongoDB authentication requires :password or URI password")))))
      (make-mongo--credential
       :username user
       :password secret
       :source source
       :mechanism mechanism
       :mechanism-properties mechanism-properties
       :aws-credential-provider aws-credential-provider
       :oidc-token oidc-token
       :oidc-token-file oidc-token-file
       :oidc-callback oidc-callback
       :oidc-human-callback oidc-human-callback
       :oidc-refresh-token oidc-refresh-token
       :oidc-allowed-hosts oidc-allowed-hosts))))

(defun mongo--validate-raw-load-balanced-params (params)
  "Validate loadBalanced constraints that do not need SRV TXT records."
  (when (mongo--params-raw-load-balanced-p params)
    (when (mongo--params-raw-replica-set-name params)
      (signal 'mongo-error
              (list "MongoDB loadBalanced=true cannot be combined with replicaSet")))
    (when (mongo--params-raw-direct-connection-p params)
      (signal 'mongo-error
              (list "MongoDB loadBalanced=true cannot be combined with directConnection=true")))
    (when (mongo--params-srv-max-hosts params)
      (signal 'mongo-error
              (list "MongoDB loadBalanced=true cannot be combined with srvMaxHosts")))))

(defun mongo--validate-raw-srv-max-hosts-params (params)
  "Validate srvMaxHosts constraints that do not need SRV TXT records."
  (when (and (mongo--params-srv-max-hosts params)
             (mongo--params-raw-replica-set-name params))
    (signal 'mongo-error
            (list "MongoDB srvMaxHosts cannot be combined with replicaSet"))))

(defun mongo--reject-unsupported-params (params)
  "Signal if PARAMS need unsupported native MongoDB features."
  (mongo--validate-raw-load-balanced-params params)
  (mongo--validate-raw-srv-max-hosts-params params)
  (mongo--params-validate-pool-options params))

(provide 'mongo-params)

;;; mongo-params.el ends here
