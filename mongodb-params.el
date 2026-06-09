;;; mongodb-params.el --- Connection params and URI parsing -*- lexical-binding: t; -*-

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

;; MongoDB URI parsing, connection params normalization, TLS params,
;; credentials, read/write concern, server API, and pool option helpers.

;;; Code:

(require 'cl-lib)
(require 'dns)
(require 'gnutls)
(require 'mongodb-bson)
(require 'mongodb-wire)
(require 'seq)
(require 'subr-x)
(require 'url)
(require 'url-util)

(defvar mongodb-connect-timeout-seconds)
(defvar mongodb-local-threshold-seconds)
(defvar mongodb-monitor-heartbeat-seconds)
(defvar mongodb-server-selection-timeout-seconds)
(defvar mongodb-tls-keylist)
(defvar mongodb-tls-trustfiles)
(defvar mongodb-tls-verify-server)

(cl-defstruct mongodb--credential
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

(cl-defstruct mongodb--srv-resolution
  endpoints
  options)

(defconst mongodb--unset :mongodb-unset)

(defconst mongodb--oidc-callback-timeout-ms 60000)

(defconst mongodb--aws-credential-timeout-seconds 10)

(defconst mongodb--aws-credential-expiry-skew-seconds 300)

(defconst mongodb--default-max-pool-size 100)

(defconst mongodb--default-min-pool-size 0)

(defconst mongodb--default-max-connecting 2)

(defconst mongodb--idle-write-period-seconds 10
  "MongoDB replica-set idle write period used for maxStalenessSeconds.")

(defconst mongodb--oidc-default-allowed-hosts
  '("*.mongodb.net"
    "*.mongodb-qa.net"
    "*.mongodb-dev.net"
    "*.mongodbgov.net"
    "localhost"
    "127.0.0.1"
    "::1"
    "*.mongodb.com")
  "Default hosts allowed for MONGODB-OIDC human callbacks.")

(cl-defstruct mongodb--server-api
  version
  (strict mongodb--unset)
  (deprecation-errors mongodb--unset))

(cl-defstruct mongodb--read-preference
  mode
  tags
  max-staleness-seconds)

(cl-defstruct mongodb--read-concern
  pairs)

(cl-defstruct mongodb--write-concern
  pairs)

(defvar mongodb--srv-resolution-cache nil
  "Connection-local cache of MongoDB SRV DNS resolution results.")

;;;; Connection parameters

(defun mongodb--nonempty-string (value)
  "Return VALUE when it is a non-empty string, otherwise nil."
  (and (stringp value)
       (> (length value) 0)
       value))

(defun mongodb--normalize-auth-mechanism (mechanism)
  "Return normalized MongoDB auth MECHANISM, or nil."
  (when mechanism
    (let ((normalized (upcase (format "%s" mechanism))))
      (unless (string= normalized "DEFAULT")
        normalized))))

(defun mongodb--url-parts (url)
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
            :options (mongodb--url-query-options query)))))

(defun mongodb--url-query-options (query)
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

(defun mongodb--url-option (options key)
  "Return MongoDB URI OPTIONS value for KEY, case-insensitively."
  (cdr (assoc (downcase key) options)))

(defun mongodb--url-options (options key)
  "Return all MongoDB URI OPTIONS values for KEY, case-insensitively."
  (let ((normalized (downcase key))
        values)
    (dolist (option options)
      (when (equal (car option) normalized)
        (push (cdr option) values)))
    (nreverse values)))

(defun mongodb--url-userinfo (userinfo)
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

(defun mongodb--truthy-url-option-p (value)
  "Return non-nil when URL option VALUE means true."
  (and value
       (member (downcase value) '("true" "1" "yes"))))

(defun mongodb--falsey-url-option-p (value)
  "Return non-nil when URL option VALUE means false."
  (and value
       (member (downcase value) '("false" "0" "no"))))

(defconst mongodb--recognized-url-options
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

(defconst mongodb--boolean-url-options
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

(defun mongodb--url-bool-option-value (value name)
  "Return VALUE parsed as a boolean URL option NAME."
  (cond
   ((mongodb--truthy-url-option-p value) t)
   ((mongodb--falsey-url-option-p value) nil)
   (t
    (signal 'mongodb-error
            (list (format "MongoDB URI option %s must be a boolean, got %S"
                          name value))))))

(defun mongodb--url-option-present-p (options key)
  "Return non-nil when URI OPTIONS include KEY."
  (assoc (downcase key) options))

(defun mongodb--url-bool-option-values (options key)
  "Return all boolean URI option values for KEY from OPTIONS."
  (mapcar (lambda (value)
            (mongodb--url-bool-option-value value key))
          (mongodb--url-options options key)))

(defun mongodb--reject-conflicting-tls-url-options (options)
  "Signal when MongoDB TLS URI OPTIONS contain forbidden combinations."
  (let ((tls-values (append
                     (mongodb--url-bool-option-values options "tls")
                     (mongodb--url-bool-option-values options "ssl"))))
    (when (and tls-values
               (cl-some (lambda (value)
                          (not (eq value (car tls-values))))
                        (cdr tls-values)))
      (signal 'mongodb-error
              (list "MongoDB URI options tls and ssl must not conflict"))))
  (dolist (pair '(("tlsInsecure" "tlsAllowInvalidCertificates")
                  ("tlsInsecure" "tlsAllowInvalidHostnames")
                  ("tlsInsecure" "tlsDisableOCSPEndpointCheck")
                  ("tlsInsecure" "tlsDisableCertificateRevocationCheck")
                  ("tlsAllowInvalidCertificates" "tlsDisableOCSPEndpointCheck")
                  ("tlsAllowInvalidCertificates" "tlsDisableCertificateRevocationCheck")
                  ("tlsDisableOCSPEndpointCheck" "tlsDisableCertificateRevocationCheck")))
    (when (and (mongodb--url-option-present-p options (car pair))
               (mongodb--url-option-present-p options (cadr pair)))
      (signal 'mongodb-error
              (list (format "MongoDB URI options %s and %s must not be combined"
                            (car pair)
                            (cadr pair)))))))

(defun mongodb--reject-unsupported-url-options (options)
  "Signal when MongoDB URI OPTIONS require unsupported native features."
  (dolist (option options)
    (let ((name (car option))
          (value (cdr option)))
      (unless (member name mongodb--recognized-url-options)
        (signal 'mongodb-error
                (list (format "Unsupported MongoDB URI option: %s" name))))
      (when (member name mongodb--boolean-url-options)
        (mongodb--url-bool-option-value value name))))
  (mongodb--reject-conflicting-tls-url-options options))

(defun mongodb--params-url-parts (params)
  "Return parsed MongoDB URL parts from PARAMS, or nil."
  (when-let* ((url (plist-get params :url)))
    (or (mongodb--url-parts url)
        (signal 'mongodb-error
                (list (format "Native MongoDB expects mongodb:// URLs, not %S; use :surface sql-interface for JDBC SQL Interface URLs"
                              url))))))

(defun mongodb--srv-scheme-p (parts)
  "Return non-nil when MongoDB URL PARTS use mongodb+srv."
  (equal (plist-get parts :scheme) "mongodb+srv"))

(defun mongodb--normalize-dns-name (name)
  "Return normalized DNS NAME without a trailing dot."
  (string-remove-suffix "." (downcase name)))

(defun mongodb--srv-parent-domain (host)
  "Return the parent domain for SRV HOST."
  (let ((labels (split-string (mongodb--normalize-dns-name host) "\\." t)))
    (when (< (length labels) 3)
      (signal 'mongodb-error
              (list "Native MongoDB SRV URLs require a hostname with a domain and TLD")))
    (mapconcat #'identity (cdr labels) ".")))

(defun mongodb--validate-srv-host (host)
  "Validate HOST for a MongoDB SRV URL."
  (when (or (string-match-p "," host)
            (string-match-p ":" host))
    (signal 'mongodb-error
            (list "MongoDB SRV URLs must contain exactly one hostname and no port")))
  (mongodb--srv-parent-domain host))

(defun mongodb--validate-srv-service-name (name)
  "Return validated MongoDB SRV service NAME."
  (setq name (or name "mongodb"))
  (unless (and (stringp name)
               (string-match-p "\\`[[:alnum:]][[:alnum:]-]*\\'" name))
    (signal 'mongodb-error
            (list (format "MongoDB srvServiceName must be a DNS service label, got %S"
                          name))))
  name)

(defun mongodb--srv-target-valid-p (target parent-domain)
  "Return non-nil when SRV TARGET belongs to PARENT-DOMAIN."
  (let ((target (mongodb--normalize-dns-name target))
        (suffix (concat "." (mongodb--normalize-dns-name parent-domain))))
    (string-suffix-p suffix target)))

(defun mongodb--dns-response-code (response)
  "Return DNS RESPONSE response code."
  (cadr (assoc 'response-code response)))

(defun mongodb--dns-answers (name type &optional required)
  "Return DNS answers for NAME and TYPE.
When REQUIRED is non-nil, signal `mongodb-error' if the query
fails or returns no answers."
  (condition-case err
      (let* ((response (dns-query name type t))
             (code (mongodb--dns-response-code response))
             (answers (cl-remove-if-not
                       (lambda (answer)
                         (eq (cadr (assoc 'type answer)) type))
                       (cadr (assoc 'answers response)))))
        (cond
         ((and required (not (eq code 'no-error)))
          (signal 'mongodb-error
                  (list (format "MongoDB SRV DNS lookup for %s returned %s"
                                name code))))
         ((and required (not answers))
          (signal 'mongodb-error
                  (list (format "MongoDB SRV DNS lookup for %s returned no %s records"
                                name type))))
         (t answers)))
    (error
     (when required
       (if (eq (car err) 'mongodb-error)
           (signal (car err) (cdr err))
         (signal 'mongodb-error
                 (list (format "MongoDB DNS lookup for %s failed: %s"
                               name (error-message-string err)))))))))

(defun mongodb--srv-answer-endpoint (answer parent-domain)
  "Return (HOST PORT) from SRV ANSWER, validating PARENT-DOMAIN."
  (let* ((data (cadr (assoc 'data answer)))
         (target (mongodb--normalize-dns-name
                  (cadr (assoc 'target data))))
         (port (cadr (assoc 'port data))))
    (when (or (string-empty-p target)
              (equal target "."))
      (signal 'mongodb-error
              (list "MongoDB SRV DNS lookup returned an empty target")))
    (unless (mongodb--srv-target-valid-p target parent-domain)
      (signal 'mongodb-error
              (list (format "MongoDB SRV target %s is outside parent domain %s"
                            target parent-domain))))
    (list target port)))

(defun mongodb--srv-text (answer)
  "Return TXT data from DNS ANSWER as a string."
  (dns-read-txt (cadr (assoc 'data answer))))

(defun mongodb--srv-txt-options (host)
  "Return MongoDB SRV TXT options for HOST."
  (let* ((answers (mongodb--dns-answers host 'TXT nil))
         (txt-answers (cl-remove-if-not
                       (lambda (answer)
                         (eq (cadr (assoc 'type answer)) 'TXT))
                       answers)))
    (when (> (length txt-answers) 1)
      (signal 'mongodb-error
              (list "MongoDB SRV TXT lookup returned multiple TXT records")))
    (when-let* ((text (and txt-answers
                           (mongodb--srv-text (car txt-answers)))))
      (let ((options (mongodb--url-query-options text)))
        (dolist (option options)
          (unless (member (car option) '("authsource" "replicaset"
                                         "loadbalanced"))
            (signal 'mongodb-error
                    (list (format "MongoDB SRV TXT option %s is not supported"
                                  (car option))))))
        options))))

(defun mongodb--resolve-srv (host &optional service-name)
  "Resolve MongoDB SRV HOST and return a `mongodb--srv-resolution'.

Arguments: HOST, SERVICE-NAME."
  (let* ((host (mongodb--normalize-dns-name host))
         (parent-domain (mongodb--validate-srv-host host))
         (service-name (mongodb--validate-srv-service-name service-name))
         (srv-name (format "_%s._tcp.%s" service-name host))
         (answers (mongodb--dns-answers srv-name 'SRV t))
         (sorted (sort (copy-sequence answers)
                       (lambda (left right)
                         (< (or (cadr (assoc 'priority
                                             (cadr (assoc 'data left))))
                                0)
                            (or (cadr (assoc 'priority
                                             (cadr (assoc 'data right))))
                                0)))))
         (endpoints (mapcar (lambda (answer)
                              (mongodb--srv-answer-endpoint
                               answer parent-domain))
                            sorted)))
    (make-mongodb--srv-resolution
     :endpoints endpoints
     :options (mongodb--srv-txt-options host))))

(defun mongodb--srv-resolution (host &optional service-name)
  "Return cached MongoDB SRV resolution for HOST.

Arguments: HOST, SERVICE-NAME."
  (let* ((host (mongodb--normalize-dns-name host))
         (service-name (mongodb--validate-srv-service-name service-name))
         (cache-key (cons host service-name))
         (cached (assoc cache-key mongodb--srv-resolution-cache)))
    (if cached
        (cdr cached)
      (let ((resolution (mongodb--resolve-srv host service-name)))
        (push (cons cache-key resolution) mongodb--srv-resolution-cache)
        resolution))))

(defun mongodb--params-effective-url-options (params)
  "Return effective MongoDB URL options for PARAMS.
For mongodb+srv URLs, URI options override DNS TXT options."
  (when-let* ((parts (mongodb--params-url-parts params)))
    (let ((options (plist-get parts :options)))
      (if (mongodb--srv-scheme-p parts)
          (append options
                  (mongodb--srv-resolution-options
                   (mongodb--srv-resolution
                    (plist-get parts :hosts)
                    (mongodb--params-srv-service-name params))))
        options))))

(defun mongodb--limit-srv-endpoints (endpoints limit)
  "Return MongoDB SRV ENDPOINTS limited by LIMIT."
  (if (and limit
           (> (length endpoints) limit))
      (seq-take endpoints limit)
    endpoints))

(defun mongodb--host-port (hostspec &optional default-port)
  "Return (HOST PORT) parsed from HOSTSPEC.
DEFAULT-PORT defaults to 27017.  URL-encoded absolute paths are returned as
UNIX-domain socket endpoints with PORT nil."
  (let ((default-port (or default-port 27017)))
    (cond
     ((mongodb--local-socket-hostspec hostspec)
      (list (mongodb--local-socket-hostspec hostspec) nil))
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

(defun mongodb--local-socket-hostspec (hostspec)
  "Return HOSTSPEC as a UNIX-domain socket path, or nil.
MongoDB URI syntax represents local sockets as URL-encoded absolute paths in
the host list, for example %2Ftmp%2Fmongodb-27017.sock."
  (let ((decoded (and (stringp hostspec)
                      (url-unhex-string hostspec))))
    (and decoded
         (file-name-absolute-p decoded)
         decoded)))

(defun mongodb--host-ports (hostspec &optional default-port)
  "Return a list of (HOST PORT) endpoints parsed from HOSTSPEC.
HOSTSPEC may be a MongoDB comma-separated seed list.

Arguments: HOSTSPEC, DEFAULT-PORT."
  (mapcar (lambda (item)
            (mongodb--host-port item default-port))
          (split-string hostspec "," t "[[:space:]\n\r\t]*")))

(defun mongodb--params-endpoints (params)
  "Return a list of (HOST PORT DATABASE) endpoints from PARAMS.
UNIX-domain socket endpoints use a nil PORT."
  (if-let* ((parts (mongodb--params-url-parts params)))
      (let ((options (mongodb--params-effective-url-options params)))
        (mongodb--reject-unsupported-url-options
         options)
        (let ((database (or (plist-get params :database)
                            (plist-get parts :database)
                            "admin")))
          (if (mongodb--srv-scheme-p parts)
              (let ((hosts (plist-get parts :hosts)))
                (mongodb--validate-srv-host hosts)
                (let ((endpoints
                       (mongodb--limit-srv-endpoints
                        (mongodb--srv-resolution-endpoints
                         (mongodb--srv-resolution
                          hosts
                          (mongodb--params-srv-service-name params)))
                        (mongodb--params-srv-max-hosts params))))
                  (mapcar (lambda (endpoint)
                            (append endpoint (list database)))
                          endpoints)))
            (mapcar (lambda (endpoint)
                      (append endpoint (list database)))
                    (mongodb--host-ports
                     (plist-get parts :hosts))))))
    (let ((database (or (plist-get params :database) "admin"))
          (default-port (or (plist-get params :port) 27017)))
      (mapcar (lambda (endpoint)
                (append endpoint (list database)))
              (mongodb--host-ports
               (format "%s" (or (plist-get params :host) "127.0.0.1"))
               default-port)))))

(defun mongodb--params-endpoint (params)
  "Return (HOST PORT DATABASE) from MongoDB connection PARAMS."
  (car (mongodb--params-endpoints params)))

(defun mongodb--params-replica-set-name (params)
  "Return the requested replica set name from PARAMS, or nil."
  (let ((options (mongodb--params-effective-url-options params)))
    (or (plist-get params :replica-set)
        (plist-get params :replicaSet)
        (mongodb--url-option options "replicaSet"))))

(defun mongodb--params-raw-replica-set-name (params)
  "Return requested replica set name without SRV TXT merging.

Arguments: PARAMS."
  (mongodb--params-raw-option-value
   params '(:replica-set :replicaSet) "replicaSet"))

(defun mongodb--params-direct-connection-p (params)
  "Return non-nil when PARAMS request direct MongoDB connection mode."
  (mongodb--params-bool-option-p
   params '(:direct-connection :directConnection) "directConnection"))

(defun mongodb--params-raw-direct-connection-p (params)
  "Return directConnection without SRV TXT merging.

Arguments: PARAMS."
  (mongodb--params-raw-bool-option-p
   params '(:direct-connection :directConnection) "directConnection"))

(defun mongodb--params-load-balanced-p (params)
  "Return non-nil when PARAMS request MongoDB load-balanced mode."
  (mongodb--params-bool-option-p
   params '(:load-balanced :loadBalanced) "loadBalanced"))

(defun mongodb--params-raw-load-balanced-p (params)
  "Return loadBalanced without SRV TXT merging.

Arguments: PARAMS."
  (mongodb--params-raw-bool-option-p
   params '(:load-balanced :loadBalanced) "loadBalanced"))

(defun mongodb--params-replica-discovery-p (params endpoints)
  "Return non-nil when PARAMS and ENDPOINTS should use replica discovery."
  (and (not (mongodb--params-direct-connection-p params))
       (not (mongodb--params-load-balanced-p params))
       (or (mongodb--params-replica-set-name params)
           (> (length endpoints) 1))))

(defun mongodb--params-auth-mechanism (params options)
  "Return authentication mechanism from PARAMS or URI OPTIONS."
  (or (plist-get params :auth-mechanism)
      (plist-get params :authMechanism)
      (mongodb--url-option options "authMechanism")))

(defun mongodb--x509-auth-mechanism-p (mechanism)
  "Return non-nil when MECHANISM names MongoDB X.509 authentication."
  (equal (mongodb--normalize-auth-mechanism mechanism) "MONGODB-X509"))

(defun mongodb--plain-auth-mechanism-p (mechanism)
  "Return non-nil when MECHANISM names MongoDB PLAIN SASL authentication."
  (equal (mongodb--normalize-auth-mechanism mechanism) "PLAIN"))

(defun mongodb--aws-auth-mechanism-p (mechanism)
  "Return non-nil when MECHANISM names MongoDB AWS IAM authentication."
  (equal (mongodb--normalize-auth-mechanism mechanism) "MONGODB-AWS"))

(defun mongodb--oidc-auth-mechanism-p (mechanism)
  "Return non-nil when MECHANISM names MongoDB OIDC authentication."
  (equal (mongodb--normalize-auth-mechanism mechanism) "MONGODB-OIDC"))

(defun mongodb--mechanism-property-name (name)
  "Return normalized auth mechanism property NAME."
  (let ((text (if (symbolp name)
                  (symbol-name name)
                (format "%s" name))))
    (setq text (string-remove-prefix ":" text))
    (upcase (replace-regexp-in-string "-" "_" text t t))))

(defun mongodb--mechanism-property-pair (name value)
  "Return a normalized auth mechanism property pair.

Arguments: NAME, VALUE."
  (let ((name (mongodb--mechanism-property-name name)))
    (when (string-empty-p name)
      (signal 'mongodb-error
              (list "MongoDB authMechanismProperties contains an empty property name")))
    (cons name (format "%s" value))))

(defun mongodb--parse-mechanism-properties-string (value)
  "Parse authMechanismProperties string VALUE into an alist."
  (let (properties)
    (dolist (entry (split-string value "," t "[[:space:]\n\r\t]*"))
      (let ((colon (cl-position ?: entry)))
        (unless colon
          (signal 'mongodb-error
                  (list (format "MongoDB authMechanismProperties entry lacks ':' in %S"
                                entry))))
        (push (mongodb--mechanism-property-pair
               (substring entry 0 colon)
               (substring entry (1+ colon)))
              properties)))
    (nreverse properties)))

(defun mongodb--mechanism-properties-from-plist (plist)
  "Return auth mechanism properties from PLIST."
  (let (properties)
    (while plist
      (unless (cdr plist)
        (signal 'mongodb-error
                (list "MongoDB auth mechanism property plist has an odd length")))
      (push (mongodb--mechanism-property-pair
             (car plist)
             (cadr plist))
            properties)
      (setq plist (cddr plist)))
    (nreverse properties)))

(defun mongodb--mechanism-properties-value (value)
  "Return normalized auth mechanism properties from VALUE."
  (cond
   ((null value) nil)
   ((stringp value)
    (mongodb--parse-mechanism-properties-string value))
   ((and (listp value)
         (consp (car value)))
    (mapcar (lambda (pair)
              (mongodb--mechanism-property-pair
               (car pair)
               (cdr pair)))
            value))
   ((listp value)
    (mongodb--mechanism-properties-from-plist value))
   (t
    (signal 'mongodb-error
            (list (format "Invalid MongoDB auth mechanism properties: %S"
                          value))))))

(defun mongodb--params-mechanism-properties (params options)
  "Return auth mechanism properties from PARAMS or URI OPTIONS."
  (mongodb--mechanism-properties-value
   (or (plist-get params :auth-mechanism-properties)
       (plist-get params :authMechanismProperties)
       (plist-get params :mechanism-properties)
       (mongodb--url-option options "authMechanismProperties"))))

(defun mongodb--mechanism-property (properties name)
  "Return auth mechanism property NAME from PROPERTIES."
  (cdr (assoc (mongodb--mechanism-property-name name) properties)))

(defun mongodb--oidc-mechanism-environment (properties)
  "Return normalized MONGODB-OIDC ENVIRONMENT from PROPERTIES, or nil."
  (when-let* ((environment (mongodb--mechanism-property properties "ENVIRONMENT")))
    (downcase environment)))

(defun mongodb--oidc-token-resource (properties)
  "Return MONGODB-OIDC TOKEN_RESOURCE from PROPERTIES, or nil."
  (mongodb--mechanism-property properties "TOKEN_RESOURCE"))

(defun mongodb--validate-mechanism-properties (mechanism properties)
  "Validate auth mechanism PROPERTIES for MECHANISM."
  (when properties
    (cond
     ((mongodb--aws-auth-mechanism-p mechanism)
      (dolist (property properties)
        (unless (member (car property) '("AWS_SESSION_TOKEN"))
          (signal 'mongodb-error
                  (list (format "Unsupported MongoDB MONGODB-AWS auth mechanism property: %s"
                                (car property)))))))
     ((mongodb--oidc-auth-mechanism-p mechanism)
      (dolist (property properties)
        (unless (member (car property) '("ENVIRONMENT" "TOKEN_RESOURCE"))
          (signal 'mongodb-error
                  (list (format "Unsupported MongoDB MONGODB-OIDC auth mechanism property: %s"
                                (car property)))))))
     (t
      (signal 'mongodb-error
              (list "MongoDB authMechanismProperties are currently supported only for MONGODB-AWS and MONGODB-OIDC"))))))

(defun mongodb--validate-oidc-configuration
    (properties oidc-callback oidc-human-callback)
  "Validate MONGODB-OIDC PROPERTIES and callback configuration.

Arguments: PROPERTIES, OIDC-CALLBACK, OIDC-HUMAN-CALLBACK."
  (let ((environment (mongodb--oidc-mechanism-environment properties))
        (token-resource (mongodb--oidc-token-resource properties)))
    (when (and environment
               (not (member environment '("test" "azure" "gcp" "k8s"))))
      (signal 'mongodb-error
              (list (format "Unsupported MongoDB MONGODB-OIDC ENVIRONMENT: %s"
                            environment))))
    (when (and environment
               (or oidc-callback oidc-human-callback))
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC ENVIRONMENT cannot be combined with :oidc-callback or :oidc-human-callback")))
    (when (and oidc-callback oidc-human-callback)
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC cannot use both :oidc-callback and :oidc-human-callback")))
    (cond
     ((and token-resource
           (not (member environment '("azure" "gcp"))))
      (signal 'mongodb-error
              (list "MongoDB MONGODB-OIDC TOKEN_RESOURCE requires ENVIRONMENT:azure or ENVIRONMENT:gcp")))
     ((and (member environment '("azure" "gcp"))
           (not (mongodb--nonempty-string token-resource)))
      (signal 'mongodb-error
              (list (format "MongoDB MONGODB-OIDC ENVIRONMENT:%s requires TOKEN_RESOURCE"
                            environment)))))))

(defun mongodb--oidc-allowed-hosts-value (value)
  "Return normalized MONGODB-OIDC allowed hosts from VALUE."
  (let ((hosts (cond
                ((stringp value)
                 (list value))
                ((vectorp value)
                 (append value nil))
                ((listp value)
                 value)
                (t
                 (signal 'mongodb-error
                         (list (format "MongoDB MONGODB-OIDC :oidc-allowed-hosts must be a string or sequence of strings, got %S"
                                       value)))))))
    (dolist (host hosts)
      (unless (and (stringp host)
                   (not (string-empty-p host)))
        (signal 'mongodb-error
                (list (format "MongoDB MONGODB-OIDC allowed host must be a non-empty string, got %S"
                              host)))))
    hosts))

(defun mongodb--params-oidc-allowed-hosts (params)
  "Return MONGODB-OIDC human callback allowed hosts for PARAMS."
  (let ((specified nil)
        value)
    (dolist (key '(:oidc-allowed-hosts :oidcAllowedHosts))
      (when (and (not specified)
                 (plist-member params key))
        (setq specified t
              value (plist-get params key))))
    (if specified
        (mongodb--oidc-allowed-hosts-value value)
      mongodb--oidc-default-allowed-hosts)))

(defun mongodb--params-api-bool (params options keys option-key)
  "Return (SPECIFIED . VALUE) for boolean KEYS or URL OPTION-KEY.

Arguments: PARAMS, OPTIONS, KEYS, OPTION-KEY."
  (let ((found nil)
        value)
    (dolist (key keys)
      (when (and (not found)
                 (plist-member params key))
        (setq found t
              value (plist-get params key))))
    (if found
        (cons t value)
      (when-let* ((option (mongodb--url-option options option-key)))
        (cons t (mongodb--truthy-url-option-p option))))))

(defun mongodb--params-server-api-version (params options)
  "Return requested MongoDB Stable API version from PARAMS or OPTIONS."
  (let ((value (or (plist-get params :server-api)
                   (plist-get params :serverApi)
                   (plist-get params :server-api-version)
                   (plist-get params :api-version)
                   (plist-get params :apiVersion)
                   (mongodb--url-option options "serverApi")
                   (mongodb--url-option options "apiVersion"))))
    (when value
      (format "%s" value))))

(defun mongodb--params-server-api (params)
  "Return a `mongodb--server-api' from PARAMS, or nil."
  (let* ((options (mongodb--params-effective-url-options params))
         (version (mongodb--params-server-api-version params options))
         (strict (mongodb--params-api-bool
                  params options
                  '(:api-strict :apiStrict :server-api-strict)
                  "apiStrict"))
         (deprecation-errors
          (mongodb--params-api-bool
           params options
           '(:api-deprecation-errors :apiDeprecationErrors
             :server-api-deprecation-errors)
           "apiDeprecationErrors")))
    (when (and (not version)
               (or strict deprecation-errors))
      (signal 'mongodb-error
              (list "MongoDB Stable API requires :server-api or :api-version when apiStrict/apiDeprecationErrors is set")))
    (when version
      (make-mongodb--server-api
       :version version
       :strict (if strict (cdr strict) mongodb--unset)
       :deprecation-errors (if deprecation-errors
                               (cdr deprecation-errors)
                             mongodb--unset)))))

(defun mongodb--validate-app-name (app-name)
  "Return valid MongoDB handshake APP-NAME, or signal."
  (when app-name
    (unless (stringp app-name)
      (signal 'mongodb-error
              (list (format "MongoDB appName must be a string, got %S"
                            app-name))))
    (when (> (length (mongodb--utf8-bytes app-name)) 128)
      (signal 'mongodb-error
              (list "MongoDB appName cannot exceed 128 UTF-8 bytes")))
    app-name))

(defun mongodb--params-app-name (params)
  "Return MongoDB handshake appName from PARAMS or URI options, or nil."
  (let* ((options (mongodb--params-effective-url-options params))
         (value (or (plist-get params :app-name)
                    (plist-get params :appName)
                    (plist-get params :application-name)
                    (plist-get params :applicationName)
                    (mongodb--url-option options "appName"))))
    (mongodb--validate-app-name value)))

(defun mongodb--server-api-fields (server-api)
  "Return command fields for SERVER-API."
  (when server-api
    `(("apiVersion" . ,(mongodb--server-api-version server-api))
      ,@(unless (eq (mongodb--server-api-strict server-api)
                    mongodb--unset)
          `(("apiStrict" . ,(if (mongodb--server-api-strict server-api)
                                t :false))))
      ,@(unless (eq (mongodb--server-api-deprecation-errors server-api)
            mongodb--unset)
        `(("apiDeprecationErrors" .
           ,(if (mongodb--server-api-deprecation-errors server-api)
                t :false)))))))

(defun mongodb--normalize-read-preference-mode (mode)
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
       (signal 'mongodb-error
               (list (format "Unsupported MongoDB readPreference: %s"
                             mode)))))))

(defun mongodb--params-read-preference-mode (params options)
  "Return requested MongoDB read preference mode from PARAMS or OPTIONS."
  (mongodb--normalize-read-preference-mode
   (or (plist-get params :read-preference)
       (plist-get params :readPreference)
       (mongodb--url-option options "readPreference")
       "primary")))

(defun mongodb--parse-integer-option (value name)
  "Return VALUE parsed as an integer for MongoDB option NAME."
  (cond
   ((null value) nil)
   ((integerp value) value)
   ((and (stringp value)
         (string-match-p "\\`-?[0-9]+\\'" value))
    (string-to-number value))
   (t
    (signal 'mongodb-error
            (list (format "MongoDB %s must be an integer, got %S"
                          name value))))))

(defun mongodb--params-option-value (params keys url-name)
  "Return PARAMS option from KEYS or URL-NAME."
  (or (seq-some (lambda (key)
                  (and (plist-member params key)
                       (plist-get params key)))
                keys)
      (let ((options (mongodb--params-effective-url-options params)))
        (mongodb--url-option options url-name))))

(defun mongodb--params-raw-url-option (params key)
  "Return raw URL option KEY from PARAMS without SRV TXT merging."
  (when-let* ((parts (mongodb--params-url-parts params)))
    (mongodb--url-option (plist-get parts :options) key)))

(defun mongodb--params-raw-option-value (params keys url-name)
  "Return PARAMS option from KEYS or raw URL-NAME without SRV TXT merging."
  (catch 'found
    (dolist (key keys)
      (when (plist-member params key)
        (throw 'found (plist-get params key))))
    (mongodb--params-raw-url-option params url-name)))

(defun mongodb--params-raw-bool-option-p (params keys url-name)
  "Return raw boolean option URL-NAME from PARAMS.
Structured PARAMS values are used as booleans directly; URI values are parsed
with MongoDB URI boolean rules.

Arguments: PARAMS, KEYS, URL-NAME."
  (let ((value (mongodb--params-raw-option-value params keys url-name)))
    (if (stringp value)
        (mongodb--url-bool-option-value value url-name)
      value)))

(defun mongodb--params-bool-option-p (params keys url-name)
  "Return boolean option URL-NAME from PARAMS or effective URL options.

Arguments: PARAMS, KEYS, URL-NAME."
  (let ((value (mongodb--params-option-value params keys url-name)))
    (if (stringp value)
        (mongodb--url-bool-option-value value url-name)
      value)))

(defun mongodb--params-nonnegative-integer-option
    (params keys url-name display-name)
  "Return non-negative integer option DISPLAY-NAME from PARAMS.

Arguments: PARAMS, KEYS, URL-NAME, DISPLAY-NAME."
  (let ((value (mongodb--params-option-value params keys url-name)))
    (when-let* ((number (mongodb--parse-integer-option value display-name)))
      (when (< number 0)
        (signal 'mongodb-error
                (list (format "MongoDB %s must be non-negative"
                              display-name))))
      number)))

(defun mongodb--params-connect-timeout (params)
  "Return MongoDB connect timeout seconds for PARAMS."
  (or (plist-get params :connect-timeout)
      (let* ((options (mongodb--params-effective-url-options params))
             (millis (mongodb--parse-integer-option
                      (mongodb--url-option options "connectTimeoutMS")
                      "connectTimeoutMS")))
        (when millis
          (when (< millis 0)
            (signal 'mongodb-error
                    (list "MongoDB connectTimeoutMS must be non-negative")))
          (/ millis 1000.0)))
      mongodb-connect-timeout-seconds))

(defun mongodb--params-server-selection-timeout (params)
  "Return MongoDB server selection timeout seconds for PARAMS."
  (cond
   ((plist-member params :server-selection-timeout)
    (let ((value (plist-get params :server-selection-timeout)))
      (when (or (not (numberp value))
                (< value 0))
        (signal 'mongodb-error
                (list "MongoDB serverSelectionTimeout must be a non-negative number")))
      value))
   ((plist-member params :serverSelectionTimeout)
    (let ((value (plist-get params :serverSelectionTimeout)))
      (when (or (not (numberp value))
                (< value 0))
        (signal 'mongodb-error
                (list "MongoDB serverSelectionTimeout must be a non-negative number")))
      value))
   (t
    (let* ((options (mongodb--params-effective-url-options params))
           (millis (mongodb--parse-integer-option
                    (mongodb--url-option options "serverSelectionTimeoutMS")
                    "serverSelectionTimeoutMS")))
      (if millis
          (progn
            (when (< millis 0)
              (signal 'mongodb-error
                      (list "MongoDB serverSelectionTimeoutMS must be non-negative")))
            (/ millis 1000.0))
        mongodb-server-selection-timeout-seconds)))))

(defun mongodb--params-server-selection-try-once-p (params)
  "Return non-nil when MongoDB server selection scans only once.
This single-threaded driver option defaults to true, matching the MongoDB URI
option semantics for single-threaded drivers.

Arguments: PARAMS."
  (let ((options (mongodb--params-effective-url-options params)))
    (cond
     ((plist-member params :server-selection-try-once)
      (mongodb--boolean-param-value
       (plist-get params :server-selection-try-once)
       "serverSelectionTryOnce"))
     ((plist-member params :serverSelectionTryOnce)
      (mongodb--boolean-param-value
       (plist-get params :serverSelectionTryOnce)
       "serverSelectionTryOnce"))
     ((mongodb--url-option options "serverSelectionTryOnce")
      (mongodb--url-bool-option-value
       (mongodb--url-option options "serverSelectionTryOnce")
       "serverSelectionTryOnce"))
     (t t))))

(defun mongodb--params-socket-timeout (params)
  "Return MongoDB socket timeout seconds for PARAMS, or nil."
  (or (plist-get params :socket-timeout)
      (plist-get params :socketTimeout)
      (let* ((options (mongodb--params-effective-url-options params))
             (millis (mongodb--parse-integer-option
                      (or (plist-get params :socket-timeout-ms)
                          (plist-get params :socketTimeoutMS)
                          (mongodb--url-option options "socketTimeoutMS"))
                      "socketTimeoutMS")))
        (when millis
          (when (< millis 0)
            (signal 'mongodb-error
                    (list "MongoDB socketTimeoutMS must be non-negative")))
          (/ millis 1000.0)))))

(defun mongodb--params-proxy-option-present-p (params keys url-name options)
  "Return non-nil when PARAMS or OPTIONS explicitly include URL-NAME.

Arguments: PARAMS, KEYS, URL-NAME, OPTIONS."
  (or (seq-some (lambda (key)
                  (plist-member params key))
                keys)
      (mongodb--url-option-present-p options url-name)))

(defun mongodb--params-proxy-string (value name &optional empty-is-nil)
  "Return validated MongoDB SOCKS5 proxy string VALUE for NAME.

Arguments: VALUE, NAME, EMPTY-IS-NIL."
  (cond
   ((null value) nil)
   ((not (stringp value))
    (signal 'mongodb-error
            (list (format "MongoDB %s must be a string, got %S"
                          name value))))
   ((string-empty-p value)
    (if empty-is-nil
        nil
      (signal 'mongodb-error
              (list (format "MongoDB %s must not be empty" name)))))
   (t value)))

(defun mongodb--params-proxy-auth-part (value name)
  "Return validated SOCKS5 username/password VALUE for NAME."
  (when-let* ((string (mongodb--params-proxy-string value name t)))
    (when (> (length (mongodb--utf8-bytes string)) 255)
      (signal 'mongodb-error
              (list (format "MongoDB SOCKS5 %s cannot exceed 255 UTF-8 bytes"
                            name))))
    string))

(defun mongodb--params-proxy (params)
  "Return SOCKS5 proxy settings from MongoDB PARAMS, or nil.
The returned plist contains :host, :port, :username, and :password.  MongoDB
SOCKS5 URI options use proxyHost, proxyPort, proxyUsername, and proxyPassword."
  (let* ((options (mongodb--params-effective-url-options params))
         (host (mongodb--params-proxy-string
                (mongodb--params-option-value
                 params '(:proxy-host :proxyHost) "proxyHost")
                "proxyHost"))
         (port-present
          (mongodb--params-proxy-option-present-p
           params '(:proxy-port :proxyPort) "proxyPort" options))
         (username-present
          (mongodb--params-proxy-option-present-p
           params '(:proxy-username :proxyUsername) "proxyUsername" options))
         (password-present
          (mongodb--params-proxy-option-present-p
           params '(:proxy-password :proxyPassword) "proxyPassword" options))
         (port-value (mongodb--params-option-value
                      params '(:proxy-port :proxyPort) "proxyPort"))
         (username (mongodb--params-proxy-auth-part
                    (mongodb--params-option-value
                     params '(:proxy-username :proxyUsername) "proxyUsername")
                    "proxyUsername"))
         (password (mongodb--params-proxy-auth-part
                    (mongodb--params-option-value
                     params '(:proxy-password :proxyPassword) "proxyPassword")
                    "proxyPassword"))
         (port (mongodb--parse-integer-option port-value "proxyPort")))
    (when (and (not host)
               (or port-present username-present password-present))
      (signal 'mongodb-error
              (list "MongoDB SOCKS5 proxy options require proxyHost")))
    (when (and host port
               (or (<= port 0)
                   (> port 65535)))
      (signal 'mongodb-error
              (list "MongoDB proxyPort must be an integer between 1 and 65535")))
    (when (and username (not password))
      (signal 'mongodb-error
              (list "MongoDB SOCKS5 proxyUsername requires proxyPassword")))
    (when (and password (not username))
      (signal 'mongodb-error
              (list "MongoDB SOCKS5 proxyPassword requires proxyUsername")))
    (when host
      (list :host host
            :port (or port 1080)
            :username username
            :password password))))

(defun mongodb--params-operation-timeout (params)
  "Return MongoDB default operation timeout seconds for PARAMS, or nil."
  (or (plist-get params :operation-timeout)
      (plist-get params :operationTimeout)
      (let* ((options (mongodb--params-effective-url-options params))
             (millis (mongodb--parse-integer-option
                      (or (plist-get params :timeout-ms)
                          (plist-get params :timeoutMS)
                          (plist-get params :operation-timeout-ms)
                          (plist-get params :operationTimeoutMS)
                          (mongodb--url-option options "timeoutMS"))
                      "timeoutMS")))
        (when millis
          (when (< millis 0)
            (signal 'mongodb-error
                    (list "MongoDB timeoutMS must be non-negative")))
          (/ millis 1000.0)))))

(defun mongodb--params-local-threshold (params)
  "Return MongoDB localThresholdMS for PARAMS in seconds."
  (cond
   ((plist-member params :local-threshold)
    (let ((value (plist-get params :local-threshold)))
      (when (or (not (numberp value))
                (< value 0))
        (signal 'mongodb-error
                (list "MongoDB localThreshold must be a non-negative number")))
      value))
   (t
    (let ((millis (mongodb--params-nonnegative-integer-option
                   params
                   '(:local-threshold-ms :localThresholdMS)
                   "localThresholdMS"
                   "localThresholdMS")))
      (if millis
          (/ millis 1000.0)
        mongodb-local-threshold-seconds)))))

(defun mongodb--params-heartbeat-frequency (params)
  "Return MongoDB heartbeatFrequencyMS for PARAMS in seconds, or nil."
  (or (plist-get params :heartbeat-frequency)
      (let ((millis (mongodb--params-nonnegative-integer-option
                     params
                     '(:heartbeat-frequency-ms :heartbeatFrequencyMS)
                     "heartbeatFrequencyMS"
                     "heartbeatFrequencyMS")))
        (when millis
          (when (zerop millis)
            (signal 'mongodb-error
                    (list "MongoDB heartbeatFrequencyMS must be greater than zero")))
          (/ millis 1000.0)))))

(defun mongodb--params-server-monitoring-mode (params)
  "Return MongoDB serverMonitoringMode for PARAMS as a symbol."
  (let* ((options (mongodb--params-effective-url-options params))
         (mode (or (plist-get params :server-monitoring-mode)
                   (plist-get params :serverMonitoringMode)
                   (mongodb--url-option options "serverMonitoringMode"))))
    (when mode
      (pcase (downcase (format "%s" mode))
        ("auto" 'auto)
        ("stream" 'stream)
        ("poll" 'poll)
        (_
         (signal 'mongodb-error
                 (list (format "Unsupported MongoDB serverMonitoringMode: %s"
                               mode))))))))

(defun mongodb--params-srv-service-name (params)
  "Return MongoDB srvServiceName for PARAMS."
  (mongodb--validate-srv-service-name
   (or (plist-get params :srv-service-name)
       (plist-get params :srvServiceName)
       (mongodb--params-raw-url-option params "srvServiceName")
       "mongodb")))

(defun mongodb--params-srv-max-hosts (params)
  "Return MongoDB srvMaxHosts for PARAMS, or nil when unbounded."
  (let ((value (or (and (plist-member params :srv-max-hosts)
                        (plist-get params :srv-max-hosts))
                   (and (plist-member params :srvMaxHosts)
                        (plist-get params :srvMaxHosts))
                   (mongodb--params-raw-url-option params "srvMaxHosts"))))
    (when-let* ((hosts (mongodb--parse-integer-option value "srvMaxHosts")))
      (when (< hosts 0)
        (signal 'mongodb-error
                (list "MongoDB srvMaxHosts must be non-negative")))
      (and (not (zerop hosts))
           hosts))))

(defun mongodb--params-max-pool-size (params)
  "Return MongoDB maxPoolSize for PARAMS.
A nil return value means the pool is unbounded."
  (let ((size (mongodb--params-nonnegative-integer-option
               params
               '(:max-pool-size :maxPoolSize)
               "maxPoolSize"
               "maxPoolSize")))
    (cond
     ((null size) mongodb--default-max-pool-size)
     ((zerop size) nil)
     (t size))))

(defun mongodb--params-min-pool-size (params)
  "Return MongoDB minPoolSize for PARAMS."
  (or (mongodb--params-nonnegative-integer-option
       params
       '(:min-pool-size :minPoolSize)
       "minPoolSize"
       "minPoolSize")
      mongodb--default-min-pool-size))

(defun mongodb--params-max-connecting (params)
  "Return MongoDB maxConnecting for PARAMS."
  (let ((value (mongodb--params-nonnegative-integer-option
                params
                '(:max-connecting :maxConnecting)
                "maxConnecting"
                "maxConnecting")))
    (cond
     ((null value) mongodb--default-max-connecting)
     ((zerop value)
      (signal 'mongodb-error
              (list "MongoDB maxConnecting must be greater than zero")))
     (t value))))

(defun mongodb--params-max-idle-time (params)
  "Return MongoDB maxIdleTimeMS for PARAMS in seconds, or nil."
  (or (plist-get params :max-idle-time)
      (let ((millis (mongodb--params-nonnegative-integer-option
                     params
                     '(:max-idle-time-ms :maxIdleTimeMS)
                     "maxIdleTimeMS"
                     "maxIdleTimeMS")))
        (and millis
             (not (zerop millis))
             (/ millis 1000.0)))))

(defun mongodb--params-wait-queue-timeout (params)
  "Return MongoDB waitQueueTimeoutMS for PARAMS in seconds, or nil.
A nil return value means the wait queue has no configured deadline."
  (or (when (plist-member params :wait-queue-timeout)
        (let ((value (plist-get params :wait-queue-timeout)))
          (when (or (not (numberp value))
                    (< value 0))
            (signal 'mongodb-error
                    (list "MongoDB waitQueueTimeoutMS must be non-negative")))
          (and (not (zerop value))
               value)))
      (let ((millis (mongodb--params-nonnegative-integer-option
                     params
                     '(:wait-queue-timeout-ms :waitQueueTimeoutMS)
                     "waitQueueTimeoutMS"
                     "waitQueueTimeoutMS")))
        (and millis
             (not (zerop millis))
             (/ millis 1000.0)))))

(defun mongodb--params-validate-pool-options (params)
  "Validate MongoDB connection pool options in PARAMS."
  (let ((max-size (mongodb--params-max-pool-size params))
        (min-size (mongodb--params-min-pool-size params)))
    (when (and max-size
               (> min-size max-size))
      (signal 'mongodb-error
              (list "MongoDB minPoolSize must be less than or equal to maxPoolSize")))))

(defun mongodb--boolean-param-value (value name)
  "Return VALUE parsed as a boolean MongoDB option NAME."
  (cond
   ((or (eq value t) (eq value :true)) t)
   ((or (null value) (eq value :false)) nil)
   ((stringp value)
    (mongodb--url-bool-option-value value name))
   (t
    (signal 'mongodb-error
            (list (format "MongoDB %s must be a boolean, got %S"
                          name value))))))

(defun mongodb--params-retry-reads-p (params)
  "Return non-nil when PARAMS enable MongoDB retryable reads.
The MongoDB driver option defaults to enabled unless explicitly disabled."
  (let ((options (mongodb--params-effective-url-options params)))
    (cond
     ((plist-member params :retry-reads)
      (mongodb--boolean-param-value
       (plist-get params :retry-reads)
       "retryReads"))
     ((plist-member params :retryReads)
      (mongodb--boolean-param-value
       (plist-get params :retryReads)
       "retryReads"))
     ((mongodb--url-option options "retryReads")
      (mongodb--url-bool-option-value
       (mongodb--url-option options "retryReads")
       "retryReads"))
     (t t))))

(defun mongodb--params-retry-writes-p (params)
  "Return non-nil when PARAMS enable MongoDB retryable writes.
The MongoDB driver option defaults to enabled unless explicitly disabled."
  (let ((options (mongodb--params-effective-url-options params)))
    (cond
     ((plist-member params :retry-writes)
      (mongodb--boolean-param-value
       (plist-get params :retry-writes)
       "retryWrites"))
     ((plist-member params :retryWrites)
      (mongodb--boolean-param-value
       (plist-get params :retryWrites)
       "retryWrites"))
     ((mongodb--url-option options "retryWrites")
      (mongodb--url-bool-option-value
       (mongodb--url-option options "retryWrites")
       "retryWrites"))
     (t t))))

(defun mongodb--params-with-connect-timeout-limit (params timeout)
  "Return PARAMS with :connect-timeout capped to TIMEOUT seconds."
  (let* ((base-timeout (mongodb--params-connect-timeout params))
         (effective (min base-timeout timeout))
         (copy (copy-sequence params)))
    (plist-put copy :connect-timeout effective)
    copy))

(defun mongodb--read-preference-tag-document (value)
  "Return VALUE as a MongoDB read preference tag document."
  (cond
   ((or (null value)
        (and (stringp value)
             (string-empty-p value)))
    (mongodb-document nil))
   ((mongodb-document-p value) value)
   ((and (consp value)
         (consp (car value)))
    value)
   ((stringp value)
    (let (pairs)
      (dolist (part (split-string value "," t "[[:space:]\n\r\t]+"))
        (let ((colon (cl-position ?: part)))
          (unless colon
            (signal 'mongodb-error
                    (list (format "MongoDB readPreferenceTags entry lacks ':' in %S"
                                  part))))
          (push (cons (substring part 0 colon)
                      (substring part (1+ colon)))
                pairs)))
      (nreverse pairs)))
   (t
    (signal 'mongodb-error
            (list (format "Invalid MongoDB readPreferenceTags value: %S"
                          value))))))

(defun mongodb--params-read-preference-tags (params options)
  "Return read preference tag sets from PARAMS or URI OPTIONS."
  (let* ((plist-value (or (plist-get params :read-preference-tags)
                          (plist-get params :readPreferenceTags)))
         (values (cond
                  ((null plist-value)
                   (mongodb--url-options options "readPreferenceTags"))
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
       (mapcar #'mongodb--read-preference-tag-document values)))))

(defun mongodb--params-max-staleness-seconds (params options)
  "Return maxStalenessSeconds from PARAMS and OPTIONS.
MongoDB drivers treat -1 as unset and require positive values to be at least
90 seconds."
  (let ((value (mongodb--parse-integer-option
                (or (plist-get params :max-staleness-seconds)
                    (plist-get params :maxStalenessSeconds)
                    (mongodb--url-option options "maxStalenessSeconds"))
                "maxStalenessSeconds")))
    (when value
      (cond
       ((= value -1) nil)
       ((or (< value 0)
            (< value 90))
        (signal 'mongodb-error
                (list "MongoDB maxStalenessSeconds must be -1 or at least 90 seconds")))
       (t value)))))

(defun mongodb--params-read-preference (params)
  "Return a `mongodb--read-preference' from PARAMS."
  (let* ((options (mongodb--params-effective-url-options params))
         (mode (mongodb--params-read-preference-mode params options))
         (tags (mongodb--params-read-preference-tags params options))
         (max-staleness (mongodb--params-max-staleness-seconds
                         params options))
         (heartbeat (or (mongodb--params-heartbeat-frequency params)
                        mongodb-monitor-heartbeat-seconds)))
    (when (and (equal mode "primary")
               (or tags max-staleness))
      (signal 'mongodb-error
              (list "MongoDB readPreference=primary cannot use readPreferenceTags or maxStalenessSeconds")))
    (when (and max-staleness
               (< max-staleness
                  (+ heartbeat mongodb--idle-write-period-seconds)))
      (signal 'mongodb-error
              (list "MongoDB maxStalenessSeconds must be at least heartbeatFrequencyMS plus 10 seconds")))
    (make-mongodb--read-preference
     :mode mode
     :tags tags
     :max-staleness-seconds max-staleness)))

(defun mongodb--read-preference-document (read-preference)
  "Return READ-PREFERENCE as a MongoDB $readPreference document."
  (when (and read-preference
             (not (equal (mongodb--read-preference-mode read-preference)
                         "primary")))
    `(("mode" . ,(mongodb--read-preference-mode read-preference))
      ,@(when (mongodb--read-preference-tags read-preference)
          `(("tags" . ,(mongodb--read-preference-tags read-preference))))
      ,@(when (mongodb--read-preference-max-staleness-seconds
               read-preference)
          `(("maxStalenessSeconds" .
             ,(mongodb--read-preference-max-staleness-seconds
               read-preference)))))))

(defun mongodb--read-concern-document-value (value)
  "Return VALUE as a MongoDB readConcern document."
  (cond
   ((null value) nil)
   ((mongodb-document-p value) value)
   ((and (consp value)
         (consp (car value)))
    value)
   (t
    `(("level" . ,(format "%s" value))))))

(defun mongodb--params-read-concern (params)
  "Return a `mongodb--read-concern' from PARAMS, or nil."
  (let* ((options (mongodb--params-effective-url-options params))
         (value (or (plist-get params :read-concern)
                    (plist-get params :readConcern)))
         (level (or (plist-get params :read-concern-level)
                    (plist-get params :readConcernLevel)
                    (mongodb--url-option options "readConcernLevel")))
         (document (or (mongodb--read-concern-document-value value)
                       (and level
                            `(("level" . ,(format "%s" level)))))))
    (when document
      (make-mongodb--read-concern :pairs document))))

(defun mongodb--read-concern-document (read-concern)
  "Return READ-CONCERN as a MongoDB readConcern document."
  (and read-concern
       (mongodb--read-concern-pairs read-concern)))

(defun mongodb--read-concern-command-document (read-concern)
  "Return READ-CONCERN as a MongoDB command document."
  (cond
   ((null read-concern) nil)
   ((mongodb--read-concern-p read-concern)
    (mongodb--read-concern-document read-concern))
   (t
    (mongodb--read-concern-document-value read-concern))))

(defun mongodb--write-concern-w-value (value)
  "Return MongoDB write concern w VALUE normalized for BSON."
  (cond
   ((null value) nil)
   ((integerp value) value)
   ((and (stringp value)
         (string-match-p "\\`[0-9]+\\'" value))
    (string-to-number value))
   (t (format "%s" value))))

(defun mongodb--params-bool-option (params options keys option-key)
  "Return (SPECIFIED . VALUE) for boolean KEYS or URL OPTION-KEY.

Arguments: PARAMS, OPTIONS, KEYS, OPTION-KEY."
  (let ((found nil)
        value)
    (dolist (key keys)
      (when (and (not found)
                 (plist-member params key))
        (setq found t
              value (plist-get params key))))
    (cond
     (found (cons t (if value t :false)))
     ((mongodb--url-option options option-key)
      (let ((option (mongodb--url-option options option-key)))
        (cond
         ((mongodb--truthy-url-option-p option)
          (cons t t))
         ((mongodb--falsey-url-option-p option)
          (cons t :false))
         (t
          (signal 'mongodb-error
                  (list (format "MongoDB %s must be a boolean, got %S"
                                option-key option))))))))))

(defun mongodb--write-concern-document-value (value)
  "Return VALUE as a MongoDB writeConcern document, or nil."
  (cond
   ((null value) nil)
   ((mongodb-document-p value) value)
   ((and (consp value)
         (consp (car value)))
    value)
   (t
    (signal 'mongodb-error
            (list (format "Invalid MongoDB writeConcern value: %S"
                          value))))))

(defun mongodb--params-write-concern (params)
  "Return a `mongodb--write-concern' from PARAMS, or nil."
  (let* ((options (mongodb--params-effective-url-options params))
         (value (or (plist-get params :write-concern)
                    (plist-get params :writeConcern)))
         (w (mongodb--write-concern-w-value
             (or (plist-get params :w)
                 (mongodb--url-option options "w"))))
         (wtimeout
          (mongodb--parse-integer-option
           (or (plist-get params :w-timeout-ms)
               (plist-get params :wtimeoutms)
               (plist-get params :wTimeoutMS)
               (mongodb--url-option options "wTimeoutMS"))
           "wTimeoutMS"))
         (journal (mongodb--params-bool-option
                   params options
                   '(:journal :j)
                   "journal"))
         (document (copy-sequence
                    (mongodb--write-concern-document-value value))))
    (when (and wtimeout
               (< wtimeout 0))
      (signal 'mongodb-error
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
      (make-mongodb--write-concern :pairs document))))

(defun mongodb--write-concern-document (write-concern)
  "Return WRITE-CONCERN as a MongoDB writeConcern document."
  (and write-concern
       (mongodb--write-concern-pairs write-concern)))

(defun mongodb--normalize-compressor (compressor)
  "Return normalized MongoDB wire COMPRESSOR name."
  (downcase (format "%s" compressor)))

(defun mongodb--compressor-values (value)
  "Return a list of compressor names parsed from VALUE."
  (cond
   ((null value) nil)
   ((listp value)
    (mapcar #'mongodb--normalize-compressor value))
   ((vectorp value)
    (mapcar #'mongodb--normalize-compressor (append value nil)))
   (t
    (mapcar #'mongodb--normalize-compressor
            (split-string (format "%s" value) "," t "[[:space:]\n\r\t]*")))))

(defun mongodb--params-zlib-compression-level (params)
  "Return zlibCompressionLevel from PARAMS, or nil when omitted.
MongoDB defines valid zlib compression levels as -1 through 9."
  (let* ((options (mongodb--params-effective-url-options params))
         (value (mongodb--parse-integer-option
                 (or (plist-get params :zlib-compression-level)
                     (plist-get params :zlibCompressionLevel)
                     (mongodb--url-option options "zlibCompressionLevel"))
                 "zlibCompressionLevel")))
    (when value
      (when (or (< value -1)
                (> value 9))
        (signal 'mongodb-error
                (list "MongoDB zlibCompressionLevel must be between -1 and 9")))
      value)))

(defun mongodb--validate-zlib-compression-level (params compressors)
  "Validate zlibCompressionLevel in PARAMS for requested COMPRESSORS.
Emacs exposes zlib decompression but not compression-level control.  The
native encoder can emit valid zlib stored-block streams, equivalent to level 0;
explicit non-zero levels are rejected rather than silently ignored."
  (when-let* ((level (mongodb--params-zlib-compression-level params)))
    (when (and (member "zlib" compressors)
               (not (zerop level)))
      (signal 'mongodb-error
              (list "MongoDB zlibCompressionLevel values other than 0 require zlib compression support not available in Emacs")))))

(defun mongodb--params-compressors (params)
  "Return requested MongoDB wire compressors for PARAMS."
  (let* ((options (mongodb--params-effective-url-options params))
         (values (mongodb--compressor-values
                  (or (plist-get params :compressors)
                      (plist-get params :compression)
                      (mongodb--url-option options "compressors"))))
         compressors)
    (dolist (compressor values)
      (pcase compressor
        ((or "disabled" "none" "")
         nil)
        ((or "zlib" "snappy" "noop" "zstd")
         (push compressor compressors))
        (_
         (signal 'mongodb-error
                 (list (format "Unknown MongoDB wire compressor: %s"
                               compressor))))))
    (setq compressors (nreverse (delete-dups compressors)))
    (when (member "zlib" compressors)
      (unless (and (fboundp 'zlib-available-p)
                   (zlib-available-p))
        (signal 'mongodb-error
                (list "MongoDB zlib wire compression requires zlib support in Emacs"))))
    (when (member "zstd" compressors)
      (unless (mongodb--zstd-available-p)
        (signal 'mongodb-error
                (list "MongoDB zstd wire compression requires `mongodb-zstd-program' executable"))))
    (mongodb--validate-zlib-compression-level params compressors)
    compressors))

(defun mongodb--negotiated-compressors (requested server)
  "Return compressors common to REQUESTED and SERVER, preserving REQUESTED order."
  (let ((server (cond
                 ((vectorp server) (append server nil))
                 ((listp server) server)
                 (server (list server)))))
    (cl-remove-if-not (lambda (compressor)
                        (member compressor server))
                      requested)))

(defun mongodb--params-tls-enabled-p (params)
  "Return non-nil when PARAMS request MongoDB TLS."
  (let* ((parts (mongodb--params-url-parts params))
         (options (mongodb--params-effective-url-options params))
         (tls-option (mongodb--url-option options "tls"))
         (ssl-option (mongodb--url-option options "ssl")))
    (cond
     ((plist-member params :tls)
      (plist-get params :tls))
     (tls-option
      (not (mongodb--falsey-url-option-p tls-option)))
     (ssl-option
      (not (mongodb--falsey-url-option-p ssl-option)))
     ((and parts (mongodb--srv-scheme-p parts))
      t)
     (t nil))))

(defun mongodb--params-tls-bool (params options param-key option-key default)
  "Return a TLS boolean from PARAMS, OPTIONS, or DEFAULT.

Arguments: PARAMS, OPTIONS, PARAM-KEY, OPTION-KEY, DEFAULT."
  (cond
   ((plist-member params param-key)
    (plist-get params param-key))
   ((mongodb--url-option options option-key)
    (not (mongodb--truthy-url-option-p
          (mongodb--url-option options option-key))))
   (t default)))

(defun mongodb--params-tls-trustfiles (params options)
  "Return TLS trustfiles from PARAMS or URI OPTIONS."
  (or (plist-get params :tls-trustfiles)
      (plist-get params :trustfiles)
      (when-let* ((file (mongodb--url-option options "tlsCAFile")))
        (list file))
      mongodb-tls-trustfiles))

(defun mongodb--params-tls-keylist (params options)
  "Return TLS client keylist from PARAMS or URI OPTIONS."
  (or (plist-get params :tls-keylist)
      (plist-get params :keylist)
      (when-let* ((file (mongodb--url-option options "tlsCertificateKeyFile")))
        (list (list file file)))
      mongodb-tls-keylist))

(defun mongodb--params-tls-insecure-p (params options)
  "Return non-nil when PARAMS or OPTIONS disable TLS verification."
  (cond
   ((plist-member params :tls-insecure)
    (plist-get params :tls-insecure))
   ((mongodb--url-option options "tlsInsecure")
    (mongodb--url-bool-option-value
     (mongodb--url-option options "tlsInsecure")
     "tlsInsecure"))))

(defun mongodb--params-tls-spec (params host)
  "Return TLS negotiation plist for PARAMS and HOST, or nil."
  (when (mongodb--params-tls-enabled-p params)
    (let* ((options (mongodb--params-effective-url-options params))
           (tls-insecure (mongodb--params-tls-insecure-p params options))
           (verify-certificate
            (and (not tls-insecure)
                 (mongodb--params-tls-bool
                  params options :tls-verify "tlsAllowInvalidCertificates"
                  mongodb-tls-verify-server)))
           (verify-hostname
            (and (not tls-insecure)
                 (mongodb--params-tls-bool
                  params options :tls-verify-hostname "tlsAllowInvalidHostnames"
                  verify-certificate)))
           (verify-error (delq nil
                               (list (and verify-certificate :trustfiles)
                                     (and verify-hostname :hostname)))))
      (list :hostname (or (plist-get params :tls-hostname) host)
            :trustfiles (mongodb--params-tls-trustfiles params options)
            :keylist (mongodb--params-tls-keylist params options)
            :verify-error (and verify-error verify-error)
            :verify-hostname-error verify-hostname))))

(defun mongodb--params-credential (params)
  "Return a MongoDB credential from PARAMS, or nil for no auth."
  (let* ((parts (mongodb--params-url-parts params))
         (options (mongodb--params-effective-url-options params))
         (userinfo (mongodb--url-userinfo (plist-get parts :userinfo)))
         (raw-user (or (plist-get params :user)
                       (plist-get userinfo :user)))
         (user (and (stringp raw-user)
                    (> (length raw-user) 0)
                    raw-user))
         (secret (or (plist-get params :password)
                     (plist-get userinfo :password)))
         (mechanism (mongodb--params-auth-mechanism params options))
         (x509 (mongodb--x509-auth-mechanism-p mechanism))
         (plain (mongodb--plain-auth-mechanism-p mechanism))
         (aws (mongodb--aws-auth-mechanism-p mechanism))
         (oidc (mongodb--oidc-auth-mechanism-p mechanism))
         (mechanism-properties
          (mongodb--params-mechanism-properties params options))
         (explicit-source (or (plist-get params :auth-database)
                              (plist-get params :auth-source)
                              (mongodb--url-option options "authSource")))
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
               (mongodb--params-oidc-allowed-hosts params)))
         (auth-requested (or (plist-get userinfo :explicit)
                             user
                             secret
                             mechanism)))
    (mongodb--validate-mechanism-properties mechanism mechanism-properties)
    (when oidc
      (mongodb--validate-oidc-configuration
       mechanism-properties oidc-callback oidc-human-callback))
    (when auth-requested
      (if x509
          (progn
            (when secret
              (signal 'mongodb-error
                      (list "MongoDB MONGODB-X509 authentication must not include a password")))
            (unless (equal source "$external")
              (signal 'mongodb-error
                      (list "MongoDB MONGODB-X509 authentication requires authSource=$external")))
            (unless (mongodb--params-tls-enabled-p params)
              (signal 'mongodb-error
                      (list "MongoDB MONGODB-X509 authentication requires TLS with a client certificate"))))
        (when oidc
          (when secret
            (signal 'mongodb-error
                    (list "MongoDB MONGODB-OIDC authentication must not include a password")))
          (unless (equal source "$external")
            (signal 'mongodb-error
                    (list "MongoDB MONGODB-OIDC authentication requires authSource=$external"))))
        (when (and plain
                   (not (equal source "$external")))
          (signal 'mongodb-error
                  (list "MongoDB PLAIN authentication requires authSource=$external")))
        (when (and aws
                   (not (equal source "$external")))
          (signal 'mongodb-error
                  (list "MongoDB MONGODB-AWS authentication requires authSource=$external")))
        (if (or aws oidc)
            (when (or user secret)
              (unless (or oidc
                          (and user (stringp secret)))
                (signal 'mongodb-error
                        (list "MongoDB MONGODB-AWS authentication requires both AWS access key id and secret access key when credentials are supplied in the URI or params"))))
          (unless user
            (signal 'mongodb-error
                    (list "Native MongoDB authentication requires :user or URI username")))
          (unless (stringp secret)
            (signal 'mongodb-error
                    (list "Native MongoDB authentication requires :password or URI password")))))
      (make-mongodb--credential
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

(defun mongodb--validate-raw-load-balanced-params (params)
  "Validate loadBalanced constraints that do not need SRV TXT records.

Arguments: PARAMS."
  (when (mongodb--params-raw-load-balanced-p params)
    (when (mongodb--params-raw-replica-set-name params)
      (signal 'mongodb-error
              (list "MongoDB loadBalanced=true cannot be combined with replicaSet")))
    (when (mongodb--params-raw-direct-connection-p params)
      (signal 'mongodb-error
              (list "MongoDB loadBalanced=true cannot be combined with directConnection=true")))
    (when (mongodb--params-srv-max-hosts params)
      (signal 'mongodb-error
              (list "MongoDB loadBalanced=true cannot be combined with srvMaxHosts")))))

(defun mongodb--validate-raw-srv-max-hosts-params (params)
  "Validate srvMaxHosts constraints that do not need SRV TXT records.

Arguments: PARAMS."
  (when (and (mongodb--params-srv-max-hosts params)
             (mongodb--params-raw-replica-set-name params))
    (signal 'mongodb-error
            (list "MongoDB srvMaxHosts cannot be combined with replicaSet"))))

(defun mongodb--reject-unsupported-params (params)
  "Signal if PARAMS need unsupported native MongoDB features."
  (mongodb--validate-raw-load-balanced-params params)
  (mongodb--validate-raw-srv-max-hosts-params params)
  (mongodb--params-validate-pool-options params))

(provide 'mongodb-params)

;;; mongodb-params.el ends here
