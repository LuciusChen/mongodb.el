;;; mongodb.el --- Native MongoDB protocol client -*- lexical-binding: t; -*-

;; Copyright (C) 2025-2026 Lucius Chen
;; SPDX-License-Identifier: GPL-3.0-or-later

;; Author: Lucius Chen <chenyh572@gmail.com>
;; Assisted-by: OpenAI Codex:gpt-5.5
;; Maintainer: Lucius Chen <chenyh572@gmail.com>
;; Version: 0.1.0
;; Package-Requires: ((emacs "29.1"))
;; Keywords: data, tools
;; URL: https://github.com/LuciusChen/mongodb.el

;;; Commentary:

;; Native MongoDB command-level protocol client for Emacs Lisp.  This package
;; speaks BSON and OP_MSG directly; it is not a JavaScript shell, JDBC bridge,
;; SQL interface, or GUI layer.

;;; Code:

(require 'cl-lib)
(require 'gnutls)
(require 'seq)
(require 'subr-x)
(require 'ucs-normalize)
(require 'url-parse)
(require 'url-util)

(defgroup mongodb nil
  "MongoDB protocol client."
  :group 'applications)

(defcustom mongodb-timeout-seconds 30
  "Seconds to wait for MongoDB command responses."
  :type 'number
  :group 'mongodb)

(defcustom mongodb-connect-timeout-seconds 10
  "Seconds to wait while opening a MongoDB socket."
  :type 'number
  :group 'mongodb)

(defcustom mongodb-tls-verify-server t
  "Non-nil means verify MongoDB TLS certificates and hostnames by default."
  :type 'boolean
  :group 'mongodb)

(defconst mongodb-version "0.1.0")





(define-error 'mongodb-error "MongoDB wire protocol error")

(defconst mongodb--int32-min (- (expt 2 31)))
(defconst mongodb--int32-max (1- (expt 2 31)))
(defconst mongodb--uint32-mod (expt 2 32))
(defconst mongodb--uint64-mod (expt 2 64))
(defconst mongodb--int64-sign (expt 2 63))
(defconst mongodb--int64-min (- mongodb--int64-sign))
(defconst mongodb--int64-max (1- mongodb--int64-sign))
(defconst mongodb--double-significand-scale (expt 2 52))
(defconst mongodb--double-positive-infinity (read "1.0e+INF"))
(defconst mongodb--decimal128-exponent-bias 6176)
(defconst mongodb--decimal128-min-exponent -6176)
(defconst mongodb--decimal128-max-exponent 6111)
(defconst mongodb--decimal128-max-digits 34)
(defconst mongodb--decimal128-max-coefficient (1- (expt 10 34)))


(cl-defstruct (mongodb-document
               (:constructor mongodb-document (pairs)))
  "Parsed MongoDB document wrapper used to preserve empty documents."
  pairs)

(cl-defstruct (mongodb-object-id
               (:constructor mongodb-object-id (hex)))
  "MongoDB ObjectId wrapper for query encoding."
  hex)

(cl-defstruct (mongodb-datetime
               (:constructor mongodb-datetime (millis)))
  "MongoDB UTC datetime wrapper for query encoding.
MILLIS is an integer count of milliseconds since the Unix epoch."
  millis)

(cl-defstruct (mongodb-timestamp
               (:constructor mongodb-timestamp (seconds increment)))
  "MongoDB BSON timestamp wrapper for query encoding.
SECONDS is the Unix epoch second.  INCREMENT is the ordinal within that
second."
  seconds
  increment)

(cl-defstruct (mongodb-int32
               (:constructor mongodb-int32 (value)))
  "MongoDB int32 wrapper for command fields that require BSON int."
  value)

(cl-defstruct (mongodb-int64
               (:constructor mongodb-int64 (value)))
  "MongoDB int64 wrapper for command fields that require BSON long."
  value)

(cl-defstruct (mongodb-decimal128
               (:constructor mongodb-decimal128 (value)))
  "MongoDB Decimal128 wrapper for query encoding.
VALUE is a Decimal128 text value, such as \"1.23\", \"NaN\", or
\"-Infinity\"."
  value)

(cl-defstruct (mongodb-undefined
               (:constructor mongodb-undefined ()))
  "MongoDB BSON Undefined wrapper for compatibility with legacy documents.")

(cl-defstruct (mongodb-db-pointer
               (:constructor mongodb-db-pointer (namespace object-id)))
  "MongoDB BSON DBPointer wrapper for compatibility with legacy documents.
NAMESPACE is the collection namespace string.  OBJECT-ID is a
`mongodb-object-id' or a 24-character ObjectId hex string."
  namespace
  object-id)

(cl-defstruct (mongodb-code
               (:constructor mongodb-code (code &optional scope)))
  "MongoDB BSON JavaScript code wrapper.
CODE is the JavaScript source string.  Optional SCOPE is a BSON document value."
  code
  scope)

(cl-defstruct (mongodb-symbol
               (:constructor mongodb-symbol (value)))
  "MongoDB BSON Symbol wrapper for compatibility with legacy documents."
  value)

(cl-defstruct (mongodb-binary
               (:constructor mongodb-binary (subtype data)))
  "MongoDB binary value wrapper for BSON encoding.
SUBTYPE is the BSON binary subtype byte.  DATA is a unibyte string."
  subtype
  data)

(defun mongodb-uuid (uuid)
  "Return UUID encoded as BSON binary subtype 4.
UUID must be a canonical RFC 4122 string."
  (unless (and (stringp uuid)
               (string-match-p
                (concat "\\`[0-9a-fA-F]\\{8\\}-"
                        "[0-9a-fA-F]\\{4\\}-"
                        "[0-9a-fA-F]\\{4\\}-"
                        "[0-9a-fA-F]\\{4\\}-"
                        "[0-9a-fA-F]\\{12\\}\\'")
                uuid))
    (signal 'mongodb-error
            (list (format "Invalid MongoDB UUID: %S" uuid))))
  (mongodb-binary
   4
   (mongodb--hex-to-bytes (replace-regexp-in-string "-" "" uuid nil t)
                        32
                        "UUID")))

(cl-defstruct (mongodb-regex
               (:constructor mongodb-regex (pattern &optional options)))
  "MongoDB BSON regular expression wrapper.
PATTERN is the regex pattern.  OPTIONS is a BSON regex option string."
  pattern
  options)

(cl-defstruct (mongodb-min-key
               (:constructor mongodb-min-key ()))
  "MongoDB BSON MinKey wrapper for query encoding.")

(cl-defstruct (mongodb-max-key
               (:constructor mongodb-max-key ()))
  "MongoDB BSON MaxKey wrapper for query encoding.")


(cl-defstruct mongodb--reader
  data
  (pos 0))

;;;; Little-endian primitives

(defun mongodb--pack-uint-le (value bytes)
  "Return VALUE packed as unsigned little-endian BYTES."
  (when (< value 0)
    (setq value (+ value (expt 2 (* 8 bytes)))))
  (pcase bytes
    (2
     (unibyte-string (logand value #xff)
                     (logand (ash value -8) #xff)))
    (4
     (unibyte-string (logand value #xff)
                     (logand (ash value -8) #xff)
                     (logand (ash value -16) #xff)
                     (logand (ash value -24) #xff)))
    (8
     (unibyte-string (logand value #xff)
                     (logand (ash value -8) #xff)
                     (logand (ash value -16) #xff)
                     (logand (ash value -24) #xff)
                     (logand (ash value -32) #xff)
                     (logand (ash value -40) #xff)
                     (logand (ash value -48) #xff)
                     (logand (ash value -56) #xff)))
    (_
     (apply #'unibyte-string
            (cl-loop for shift from 0 below (* 8 bytes) by 8
                     collect (logand (ash value (- shift)) #xff))))))

(defun mongodb--pack-int32 (value)
  "Return VALUE packed as little-endian int32."
  (mongodb--pack-uint-le value 4))

(defun mongodb--pack-int64 (value)
  "Return VALUE packed as little-endian int64."
  (mongodb--pack-uint-le value 8))

(defun mongodb--read-byte (reader)
  "Read one byte from READER."
  (let* ((pos (mongodb--reader-pos reader))
         (data (mongodb--reader-data reader)))
    (when (>= pos (length data))
      (signal 'mongodb-error
              (list "MongoDB wire response ended unexpectedly")))
    (setf (mongodb--reader-pos reader) (1+ pos))
    (aref data pos)))

(defun mongodb--read-bytes (reader size)
  "Read SIZE raw bytes from READER."
  (unless (and (integerp size) (>= size 0))
    (signal 'mongodb-error
            (list (format "Invalid MongoDB wire byte count: %S" size))))
  (let* ((pos (mongodb--reader-pos reader))
         (end (+ pos size))
         (data (mongodb--reader-data reader)))
    (when (> end (length data))
      (signal 'mongodb-error
              (list "MongoDB wire response ended unexpectedly")))
    (setf (mongodb--reader-pos reader) end)
    (substring data pos end)))

(defun mongodb--read-uint-le (reader bytes)
  "Read an unsigned little-endian integer of BYTES from READER."
  (let* ((pos (mongodb--reader-pos reader))
         (end (+ pos bytes))
         (data (mongodb--reader-data reader)))
    (when (> end (length data))
      (signal 'mongodb-error
              (list "MongoDB wire response ended unexpectedly")))
    (setf (mongodb--reader-pos reader) end)
    (pcase bytes
      (2
       (logior (aref data pos)
               (ash (aref data (+ pos 1)) 8)))
      (4
       (logior (aref data pos)
               (ash (aref data (+ pos 1)) 8)
               (ash (aref data (+ pos 2)) 16)
               (ash (aref data (+ pos 3)) 24)))
      (8
       (logior (aref data pos)
               (ash (aref data (+ pos 1)) 8)
               (ash (aref data (+ pos 2)) 16)
               (ash (aref data (+ pos 3)) 24)
               (ash (aref data (+ pos 4)) 32)
               (ash (aref data (+ pos 5)) 40)
               (ash (aref data (+ pos 6)) 48)
               (ash (aref data (+ pos 7)) 56)))
      (_
       (let ((value 0)
             (i 0))
         (while (< i bytes)
           (setq value (logior value
                               (ash (aref data (+ pos i)) (* 8 i))))
           (setq i (1+ i)))
         value)))))

(defun mongodb--read-int32 (reader)
  "Read a little-endian int32 from READER."
  (let ((value (mongodb--read-uint-le reader 4)))
    (if (>= value #x80000000)
        (- value #x100000000)
      value)))

(defun mongodb--read-int64 (reader)
  "Read a little-endian int64 from READER."
  (let ((value (mongodb--read-uint-le reader 8)))
    (if (>= value mongodb--int64-sign)
        (- value mongodb--uint64-mod)
      value)))

(defun mongodb--decode-double (reader)
  "Read a little-endian IEEE-754 double from READER."
  (let* ((bits (mongodb--read-uint-le reader 8))
         (sign (if (zerop (logand (ash bits -63) 1)) 1.0 -1.0))
         (exponent (logand (ash bits -52) #x7ff))
         (fraction (logand bits (1- (expt 2 52)))))
    (cond
     ((= exponent 0)
      (* sign fraction (expt 2.0 -1074)))
     ((= exponent #x7ff)
      (if (zerop fraction)
          (if (> sign 0) "Infinity" "-Infinity")
        "NaN"))
     (t
      (* sign
         (+ 1.0 (/ fraction (float (expt 2 52))))
         (expt 2.0 (- exponent 1023)))))))

(defun mongodb--encode-double (value)
  "Return VALUE packed as little-endian IEEE-754 double."
  (let ((sign-bit (if (< (copysign 1.0 value) 0.0)
                      mongodb--int64-sign
                    0)))
    (mongodb--pack-int64
     (cond
      ((isnan value)
       (+ sign-bit #x7ff8000000000000))
      ((= (logb value) mongodb--double-positive-infinity)
       (+ sign-bit #x7ff0000000000000))
      ((zerop value)
       sign-bit)
      (t
       (let* ((abs-value (abs value))
              (parts (frexp abs-value))
              (mantissa (car parts))
              (exponent (cdr parts)))
         (if (>= exponent -1021)
             (let* ((biased-exponent (+ exponent 1022))
                    (fraction
                     (round
                      (ldexp (- (* mantissa 2.0) 1.0) 52))))
               (when (= fraction mongodb--double-significand-scale)
                 (setq fraction 0
                       biased-exponent (1+ biased-exponent)))
               (+ sign-bit
                  (ash biased-exponent 52)
                  fraction))
           (+ sign-bit
              (round (ldexp abs-value 1074))))))))))

(defun mongodb--read-cstring (reader)
  "Read a null-terminated UTF-8 string from READER."
  (let* ((data (mongodb--reader-data reader))
         (start (mongodb--reader-pos reader))
         (end (cl-position 0 data :start start)))
    (unless end
      (signal 'mongodb-error
              (list "MongoDB wire response contains an unterminated cstring")))
    (setf (mongodb--reader-pos reader) (1+ end))
    (decode-coding-string (substring data start end) 'utf-8 t)))

(defun mongodb--encode-cstring (string)
  "Return STRING encoded as BSON cstring."
  (let ((bytes (encode-coding-string (format "%s" string) 'utf-8 t)))
    (when (cl-position 0 bytes)
      (signal 'mongodb-error
              (list (format "MongoDB document key contains NUL: %S" string))))
    (concat bytes (unibyte-string 0))))

(defun mongodb--encode-string-value (string)
  "Return STRING encoded as a BSON string value."
  (let ((bytes (encode-coding-string string 'utf-8 t)))
    (concat (mongodb--pack-int32 (1+ (length bytes)))
            bytes
            (unibyte-string 0))))

(defun mongodb--decode-string-value (reader)
  "Read a BSON string value from READER."
  (let* ((length (mongodb--read-int32 reader))
         (bytes (mongodb--read-bytes reader (1- length))))
    (unless (zerop (mongodb--read-byte reader))
      (signal 'mongodb-error
              (list "MongoDB BSON string is not null-terminated")))
    (decode-coding-string bytes 'utf-8 t)))

;;;; BSON

(defun mongodb--document-pairs (document)
  "Return key/value pairs for BSON DOCUMENT."
  (cond
   ((mongodb-document-p document)
    (mongodb-document-pairs document))
   ((hash-table-p document)
    (let (pairs)
      (maphash (lambda (key value)
                 (push (cons (format "%s" key) value) pairs))
               document)
      (nreverse pairs)))
   ((and (consp document)
         (consp (car document)))
    document)
   ((null document) nil)
   (t
    (signal 'mongodb-error
            (list (format "Cannot encode MongoDB document: %S" document))))))

(defun mongodb--document-value-p (value)
  "Return non-nil when VALUE should encode as a BSON document."
  (or (mongodb-document-p value)
      (hash-table-p value)
      (and (consp value)
           (consp (car value)))))

(defun mongodb-document-value-p (value)
  "Return non-nil when VALUE can encode as a BSON document."
  (mongodb--document-value-p value))

(defun mongodb-document-elements (document)
  "Return BSON key/value pairs for DOCUMENT.
DOCUMENT may be a `mongodb-document', hash table, alist, or nil.  Signal
`mongodb-error' when DOCUMENT is not document-shaped."
  (mongodb--document-pairs document))

(defun mongodb--hex-to-bytes (hex expected-length name)
  "Return HEX decoded as bytes after validating EXPECTED-LENGTH for NAME."
  (unless (and (stringp hex)
               (= (length hex) expected-length)
               (string-match-p "\\`[0-9a-fA-F]+\\'" hex))
    (signal 'mongodb-error
            (list (format "Invalid MongoDB %s: %S" name hex))))
  (apply #'unibyte-string
         (cl-loop for i from 0 below expected-length by 2
                  collect (string-to-number (substring hex i (+ i 2)) 16))))

(defun mongodb--encode-object-id (object-id)
  "Return OBJECT-ID encoded as 12 raw bytes."
  (mongodb--hex-to-bytes (mongodb-object-id-hex object-id) 24 "ObjectId"))

(defun mongodb--object-id-bytes (value)
  "Return VALUE encoded as raw MongoDB ObjectId bytes."
  (mongodb--encode-object-id
   (cond
    ((mongodb-object-id-p value) value)
    ((stringp value) (mongodb-object-id value))
    (t
     (signal 'mongodb-error
             (list (format "Invalid MongoDB ObjectId value: %S" value)))))))

(defun mongodb--decode-object-id (reader)
  "Read an ObjectId from READER as Extended JSON."
  (let ((bytes (mongodb--read-bytes reader 12)))
    (list (cons "$oid"
                (mapconcat (lambda (byte) (format "%02x" byte))
                           bytes
                           "")))))

(defun mongodb--uint32-value (value name)
  "Return VALUE as an unsigned 32-bit integer for MongoDB field NAME."
  (unless (and (integerp value)
               (<= 0 value)
               (< value mongodb--uint32-mod))
    (signal 'mongodb-error
            (list (format "MongoDB %s must be an unsigned 32-bit integer, got %S"
                          name value))))
  value)

(defun mongodb--int32-value (value name)
  "Return VALUE as a signed 32-bit integer for MongoDB field NAME."
  (unless (and (integerp value)
               (<= mongodb--int32-min value)
               (<= value mongodb--int32-max))
    (signal 'mongodb-error
            (list (format "MongoDB %s must be a signed 32-bit integer, got %S"
                          name value))))
  value)

(defun mongodb--int64-value (value name)
  "Return VALUE as a signed 64-bit integer for MongoDB field NAME."
  (unless (and (integerp value)
               (<= mongodb--int64-min value)
               (<= value mongodb--int64-max))
    (signal 'mongodb-error
            (list (format "MongoDB %s must be a signed 64-bit integer, got %S"
                          name value))))
  value)

(defun mongodb--encode-binary (binary)
  "Return BINARY encoded as a BSON binary value."
  (let* ((subtype (mongodb-binary-subtype binary))
         (data (mongodb--byte-string (mongodb-binary-data binary))))
    (unless (and (integerp subtype)
                 (<= 0 subtype)
                 (<= subtype #xff))
      (signal 'mongodb-error
              (list (format "Invalid MongoDB binary subtype: %S" subtype))))
    (if (= subtype 2)
        (let ((payload (concat (mongodb--pack-int32 (length data))
                               data)))
          (concat (mongodb--pack-int32 (length payload))
                  (unibyte-string subtype)
                  payload))
      (concat (mongodb--pack-int32 (length data))
              (unibyte-string subtype)
              data))))

(defun mongodb--encode-db-pointer (db-pointer)
  "Return DB-POINTER encoded as a BSON DBPointer payload."
  (let ((namespace (mongodb-db-pointer-namespace db-pointer)))
    (unless (stringp namespace)
      (signal 'mongodb-error
              (list (format "MongoDB DBPointer namespace must be a string, got %S"
                            namespace))))
    (concat (mongodb--encode-string-value namespace)
            (mongodb--object-id-bytes
             (mongodb-db-pointer-object-id db-pointer)))))

(defun mongodb--decimal128-special-p (text value)
  "Return non-nil when Decimal128 TEXT names special VALUE."
  (let ((case-fold-search t))
    (string-match-p
     (pcase value
       (:nan "\\`[+-]?nan\\'")
       (:infinity "\\`\\+?\\(?:inf\\|infinity\\)\\'")
       (:negative-infinity "\\`-\\(?:inf\\|infinity\\)\\'"))
     text)))

(defun mongodb--parse-decimal128 (value)
  "Parse Decimal128 VALUE into a kind list for BSON encoding."
  (unless (stringp value)
    (signal 'mongodb-error
            (list (format "MongoDB Decimal128 must be a string, got %S"
                          value))))
  (cond
   ((mongodb--decimal128-special-p value :nan)
    (list :nan))
   ((mongodb--decimal128-special-p value :infinity)
    (list :infinity nil))
   ((mongodb--decimal128-special-p value :negative-infinity)
    (list :infinity t))
   ((string-match
     (concat "\\`\\([+-]?\\)"
             "\\(?:\\([0-9]+\\)\\(?:\\.\\([0-9]*\\)\\)?\\|\\.\\([0-9]+\\)\\)"
             "\\(?:[eE]\\([+-]?[0-9]+\\)\\)?\\'")
     value)
    (let* ((negative (equal (match-string 1 value) "-"))
           (integer-part (or (match-string 2 value) ""))
           (fraction-part (or (match-string 3 value)
                              (match-string 4 value)
                              ""))
           (explicit-exponent (if (match-string 5 value)
                                  (string-to-number (match-string 5 value))
                                0))
           (exponent (- explicit-exponent (length fraction-part)))
           (digits (concat integer-part fraction-part)))
      (setq digits (replace-regexp-in-string "\\`0+" "" digits))
      (if (string-empty-p digits)
          (progn
            (setq exponent
                  (min mongodb--decimal128-max-exponent
                       (max mongodb--decimal128-min-exponent exponent)))
            (list :finite negative 0 exponent))
        (while (and (> (length digits) mongodb--decimal128-max-digits)
                    (string-suffix-p "0" digits))
          (setq digits (substring digits 0 -1)
                exponent (1+ exponent)))
        (when (> (length digits) mongodb--decimal128-max-digits)
          (signal 'mongodb-error
                  (list (format "MongoDB Decimal128 has more than %s significant digits: %S"
                                mongodb--decimal128-max-digits value))))
        (while (and (< exponent mongodb--decimal128-min-exponent)
                    (string-suffix-p "0" digits))
          (setq digits (substring digits 0 -1)
                exponent (1+ exponent)))
        (when (< exponent mongodb--decimal128-min-exponent)
          (signal 'mongodb-error
                  (list (format "MongoDB Decimal128 exponent underflow: %S"
                                value))))
        (while (and (> exponent mongodb--decimal128-max-exponent)
                    (< (length digits) mongodb--decimal128-max-digits))
          (setq digits (concat digits "0")
                exponent (1- exponent)))
        (when (> exponent mongodb--decimal128-max-exponent)
          (signal 'mongodb-error
                  (list (format "MongoDB Decimal128 exponent overflow: %S"
                                value))))
        (list :finite negative (string-to-number digits) exponent))))
   (t
    (signal 'mongodb-error
            (list (format "Invalid MongoDB Decimal128 string: %S"
                          value))))))

(defun mongodb--encode-decimal128 (decimal)
  "Return DECIMAL encoded as a BSON Decimal128 payload."
  (pcase (mongodb--parse-decimal128 (mongodb-decimal128-value decimal))
    (`(:nan)
     (concat (mongodb--pack-uint-le 0 8)
             (mongodb--pack-uint-le #x7c00000000000000 8)))
    (`(:infinity ,negative)
     (concat (mongodb--pack-uint-le 0 8)
             (mongodb--pack-uint-le
              (if negative
                  #xf800000000000000
                #x7800000000000000)
              8)))
    (`(:finite ,negative ,coefficient ,exponent)
     (when (> coefficient mongodb--decimal128-max-coefficient)
       (signal 'mongodb-error
               (list (format "MongoDB Decimal128 coefficient is too large: %S"
                             (mongodb-decimal128-value decimal)))))
     (let* ((biased-exponent (+ exponent mongodb--decimal128-exponent-bias))
            (low (logand coefficient (1- mongodb--uint64-mod)))
            (high (logior (ash biased-exponent 49)
                          (ash coefficient -64)
                          (if negative
                              (expt 2 63)
                            0))))
       (concat (mongodb--pack-uint-le low 8)
               (mongodb--pack-uint-le high 8))))))

(defun mongodb--normalize-regex-options (options)
  "Return BSON regex OPTIONS sorted and validated."
  (let ((chars nil))
    (dolist (char (append (or options "") nil))
      (unless (memq char '(?i ?m ?s ?u ?x))
        (signal 'mongodb-error
                (list (format "Unsupported MongoDB regex option: %c"
                              char))))
      (cl-pushnew char chars))
    (apply #'string (sort chars #'<))))

(defun mongodb--encode-regex (regex)
  "Return REGEX encoded as BSON regex payload."
  (concat (mongodb--encode-cstring (mongodb-regex-pattern regex))
          (mongodb--encode-cstring
           (mongodb--normalize-regex-options
            (mongodb-regex-options regex)))))

(defun mongodb--encode-timestamp (timestamp)
  "Return TIMESTAMP encoded as a BSON timestamp payload."
  (concat
   (mongodb--pack-uint-le
    (mongodb--uint32-value (mongodb-timestamp-increment timestamp)
                         "timestamp increment")
    4)
   (mongodb--pack-uint-le
    (mongodb--uint32-value (mongodb-timestamp-seconds timestamp)
                         "timestamp seconds")
    4)))

(defun mongodb--encode-array (array)
  "Return ARRAY encoded as a BSON array document."
  (let ((seq (if (vectorp array) array (vconcat array))))
    (mongodb--encode-document
     (cl-loop for value across seq
              for index from 0
              collect (cons (number-to-string index) value)))))

(defun mongodb--encode-element (key value)
  "Return BSON element KEY with VALUE."
  (let ((name (mongodb--encode-cstring key)))
    (cond
     ((floatp value)
      (concat (unibyte-string #x01)
              name
              (mongodb--encode-double value)))
     ((stringp value)
      (concat (unibyte-string #x02)
              name
              (mongodb--encode-string-value value)))
     ((mongodb-undefined-p value)
      (concat (unibyte-string #x06) name))
     ((mongodb--document-value-p value)
      (concat (unibyte-string #x03)
              name
              (mongodb--encode-document value)))
     ((mongodb-object-id-p value)
      (concat (unibyte-string #x07)
              name
              (mongodb--encode-object-id value)))
     ((mongodb-datetime-p value)
      (concat (unibyte-string #x09)
              name
              (mongodb--pack-int64 (mongodb-datetime-millis value))))
     ((mongodb-timestamp-p value)
      (concat (unibyte-string #x11)
              name
              (mongodb--encode-timestamp value)))
     ((mongodb-int32-p value)
      (concat (unibyte-string #x10)
              name
              (mongodb--pack-int32
               (mongodb--int32-value (mongodb-int32-value value)
                                    "int32"))))
     ((mongodb-int64-p value)
      (concat (unibyte-string #x12)
              name
              (mongodb--pack-int64
               (mongodb--int64-value (mongodb-int64-value value)
                                    "int64"))))
     ((mongodb-decimal128-p value)
      (concat (unibyte-string #x13)
              name
              (mongodb--encode-decimal128 value)))
     ((mongodb-binary-p value)
      (concat (unibyte-string #x05)
              name
              (mongodb--encode-binary value)))
     ((mongodb-regex-p value)
      (concat (unibyte-string #x0b)
              name
              (mongodb--encode-regex value)))
     ((mongodb-db-pointer-p value)
      (concat (unibyte-string #x0c)
              name
              (mongodb--encode-db-pointer value)))
     ((mongodb-code-p value)
      (if (mongodb-code-scope value)
          (let* ((payload
                  (concat
                   (mongodb--encode-string-value (mongodb-code-code value))
                   (mongodb--encode-document (mongodb-code-scope value))))
                 (length (+ 4 (length payload))))
            (concat (unibyte-string #x0f)
                    name
                    (mongodb--pack-int32 length)
                    payload))
        (concat (unibyte-string #x0d)
                name
                (mongodb--encode-string-value (mongodb-code-code value)))))
     ((mongodb-symbol-p value)
      (concat (unibyte-string #x0e)
              name
              (mongodb--encode-string-value (mongodb-symbol-value value))))
     ((mongodb-min-key-p value)
      (concat (unibyte-string #xff) name))
     ((mongodb-max-key-p value)
      (concat (unibyte-string #x7f) name))
     ((vectorp value)
      (concat (unibyte-string #x04)
              name
              (mongodb--encode-array value)))
     ((eq value t)
      (concat (unibyte-string #x08) name (unibyte-string #x01)))
     ((eq value :false)
      (concat (unibyte-string #x08) name (unibyte-string #x00)))
     ((null value)
      (concat (unibyte-string #x0a) name))
     ((integerp value)
      (if (and (>= value mongodb--int32-min)
               (<= value mongodb--int32-max))
          (concat (unibyte-string #x10)
                  name
                  (mongodb--pack-int32 value))
        (concat (unibyte-string #x12)
                name
                (mongodb--pack-int64
                 (mongodb--int64-value value "integer")))))
     (t
      (signal 'mongodb-error
              (list (format "Cannot encode MongoDB BSON value for %s: %S"
                            key value)))))))

(defun mongodb--encode-document (document)
  "Return DOCUMENT encoded as BSON."
  (let* ((body (apply #'concat
                      (append
                       (mapcar (lambda (pair)
                                 (mongodb--encode-element
                                  (car pair)
                                  (cdr pair)))
                               (mongodb--document-pairs document))
                       (list (unibyte-string 0)))))
         (length (+ 4 (length body))))
    (concat (mongodb--pack-int32 length) body)))

(defun mongodb--decode-binary (reader)
  "Read BSON binary from READER as Extended JSON-ish data."
  (let* ((size (mongodb--read-int32 reader))
         (subtype (mongodb--read-byte reader))
         (bytes (if (= subtype 2)
                    (let ((inner-size (mongodb--read-int32 reader)))
                      (unless (= inner-size (- size 4))
                        (signal 'mongodb-error
                                (list (format "Invalid old MongoDB binary length: outer %S inner %S"
                                              size inner-size))))
                      (mongodb--read-bytes reader inner-size))
                  (mongodb--read-bytes reader size))))
    (list (cons "$binary"
                (list (cons "subType" (format "%02x" subtype))
                      (cons "bytes"
                            (base64-encode-string bytes t)))))))

(defun mongodb--decode-datetime (reader)
  "Read BSON UTC datetime from READER as Extended JSON-ish data."
  (let ((millis (mongodb--read-int64 reader)))
    (list (cons "$date" millis))))

(defun mongodb--decode-timestamp (reader)
  "Read BSON timestamp from READER as Extended JSON-ish data."
  (let* ((raw (mongodb--read-uint-le reader 8))
         (increment (logand raw #xffffffff))
         (time (logand (ash raw -32) #xffffffff)))
    (list (cons "$timestamp"
                (list (cons "t" time)
                      (cons "i" increment))))))

(defun mongodb--decode-regex (reader)
  "Read BSON regex from READER as Extended JSON."
  (let ((pattern (mongodb--read-cstring reader))
        (options (mongodb--read-cstring reader)))
    (list (cons "$regularExpression"
                (list (cons "pattern" pattern)
                      (cons "options" options))))))

(defun mongodb--decode-db-pointer (reader)
  "Read BSON DBPointer from READER as Extended JSON."
  (let ((namespace (mongodb--decode-string-value reader))
        (object-id (mongodb--decode-object-id reader)))
    (list (cons "$dbPointer"
                (list (cons "$ref" namespace)
                      (cons "$id" object-id))))))

(defun mongodb--decode-code (reader)
  "Read BSON JavaScript code from READER as Extended JSON."
  (list (cons "$code" (mongodb--decode-string-value reader))))

(defun mongodb--decode-symbol (reader)
  "Read BSON Symbol from READER as Extended JSON."
  (list (cons "$symbol" (mongodb--decode-string-value reader))))

(defun mongodb--decode-code-with-scope (reader)
  "Read BSON JavaScript code with scope from READER as Extended JSON."
  (let* ((start (mongodb--reader-pos reader))
         (length (mongodb--read-int32 reader))
         (end (+ start length))
         (code (mongodb--decode-string-value reader))
         (scope (mongodb--decode-document reader)))
    (unless (= (mongodb--reader-pos reader) end)
      (signal 'mongodb-error
              (list (format "Invalid MongoDB code-with-scope length: %S"
                            length))))
    (list (cons "$code" code)
          (cons "$scope" scope))))

(defun mongodb--decimal128-scientific-string (digits exponent)
  "Return Decimal128 DIGITS formatted with adjusted EXPONENT."
  (concat (substring digits 0 1)
          (when (> (length digits) 1)
            (concat "." (substring digits 1)))
          (format "E%+d" exponent)))

(defun mongodb--format-decimal128 (negative coefficient exponent)
  "Return canonical text for Decimal128 COEFFICIENT and EXPONENT.

Arguments: NEGATIVE, COEFFICIENT, EXPONENT."
  (let* ((sign (if negative "-" ""))
         (digits (number-to-string coefficient)))
    (if (zerop coefficient)
        (concat
         sign
         (cond
          ((zerop exponent) "0")
          ((and (< exponent 0) (>= exponent -6))
           (concat "0." (make-string (- exponent) ?0)))
          (t (concat "0" (format "E%+d" exponent)))))
      (let* ((length (length digits))
             (adjusted (1- (+ length exponent))))
        (concat
         sign
         (cond
          ((> exponent 0)
           (mongodb--decimal128-scientific-string digits adjusted))
          ((zerop exponent)
           digits)
          (t
           (let ((point (+ length exponent)))
             (cond
              ((> point 0)
               (concat (substring digits 0 point)
                       "."
                       (substring digits point)))
              ((>= adjusted -6)
               (concat "0."
                       (make-string (- point) ?0)
                       digits))
              (t
               (mongodb--decimal128-scientific-string
                digits adjusted)))))))))))

(defun mongodb--decode-decimal128 (reader)
  "Read BSON Decimal128 from READER as Extended JSON."
  (let* ((low (mongodb--read-uint-le reader 8))
         (high (mongodb--read-uint-le reader 8))
         (negative (not (zerop (logand high (expt 2 63)))))
         (combination (logand (ash high -58) #x1f)))
    (list
     (cons "$numberDecimal"
           (cond
            ((= combination 30)
             (if negative "-Infinity" "Infinity"))
            ((= combination 31)
             "NaN")
            ((>= combination 24)
             (signal 'mongodb-error
                     (list "Unsupported MongoDB Decimal128 combination field")))
            (t
             (let* ((exponent (- (logand (ash high -49) #x3fff)
                                 mongodb--decimal128-exponent-bias))
                    (coefficient
                     (logior
                      (ash (logand high (1- (expt 2 49))) 64)
                      low)))
               (mongodb--format-decimal128 negative coefficient exponent))))))))

(defun mongodb--decode-element (reader)
  "Read one BSON element from READER."
  (let ((type (mongodb--read-byte reader))
        (name nil))
    (setq name (mongodb--read-cstring reader))
    (cons
     name
     (pcase type
       (#x01 (mongodb--decode-double reader))
       (#x02 (mongodb--decode-string-value reader))
       (#x03 (mongodb--decode-document reader))
       (#x04 (mapcar #'cdr
                     (mongodb--decode-document reader)))
       (#x05 (mongodb--decode-binary reader))
       (#x06 '(("$undefined" . t)))
       (#x07 (mongodb--decode-object-id reader))
       (#x08 (if (zerop (mongodb--read-byte reader))
                 :false
               t))
       (#x09 (mongodb--decode-datetime reader))
       (#x0a nil)
       (#x0b (mongodb--decode-regex reader))
       (#x0c (mongodb--decode-db-pointer reader))
       (#x0d (mongodb--decode-code reader))
       (#x0e (mongodb--decode-symbol reader))
       (#x0f (mongodb--decode-code-with-scope reader))
       (#x10 (mongodb--read-int32 reader))
       (#x11 (mongodb--decode-timestamp reader))
       (#x12 (mongodb--read-int64 reader))
       (#x13 (mongodb--decode-decimal128 reader))
       (#x7f '(("$maxKey" . 1)))
       (#xff '(("$minKey" . 1)))
       (_
        (signal 'mongodb-error
                (list (format "Unsupported MongoDB BSON type 0x%02x for %s"
                              type name))))))))

(defun mongodb--decode-document (reader)
  "Read a BSON document from READER as an alist."
  (let* ((start (mongodb--reader-pos reader))
         (length (mongodb--read-int32 reader))
         (end (+ start length))
         pairs)
    (when (or (< length 5)
              (> end (length (mongodb--reader-data reader))))
      (signal 'mongodb-error
              (list (format "Invalid MongoDB BSON document length: %s" length))))
    (while (< (mongodb--reader-pos reader) (1- end))
      (push (mongodb--decode-element reader) pairs))
    (unless (zerop (mongodb--read-byte reader))
      (signal 'mongodb-error
              (list "MongoDB BSON document is not null-terminated")))
    (setf (mongodb--reader-pos reader) end)
    (nreverse pairs)))

(defun mongodb--decode-document-from-string (data)
  "Decode BSON DATA into an alist."
  (mongodb--decode-document
   (make-mongodb--reader :data data :pos 0)))

(defun mongodb--byte-string (string)
  "Return STRING as a unibyte byte string."
  (if (multibyte-string-p string)
      (encode-coding-string string 'raw-text t)
    string))

(defun mongodb-byte-string (string)
  "Return STRING as a unibyte byte string."
  (mongodb--byte-string string))

(defun mongodb--binary-value-data (value)
  "Return raw bytes from BSON binary VALUE."
  (cond
   ((mongodb-binary-p value)
    (mongodb--byte-string (mongodb-binary-data value)))
   ((and (consp value)
         (consp (car value))
         (assoc "$binary" value))
    (let* ((binary (cdr (assoc "$binary" value)))
           (bytes (cdr (assoc "bytes" binary))))
      (unless (stringp bytes)
        (signal 'mongodb-error
                (list (format "Invalid MongoDB binary value: %S" value))))
      (base64-decode-string bytes)))
   (t
    (signal 'mongodb-error
            (list (format "Expected MongoDB binary value, got: %S" value))))))

(defun mongodb--utf8-bytes (string)
  "Return STRING encoded as unibyte UTF-8."
  (encode-coding-string (format "%s" string) 'utf-8 t))

(defun mongodb--base64-encode (bytes)
  "Return BYTES as base64 without line breaks."
  (base64-encode-string (mongodb--byte-string bytes) t))

(defun mongodb--base64-decode (string)
  "Return base64 STRING decoded as raw bytes."
  (base64-decode-string string))

(defun mongodb--bytes-to-hex (bytes)
  "Return BYTES rendered as lowercase hexadecimal."
  (mapconcat (lambda (byte) (format "%02x" byte))
             (mongodb--byte-string bytes)
             ""))

(defun mongodb-bytes-to-hex (bytes)
  "Return BYTES rendered as lowercase hexadecimal."
  (mongodb--bytes-to-hex bytes))

(defun mongodb--pack-uint32-be (value)
  "Return VALUE packed as unsigned big-endian uint32."
  (apply #'unibyte-string
         (cl-loop for shift from 24 downto 0 by 8
                  collect (logand (ash value (- shift)) #xff))))

(defconst mongodb--crc32c-table
  (apply
   #'vector
   (cl-loop for value from 0 below 256
            collect
            (let ((crc value))
              (dotimes (_ 8)
                (setq crc
                      (if (zerop (logand crc 1))
                          (ash crc -1)
                        (logxor (ash crc -1) #x82f63b78))))
              (logand crc #xffffffff))))
  "CRC-32C table using the reflected Castagnoli polynomial.")

(defun mongodb--crc32c (data)
  "Return the CRC-32C checksum for byte string DATA."
  (setq data (mongodb--byte-string data))
  (let ((crc #xffffffff))
    (dotimes (i (length data))
      (setq crc
            (logxor
             (aref mongodb--crc32c-table
                   (logand (logxor crc (aref data i)) #xff))
             (ash crc -8)))
      (setq crc (logand crc #xffffffff)))
    (logand (logxor crc #xffffffff) #xffffffff)))

(defun mongodb--xor-bytes (a b)
  "Return bytewise XOR of same-length byte strings A and B."
  (setq a (mongodb--byte-string a)
        b (mongodb--byte-string b))
  (unless (= (length a) (length b))
    (signal 'mongodb-error
            (list "Cannot XOR MongoDB byte strings with different lengths")))
  (apply #'unibyte-string
         (cl-loop for i from 0 below (length a)
                  collect (logxor (aref a i) (aref b i)))))

(defun mongodb--hmac-sha256 (key data)
  "Return HMAC-SHA-256 of DATA using KEY."
  (gnutls-hash-mac 'SHA256
                   (copy-sequence (mongodb--byte-string key))
                   (mongodb--byte-string data)))

(defun mongodb--hmac-sha1 (key data)
  "Return HMAC-SHA-1 of DATA using KEY."
  (gnutls-hash-mac 'SHA1
                   (copy-sequence (mongodb--byte-string key))
                   (mongodb--byte-string data)))

(defun mongodb--sha256 (data)
  "Return SHA-256 digest bytes of DATA."
  (secure-hash 'sha256 (mongodb--byte-string data) nil nil t))

(defun mongodb--sha1 (data)
  "Return SHA-1 digest bytes of DATA."
  (secure-hash 'sha1 (mongodb--byte-string data) nil nil t))

(defun mongodb--pbkdf2-hmac-sha256 (secret salt iterations)
  "Return PBKDF2-HMAC-SHA-256 for SECRET and SALT.
The derived key length is SHA-256's 32-byte digest length.

Arguments: SECRET, SALT, ITERATIONS."
  (unless (and (integerp iterations)
               (> iterations 0))
    (signal 'mongodb-error
            (list (format "Invalid MongoDB SCRAM iteration count: %S"
                          iterations))))
  (let* ((u (mongodb--hmac-sha256
             secret
             (concat (mongodb--byte-string salt)
                     (mongodb--pack-uint32-be 1))))
         (result u))
    (dotimes (_ (1- iterations))
      (let ((next-u (mongodb--hmac-sha256 secret u)))
        (setq result (mongodb--xor-bytes result next-u)
              u next-u)))
    result))

(defun mongodb--pbkdf2-hmac-sha1 (secret salt iterations)
  "Return PBKDF2-HMAC-SHA-1 for SECRET and SALT.
The derived key length is SHA-1's 20-byte digest length.

Arguments: SECRET, SALT, ITERATIONS."
  (unless (and (integerp iterations)
               (> iterations 0))
    (signal 'mongodb-error
            (list (format "Invalid MongoDB SCRAM iteration count: %S"
                          iterations))))
  (let* ((u (mongodb--hmac-sha1
             secret
             (concat (mongodb--byte-string salt)
                     (mongodb--pack-uint32-be 1))))
         (result u))
    (dotimes (_ (1- iterations))
      (let ((next-u (mongodb--hmac-sha1 secret u)))
        (setq result (mongodb--xor-bytes result next-u)
              u next-u)))
    result))





(defconst mongodb--op-msg 2013)

(defconst mongodb--op-msg-checksum-present #x1)

(defconst mongodb--op-msg-more-to-come #x2)

(defconst mongodb--op-msg-required-flag-mask #xffff)

(defconst mongodb--op-msg-known-required-flag-mask
  (logior mongodb--op-msg-checksum-present
          mongodb--op-msg-more-to-come))

(cl-defstruct mongodb--decoded-message
  request-id
  response-to
  opcode
  flags
  document)

;;;; OP_MSG framing

(defun mongodb--encode-op-msg-document-sequence (sequence)
  "Return a kind 1 OP_MSG document SEQUENCE section.
SEQUENCE is a cons cell whose car is the sequence identifier and whose cdr is
a vector or list of BSON documents."
  (let* ((identifier (car sequence))
         (documents (cdr sequence))
         (document-list (if (vectorp documents)
                            (append documents nil)
                          documents)))
    (unless (stringp identifier)
      (signal 'mongodb-error
              (list (format "MongoDB OP_MSG sequence identifier must be a string: %S"
                            identifier))))
    (unless (listp document-list)
      (signal 'mongodb-error
              (list (format "MongoDB OP_MSG sequence documents must be a list or vector: %S"
                            documents))))
    (let* ((document-bytes (apply #'concat
                                  (mapcar #'mongodb--encode-document
                                          document-list)))
           (identifier-bytes (mongodb--encode-cstring identifier))
           (section-size (+ 4
                            (length identifier-bytes)
                            (length document-bytes))))
      (concat (unibyte-string 1)
              (mongodb--pack-int32 section-size)
              identifier-bytes
              document-bytes))))

(defun mongodb--make-op-msg
    (request-id document &optional flag-bits checksum sequences response-to)
  "Return an OP_MSG request REQUEST-ID containing DOCUMENT.
FLAG-BITS defaults to zero.  CHECKSUM, when t, appends a computed CRC-32C
checksum; when an integer, appends that explicit uint32 checksum.  Either
CHECKSUM value sets the checksumPresent flag.  SEQUENCES is a list of kind 1
document sequence sections.  RESPONSE-TO defaults to zero."
  (let* ((body-document (mongodb--encode-document document))
         (sequence-bytes (apply #'concat
                                (mapcar #'mongodb--encode-op-msg-document-sequence
                                        sequences)))
         (flag-bits (if checksum
                        (logior (or flag-bits 0)
                                mongodb--op-msg-checksum-present)
                      (or flag-bits 0)))
         (body-without-checksum (concat (mongodb--pack-int32 flag-bits)
                                        (unibyte-string 0)
                                        body-document
                                        sequence-bytes))
         (length (+ 16
                    (length body-without-checksum)
                    (if checksum 4 0)))
         (message-without-checksum
          (concat (mongodb--pack-int32 length)
                  (mongodb--pack-int32 request-id)
                  (mongodb--pack-int32 (or response-to 0))
                  (mongodb--pack-int32 mongodb--op-msg)
                  body-without-checksum)))
    (if checksum
        (concat
         message-without-checksum
         (mongodb--pack-int32
          (cond
           ((eq checksum t)
            (mongodb--crc32c message-without-checksum))
           ((integerp checksum)
            checksum)
           (t
            (signal 'mongodb-error
                    (list (format "Invalid MongoDB OP_MSG checksum value: %S"
                                  checksum)))))))
      message-without-checksum)))


(defun mongodb--read-int32-from-string (data)
  "Read the first little-endian int32 from DATA."
  (mongodb--read-int32
   (make-mongodb--reader :data data :pos 0)))

(defun mongodb--validate-op-msg-flags (flag-bits)
  "Signal when OP_MSG FLAG-BITS contain unknown required flags."
  (let ((unknown-required
         (logand flag-bits
                 (logxor mongodb--op-msg-required-flag-mask
                         mongodb--op-msg-known-required-flag-mask))))
    (unless (zerop unknown-required)
      (signal 'mongodb-error
              (list (format "Unknown MongoDB OP_MSG required flag bits: %s"
                            unknown-required))))))

(defun mongodb--decode-op-msg-frame (message &optional allow-more-to-come)
  "Decode OP_MSG MESSAGE and return a `mongodb--decoded-message'.
Signal when a reply sets moreToCome unless ALLOW-MORE-TO-COME is non-nil."
  (let* ((reader (make-mongodb--reader :data message :pos 0))
         (length (mongodb--read-int32 reader))
         (request-id (mongodb--read-int32 reader))
         (response-to (mongodb--read-int32 reader))
         (opcode (mongodb--read-int32 reader))
         (flag-bits nil)
         (sections-end nil)
         document)
    (unless (= length (length message))
      (signal 'mongodb-error
              (list "MongoDB wire message length mismatch")))
    (unless (= opcode mongodb--op-msg)
      (signal 'mongodb-error
              (list (format "Unexpected MongoDB opcode: %s" opcode))))
    (setq flag-bits (mongodb--read-int32 reader))
    (mongodb--validate-op-msg-flags flag-bits)
    (when (and (not allow-more-to-come)
               (not (zerop (logand flag-bits
                                    mongodb--op-msg-more-to-come))))
      (signal 'mongodb-error
              (list "MongoDB OP_MSG moreToCome flag received without exhaustAllowed request")))
    (setq sections-end
          (if (not (zerop (logand flag-bits
                                   mongodb--op-msg-checksum-present)))
              (- length 4)
            length))
    (when (< sections-end (mongodb--reader-pos reader))
      (signal 'mongodb-error
              (list "MongoDB OP_MSG checksum flag set on a truncated message")))
    (while (< (mongodb--reader-pos reader) sections-end)
      (pcase (mongodb--read-byte reader)
        (0
         (setq document (mongodb--decode-document reader))
         (when (> (mongodb--reader-pos reader) sections-end)
           (signal 'mongodb-error
                   (list "MongoDB OP_MSG body section exceeds message length"))))
        (1
         (let* ((section-start (mongodb--reader-pos reader))
                (section-size (mongodb--read-int32 reader))
                (section-end (+ section-start section-size)))
           (when (or (< section-size 5)
                     (> section-end sections-end))
             (signal 'mongodb-error
                     (list "MongoDB OP_MSG document sequence section has invalid size")))
           (mongodb--read-cstring reader)
           (while (< (mongodb--reader-pos reader) section-end)
             (mongodb--decode-document reader))
           (setf (mongodb--reader-pos reader) section-end)))
        (kind
         (signal 'mongodb-error
                 (list (format "Unexpected MongoDB OP_MSG section kind: %s"
                               kind))))))
    (unless (= (mongodb--reader-pos reader) sections-end)
      (signal 'mongodb-error
              (list "MongoDB OP_MSG sections ended at an unexpected offset")))
    (when (not (zerop (logand flag-bits mongodb--op-msg-checksum-present)))
      (let ((expected (mongodb--read-uint-le reader 4))
            (actual (mongodb--crc32c (substring message 0 sections-end))))
        (unless (= expected actual)
          (signal 'mongodb-error
                  (list (format
                         "MongoDB OP_MSG checksum mismatch: expected %08x, got %08x"
                         expected actual))))))
    (make-mongodb--decoded-message
     :request-id request-id
     :response-to response-to
     :opcode opcode
     :flags flag-bits
     :document
     (or document
         (signal 'mongodb-error
                 (list "MongoDB OP_MSG reply contained no body document"))))))

(defun mongodb--decode-message-frame (message &optional allow-more-to-come)
  "Decode a MongoDB OP_MSG wire MESSAGE and return a decoded frame.

Arguments: MESSAGE, ALLOW-MORE-TO-COME."
  (mongodb--decode-op-msg-frame message allow-more-to-come))

(defun mongodb--validate-response-to (frame expected-response-to)
  "Signal unless FRAME's responseTo matches EXPECTED-RESPONSE-TO."
  (when (and expected-response-to
             (/= (mongodb--decoded-message-response-to frame)
                 expected-response-to))
    (signal 'mongodb-error
            (list (format "MongoDB responseTo mismatch: expected %s, got %s"
                          expected-response-to
                          (mongodb--decoded-message-response-to frame))))))


;;;; Connection parameters and SCRAM authentication

(cl-defstruct mongodb--credential
  username
  password
  source
  mechanism)

(cl-defstruct mongodb-conn
  process
  buffer
  host
  port
  database
  params
  credential
  (request-id 0)
  (max-bson-object-size (* 16 1024 1024))
  (max-message-size-bytes 48000000)
  (max-write-batch-size 100000)
  (closed nil)
  live
  (busy nil))

(defconst mongodb--scram-auth-mechanisms '("SCRAM-SHA-256" "SCRAM-SHA-1"))

(defvar mongodb--random-seeded nil
  "Non-nil after `random' has been seeded for MongoDB nonce generation.")

(defvar mongodb--object-id-random nil
  "Five process-random bytes used when generating MongoDB ObjectIds.")

(defvar mongodb--object-id-counter nil
  "Three-byte counter used when generating MongoDB ObjectIds.")

(defun mongodb--nonempty-string (value)
  "Return VALUE when it is a non-empty string, otherwise nil."
  (and (stringp value) (not (string-empty-p value)) value))

(defun mongodb--normalize-auth-mechanism (mechanism)
  "Return normalized MongoDB auth MECHANISM, or nil."
  (when (mongodb--nonempty-string mechanism)
    (upcase mechanism)))

(defun mongodb--url-decode (value)
  "Return URL-decoded VALUE."
  (and value (decode-coding-string (url-unhex-string value) 'utf-8 t)))

(defun mongodb--parse-query (query)
  "Return QUERY as a case-insensitive option alist."
  (let (pairs)
    (dolist (part (and query (split-string query "&" t)))
      (pcase-let* ((`(,key ,value) (split-string part "=")))
        (push (cons (downcase (mongodb--url-decode key))
                    (mongodb--url-decode (or value "")))
              pairs)))
    (nreverse pairs)))

(defun mongodb--query-option (options key)
  "Return option KEY from parsed query OPTIONS."
  (cdr (assoc (downcase key) options)))

(defun mongodb--truthy-string-p (value)
  "Return non-nil when VALUE is a truthy MongoDB URI boolean."
  (and value (not (null (member (downcase value) '("true" "1"))))))

(defun mongodb--falsey-string-p (value)
  "Return non-nil when VALUE is a falsey MongoDB URI boolean."
  (and value (not (null (member (downcase value) '("false" "0"))))))

(defun mongodb--parse-uri-boolean (value option)
  "Return URI boolean VALUE for OPTION, or nil when VALUE is absent."
  (cond
   ((null value) nil)
   ((mongodb--truthy-string-p value) t)
   ((mongodb--falsey-string-p value) nil)
   (t
    (signal 'mongodb-error
            (list (format "Invalid MongoDB URI boolean for %s: %S"
                          option value))))))

(defun mongodb--parse-host-port (hostspec)
  "Return (HOST . PORT) parsed from HOSTSPEC."
  (let* ((first (car (split-string hostspec "," t)))
         (host first)
         (port 27017))
    (when (string-match "\\`\\([^:]+\\):\\([0-9]+\\)\\'" first)
      (setq host (match-string 1 first))
      (setq port (string-to-number (match-string 2 first))))
    (cons host port)))

(defun mongodb--normalize-params (params)
  "Return normalized MongoDB connection PARAMS."
  (let* ((params (if (stringp params) (list :url params) params))
         (url (plist-get params :url))
         query hostspec path user password options endpoint database
         tls-option tls-option-present allow-invalid tls tls-verify)
    (when url
      (when (string-prefix-p "mongodb+srv://" url)
        (signal 'mongodb-error
                (list "mongodb+srv URLs are not supported by this lightweight client")))
      (unless (string-match (concat "\\`mongodb://"
                                    "\\(?:\\([^@/?]+\\)@\\)?"
                                    "\\([^/?]+\\)"
                                    "\\(?:/\\([^?]*\\)\\)?"
                                    "\\(?:\\?\\(.*\\)\\)?\\'")
                            url)
        (signal 'mongodb-error
                (list (format "Unsupported MongoDB URL: %s" url))))
      (let ((userinfo (match-string 1 url)))
        (setq hostspec (match-string 2 url))
        (setq path (match-string 3 url))
        (setq query (match-string 4 url))
        (when userinfo
          (pcase-let* ((`(,raw-user ,raw-pass)
                        (split-string userinfo ":")))
            (setq user (mongodb--url-decode raw-user))
            (setq password (mongodb--url-decode raw-pass))))))
    (setq options (mongodb--parse-query query))
    (setq tls-option-present (or (plist-member params :tls)
                                 (plist-member params :ssl)))
    (setq tls-option (if (plist-member params :tls)
                         (plist-get params :tls)
                       (plist-get params :ssl)))
    (setq tls (if tls-option-present
                  (and tls-option (not (eq tls-option :false)))
                (mongodb--parse-uri-boolean
                 (or (mongodb--query-option options "tls")
                     (mongodb--query-option options "ssl"))
                 "tls")))
    (setq allow-invalid
          (mongodb--query-option options "tlsAllowInvalidCertificates"))
    (when allow-invalid
      (mongodb--parse-uri-boolean allow-invalid
                                  "tlsAllowInvalidCertificates"))
    (setq tls-verify
          (cond
           ((plist-member params :tls-verify)
            (let ((value (plist-get params :tls-verify)))
              (and value (not (eq value :false)))))
           ((mongodb--truthy-string-p allow-invalid) nil)
           ((mongodb--falsey-string-p allow-invalid) t)
           (t mongodb-tls-verify-server)))
    (setq endpoint
          (mongodb--parse-host-port
           (or hostspec
               (plist-get params :host)
               "127.0.0.1")))
    (setq database
          (or (mongodb--nonempty-string (and path (mongodb--url-decode path)))
              (plist-get params :database)
              "test"))
    (list :host (car endpoint)
          :port (or (plist-get params :port) (cdr endpoint))
          :database database
          :username (or (plist-get params :username)
                        (plist-get params :user)
                        user)
          :password (or (plist-get params :password) password)
          :auth-source (or (plist-get params :auth-source)
                           (mongodb--query-option options "authSource")
                           database)
          :auth-mechanism (or (plist-get params :auth-mechanism)
                              (mongodb--query-option options "authMechanism"))
          :tls tls
          :tls-verify tls-verify)))

(defun mongodb--params-credential (params)
  "Return MongoDB credential parsed from normalized PARAMS."
  (when-let* ((username (plist-get params :username)))
    (make-mongodb--credential
     :username username
     :password (or (plist-get params :password) "")
     :source (or (plist-get params :auth-source) (plist-get params :database) "admin")
     :mechanism (mongodb--normalize-auth-mechanism
                 (plist-get params :auth-mechanism)))))

(defun mongodb--random-bytes (count)
  "Return COUNT random bytes."
  (unless mongodb--random-seeded
    (random t)
    (setq mongodb--random-seeded t))
  (let ((bytes ""))
    (while (< (length bytes) count)
      (setq bytes
            (concat bytes
                    (secure-hash
                     'sha256
                     (format "%S:%S:%S:%S"
                             (current-time) (random) (emacs-pid)
                             (garbage-collect))
                     nil nil t))))
    (substring bytes 0 count)))

(defun mongodb--uint24-value (bytes)
  "Return the unsigned 24-bit integer represented by BYTES."
  (logior (ash (aref bytes 0) 16)
          (ash (aref bytes 1) 8)
          (aref bytes 2)))

(defun mongodb--pack-uint24-be (value)
  "Return VALUE packed as unsigned big-endian uint24."
  (unibyte-string (logand (ash value -16) #xff)
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
         (bytes (concat (mongodb--pack-uint32-be seconds)
                        mongodb--object-id-random
                        (mongodb--pack-uint24-be counter))))
    (setq mongodb--object-id-counter
          (mod (1+ mongodb--object-id-counter) #x1000000))
    (mongodb-object-id (mongodb--bytes-to-hex bytes))))

(defun mongodb--codepoint-in-ranges-p (codepoint ranges)
  "Return non-nil when CODEPOINT is included in RANGES."
  (cl-some (lambda (range)
             (and (<= (car range) codepoint)
                  (<= codepoint (cdr range))))
           ranges))

(defconst mongodb--saslprep-map-to-nothing-ranges
  '((#x00AD . #x00AD) (#x034F . #x034F) (#x1806 . #x1806)
    (#x180B . #x180D) (#x200B . #x200D) (#x2060 . #x2060)
    (#xFE00 . #xFE0F) (#xFEFF . #xFEFF)))

(defconst mongodb--saslprep-space-ranges
  '((#x00A0 . #x00A0) (#x1680 . #x1680) (#x2000 . #x200A)
    (#x202F . #x202F) (#x205F . #x205F) (#x3000 . #x3000)))

(defconst mongodb--saslprep-prohibited-ranges
  '((#x0000 . #x001F) (#x007F . #x009F) (#x06DD . #x06DD)
    (#x070F . #x070F) (#x180E . #x180E) (#x200C . #x200D)
    (#x2028 . #x2029) (#x2060 . #x2063) (#x206A . #x206F)
    (#x2FF0 . #x2FFB) (#xD800 . #xDFFF) (#xE000 . #xF8FF)
    (#xFDD0 . #xFDEF) (#xFEFF . #xFEFF) (#xFFF9 . #xFFFD)
    (#x1D173 . #x1D17A) (#xE0001 . #xE0001) (#xE0020 . #xE007F)
    (#xF0000 . #xFFFFD) (#x100000 . #x10FFFD)))

(defun mongodb--saslprep-map-char (char)
  "Return SASLprep-mapped CHAR, or nil when CHAR maps to nothing."
  (cond
   ((mongodb--codepoint-in-ranges-p char mongodb--saslprep-map-to-nothing-ranges) nil)
   ((mongodb--codepoint-in-ranges-p char mongodb--saslprep-space-ranges) ?\s)
   (t char)))

(defun mongodb--saslprep-prohibited-p (char)
  "Return non-nil when CHAR is prohibited by SASLprep."
  (or (mongodb--codepoint-in-ranges-p char mongodb--saslprep-prohibited-ranges)
      (and (<= #xFDD0 char) (<= char #xFDEF))
      (let ((low (logand char #xFFFF)))
        (or (= low #xFFFE) (= low #xFFFF)))))

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
         has-randal has-lcat)
    (cl-loop for char across normalized
             do (when (mongodb--saslprep-prohibited-p char)
                  (signal 'mongodb-error
                          (list (format "MongoDB SCRAM password contains a prohibited SASLprep character: U+%04X" char))))
             do (when (mongodb--saslprep-randal-p char) (setq has-randal t))
             do (when (mongodb--saslprep-lcat-p char) (setq has-lcat t)))
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
   (secure-hash 'md5
                (mongodb--utf8-bytes
                 (format "%s:mongodb:%s" username secret)))))

(defun mongodb--scram-client-nonce ()
  "Return a printable SCRAM client nonce."
  (mongodb--base64-encode (mongodb--random-bytes 24)))

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
      (push (cons (match-string 1 part) (match-string 2 part)) attrs))
    (nreverse attrs)))

(defun mongodb--scram-payload-string (payload)
  "Return SCRAM PAYLOAD decoded as a UTF-8 string."
  (if (stringp payload)
      payload
    (decode-coding-string (mongodb--binary-value-data payload) 'utf-8 t)))

(defun mongodb--scram-start-data (credential mechanism)
  "Return SCRAM client-first data for CREDENTIAL and MECHANISM."
  (let* ((username (mongodb--credential-username credential))
         (client-nonce (mongodb--scram-client-nonce))
         (client-first-bare
          (format "n=%s,r=%s" (mongodb--scram-escape-name username) client-nonce))
         (client-first (concat "n,," client-first-bare)))
    (list :mechanism mechanism
          :source (mongodb--credential-source credential)
          :username username
          :client-nonce client-nonce
          :client-first-bare client-first-bare
          :client-first client-first)))

(defun mongodb--scram-start-command (start-data)
  "Return a MongoDB saslStart command from START-DATA."
  `(("saslStart" . 1)
    ("mechanism" . ,(plist-get start-data :mechanism))
    ("options" . (("skipEmptyExchange" . t)))
    ("payload" . ,(mongodb-binary
                    0
                    (mongodb--utf8-bytes
                     (plist-get start-data :client-first))))
    ("autoAuthorize" . 1)))

(defun mongodb--scram-client-final
    (mechanism username secret client-first-bare client-nonce server-first-message)
  "Return SCRAM final data for MECHANISM and SERVER-FIRST-MESSAGE.
USERNAME, SECRET, CLIENT-FIRST-BARE, and CLIENT-NONCE are client SCRAM
values."
  (let* ((attrs (mongodb--scram-parse-attrs server-first-message))
         (server-nonce (cdr (assoc "r" attrs)))
         (salt64 (cdr (assoc "s" attrs)))
         (iterations-text (cdr (assoc "i" attrs)))
         (iterations (and iterations-text (string-to-number iterations-text))))
    (unless (and server-nonce (string-prefix-p client-nonce server-nonce))
      (signal 'mongodb-error
              (list "MongoDB SCRAM server nonce does not extend client nonce")))
    (unless salt64
      (signal 'mongodb-error
              (list "MongoDB SCRAM server message is missing salt")))
    (unless (and iterations (>= iterations 4096))
      (signal 'mongodb-error
              (list "MongoDB SCRAM server message has invalid iteration count")))
    (let* ((salt (mongodb--base64-decode salt64))
           (client-final-without-proof (format "c=biws,r=%s" server-nonce))
           (auth-message
            (mongodb--utf8-bytes
             (mapconcat #'identity
                        (list client-first-bare server-first-message
                              client-final-without-proof)
                        ",")))
           (salted-password
            (pcase mechanism
              ("SCRAM-SHA-256"
               (mongodb--pbkdf2-hmac-sha256
                (mongodb--scram-password-bytes secret) salt iterations))
              ("SCRAM-SHA-1"
               (mongodb--pbkdf2-hmac-sha1
                (mongodb--scram-sha1-password-bytes username secret)
                salt iterations))))
           (client-key
            (if (equal mechanism "SCRAM-SHA-256")
                (mongodb--hmac-sha256 salted-password (mongodb--utf8-bytes "Client Key"))
              (mongodb--hmac-sha1 salted-password (mongodb--utf8-bytes "Client Key"))))
           (stored-key
            (if (equal mechanism "SCRAM-SHA-256")
                (mongodb--sha256 client-key)
              (mongodb--sha1 client-key)))
           (client-signature
            (if (equal mechanism "SCRAM-SHA-256")
                (mongodb--hmac-sha256 stored-key auth-message)
              (mongodb--hmac-sha1 stored-key auth-message)))
           (client-proof (mongodb--xor-bytes client-key client-signature))
           (server-key
            (if (equal mechanism "SCRAM-SHA-256")
                (mongodb--hmac-sha256 salted-password (mongodb--utf8-bytes "Server Key"))
              (mongodb--hmac-sha1 salted-password (mongodb--utf8-bytes "Server Key"))))
           (server-signature
            (if (equal mechanism "SCRAM-SHA-256")
                (mongodb--hmac-sha256 server-key auth-message)
              (mongodb--hmac-sha1 server-key auth-message))))
      (list :message
            (format "%s,p=%s" client-final-without-proof
                    (mongodb--base64-encode client-proof))
            :server-signature server-signature))))

(defun mongodb--choose-auth-mechanism (credential hello)
  "Return the auth mechanism to use for CREDENTIAL from HELLO."
  (let ((mechanism (mongodb--credential-mechanism credential))
        (supported (cdr (assoc "saslSupportedMechs" hello))))
    (cond
     (mechanism
      (unless (member mechanism mongodb--scram-auth-mechanisms)
        (signal 'mongodb-error
                (list (format "Native MongoDB authentication supports SCRAM-SHA-256 and SCRAM-SHA-1, not %s" mechanism))))
      mechanism)
     ((member "SCRAM-SHA-256" supported) "SCRAM-SHA-256")
     ((member "SCRAM-SHA-1" supported) "SCRAM-SHA-1")
     (t "SCRAM-SHA-256"))))

(defun mongodb--authenticate-scram (conn credential mechanism)
  "Authenticate CONN with CREDENTIAL using SCRAM MECHANISM."
  (let* ((start-data (mongodb--scram-start-data credential mechanism))
         (username (mongodb--credential-username credential))
         (secret (mongodb--credential-password credential))
         (source (mongodb--credential-source credential))
         (client-nonce (plist-get start-data :client-nonce))
         (client-first-bare (plist-get start-data :client-first-bare))
         (start-response
          (mongodb-command conn source (mongodb--scram-start-command start-data)))
         (conversation-id (cdr (assoc "conversationId" start-response)))
         (server-first
          (mongodb--scram-payload-string
           (cdr (assoc "payload" start-response)))))
    (when (eq (cdr (assoc "done" start-response)) t)
      (signal 'mongodb-error
              (list "MongoDB SCRAM conversation ended before client proof")))
    (let* ((final-data
            (mongodb--scram-client-final
             mechanism username secret client-first-bare client-nonce server-first))
           (continue-response
            (mongodb-command
             conn source
             `(("saslContinue" . 1)
               ("conversationId" . ,conversation-id)
               ("payload" . ,(mongodb-binary
                               0
                               (mongodb--utf8-bytes
                                (plist-get final-data :message)))))))
           server-verified)
      (while continue-response
        (when-let* ((payload (cdr (assoc "payload" continue-response))))
          (let* ((server-final (mongodb--scram-payload-string payload))
                 (attrs (and (not (string-empty-p server-final))
                             (mongodb--scram-parse-attrs server-final))))
            (when-let* ((error-text (cdr (assoc "e" attrs))))
              (signal 'mongodb-error
                      (list (format "MongoDB SCRAM authentication failed: %s" error-text))))
            (when-let* ((verifier (cdr (assoc "v" attrs))))
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
                (list "MongoDB SCRAM server signature was not returned"))))))

(defun mongodb--authenticate (conn credential hello)
  "Authenticate CONN with CREDENTIAL using data from HELLO."
  (mongodb--authenticate-scram
   conn credential (mongodb--choose-auth-mechanism credential hello)))

;;;; Wire transport and commands

(defconst mongodb--client-min-wire-version 6)
(defconst mongodb--client-max-wire-version 25)

(defun mongodb--next-request-id (conn)
  "Return the next request id for CONN."
  (let ((next (1+ (mongodb-conn-request-id conn))))
    (setf (mongodb-conn-request-id conn) next)
    next))

(defun mongodb--ensure-command-ready (conn)
  "Ensure CONN can start a command."
  (unless (mongodb-live-p conn)
    (signal 'mongodb-error (list "MongoDB connection closed")))
  (when (mongodb-conn-busy conn)
    (signal 'mongodb-error
            (list "MongoDB connection is already running a command"))))

(defun mongodb--wait-for-bytes (conn count deadline)
  "Wait until CONN has COUNT bytes before absolute DEADLINE."
  (unless (and (integerp count) (>= count 0))
    (signal 'mongodb-error
            (list (format "Invalid MongoDB wire byte count: %S" count))))
  (let ((proc (mongodb-conn-process conn))
        (buffer (mongodb-conn-buffer conn)))
    (with-current-buffer buffer
      (while (< (buffer-size) count)
        (unless (process-live-p proc)
          (signal 'mongodb-error (list "MongoDB connection closed")))
        (let ((remaining (- deadline (float-time))))
          (when (<= remaining 0)
            (signal 'mongodb-error (list "MongoDB response timed out")))
          (accept-process-output proc (min remaining 0.05))))
      (let ((data (buffer-substring-no-properties (point-min) (+ (point-min) count))))
        (delete-region (point-min) (+ (point-min) count))
        (mongodb--byte-string data)))))

(defun mongodb--recv-message-frame (conn timeout expected-response-to)
  "Receive one MongoDB message frame from CONN within TIMEOUT.
EXPECTED-RESPONSE-TO, when non-nil, must match the reply header."
  (let* ((deadline (+ (float-time) (or timeout mongodb-timeout-seconds)))
         (header (mongodb--wait-for-bytes conn 4 deadline))
         (length (mongodb--read-int32-from-string header))
         (maximum (mongodb-conn-max-message-size-bytes conn)))
    (unless (and (integerp maximum)
                 (>= length 16)
                 (<= length maximum))
      (signal 'mongodb-error
              (list (format "Invalid MongoDB wire message length: %s" length))))
    (let* ((body (mongodb--wait-for-bytes conn (- length 4) deadline))
           (frame (mongodb--decode-message-frame (concat header body))))
      (mongodb--validate-response-to frame expected-response-to)
      frame)))

(defun mongodb--send-document (conn document &optional timeout sequences)
  "Send command DOCUMENT through CONN and return the reply document."
  (mongodb--ensure-command-ready conn)
  (let* ((request-id (mongodb--next-request-id conn))
         (message (mongodb--make-op-msg request-id document nil nil sequences)))
    (when (> (length message) (mongodb-conn-max-message-size-bytes conn))
      (signal 'mongodb-error
              (list "MongoDB command exceeds maxMessageSizeBytes")))
    (setf (mongodb-conn-busy conn) t)
    (unwind-protect
        (condition-case err
            (progn
              (process-send-string (mongodb-conn-process conn) message)
              (mongodb--decoded-message-document
               (mongodb--recv-message-frame conn timeout request-id)))
          (mongodb-error
           (mongodb-disconnect conn)
           (signal (car err) (cdr err)))
          (quit
           (mongodb-disconnect conn)
           (signal (car err) (cdr err)))
          (error
           (mongodb-disconnect conn)
           (signal 'mongodb-error (list (error-message-string err)))))
      (setf (mongodb-conn-busy conn) nil))))

(defun mongodb--os-type ()
  "Return a compact MongoDB client metadata OS type."
  (pcase system-type
    ('darwin "Darwin")
    ('gnu/linux "Linux")
    ('windows-nt "Windows")
    (_ (symbol-name system-type))))

(defun mongodb--client-metadata ()
  "Return MongoDB client metadata document."
  `(("driver" . (("name" . "mongodb.el")
                 ("version" . ,mongodb-version)))
    ("os" . (("type" . ,(mongodb--os-type))))
    ("platform" . ,(format "Emacs %s" emacs-version))))

(defun mongodb--hello-command (credential)
  "Return the initial MongoDB hello command for CREDENTIAL."
  `(("hello" . 1)
    ("helloOk" . t)
    ("client" . ,(mongodb--client-metadata))
    ,@(when credential
        `(("saslSupportedMechs" . ,(format "%s.%s"
                                    (mongodb--credential-source credential)
                                    (mongodb--credential-username credential)))))
    ("$db" . "admin")))

(defun mongodb--hello-limit (hello field minimum)
  "Return positive integer FIELD from HELLO, bounded by MINIMUM."
  (when-let* ((entry (assoc field hello)))
    (let ((value (cdr entry)))
      (unless (and (integerp value) (>= value minimum))
        (signal 'mongodb-error
                (list (format "Invalid MongoDB hello %s: %S" field value))))
      value)))

(defun mongodb--apply-hello-limits (conn hello)
  "Validate and apply server HELLO wire limits to CONN."
  (when-let* ((value (mongodb--hello-limit hello "maxBsonObjectSize" 5)))
    (setf (mongodb-conn-max-bson-object-size conn) value))
  (when-let* ((value (mongodb--hello-limit hello "maxMessageSizeBytes" 16)))
    (setf (mongodb-conn-max-message-size-bytes conn) value))
  (when-let* ((value (mongodb--hello-limit hello "maxWriteBatchSize" 1)))
    (setf (mongodb-conn-max-write-batch-size conn) value)))

(defun mongodb--response-ok-p (response)
  "Return non-nil when MongoDB RESPONSE reports ok."
  (let ((ok (cdr (assoc "ok" response))))
    (or (eq ok t)
        (and (numberp ok) (= ok 1)))))

(defun mongodb-response-ok-p (response)
  "Return non-nil when MongoDB RESPONSE reports ok."
  (mongodb--response-ok-p response))

(defun mongodb--response-message (response)
  "Return an error message from MongoDB RESPONSE."
  (or (cdr (assoc "errmsg" response))
      (cdr (assoc "$err" response))
      (format "MongoDB command failed: %S" response)))

(defun mongodb--response-error-labels (response)
  "Return error labels from MongoDB RESPONSE."
  (let ((labels (cdr (assoc "errorLabels" response))))
    (cond
     ((vectorp labels) (append labels nil))
     ((listp labels) labels)
     (t nil))))

(defun mongodb--signal-command-error (response)
  "Signal a MongoDB command error from RESPONSE."
  (signal 'mongodb-error
          (list (mongodb--response-message response)
                :error-labels
                (mongodb--response-error-labels response))))

(defun mongodb-error-labels (condition)
  "Return MongoDB error labels from CONDITION."
  (let ((data (cdr condition)))
    (plist-get (if (keywordp (car data)) data (cdr data))
               :error-labels)))

(defun mongodb-error-has-label-p (condition label)
  "Return non-nil when CONDITION includes MongoDB error LABEL."
  (member label (mongodb-error-labels condition)))

(defun mongodb--option-pairs (options)
  "Return MongoDB command option pairs from OPTIONS."
  (cond
   ((null options) nil)
   ((mongodb-document-p options) (mongodb-document-pairs options))
   ((listp options) options)
   (t (signal 'mongodb-error
              (list (format "MongoDB command options must be a document: %S" options))))))

(defun mongodb--remove-option-pairs (keys pairs)
  "Return PAIRS without any entry whose car is in KEYS."
  (cl-remove-if (lambda (pair) (member (car pair) keys)) pairs))

(defun mongodb--command-with-db (database command)
  "Return COMMAND with DATABASE as its $db field."
  (append (mongodb--remove-option-pairs '("$db") (mongodb--document-pairs command))
          `(("$db" . ,database))))

(defun mongodb-command (conn database command &optional timeout sequences)
  "Run MongoDB COMMAND on DATABASE through CONN."
  (let ((response (mongodb--send-document
                   conn
                   (mongodb--command-with-db database command)
                   timeout sequences)))
    (unless (mongodb--response-ok-p response)
      (mongodb--signal-command-error response))
    response))

(defun mongodb--check-write-response (response)
  "Signal if a write RESPONSE contains write errors."
  (when (or (cdr (assoc "writeErrors" response))
            (cdr (assoc "writeConcernError" response)))
    (mongodb--signal-command-error response))
  response)

(defun mongodb--tls-available-p ()
  "Return non-nil when GnuTLS is available."
  (and (fboundp 'gnutls-available-p) (gnutls-available-p)))

(defun mongodb--upgrade-to-tls (proc host timeout verify-server)
  "Upgrade PROC to TLS for HOST within TIMEOUT.
When VERIFY-SERVER is non-nil, reject certificate and hostname failures."
  (unless (mongodb--tls-available-p)
    (signal 'mongodb-error (list "MongoDB TLS requires GnuTLS support")))
  (gnutls-negotiate
   :process proc
   :type 'gnutls-x509pki
   :hostname host
   :priority-string "NORMAL"
   :verify-error verify-server
   :verify-hostname-error verify-server)
  (let ((deadline (+ (float-time) timeout)))
    (while (and (eq (process-status proc) 'open)
                (process-contact proc :gnutls-boot-parameters))
      (when (> (float-time) deadline)
        (signal 'mongodb-error (list "MongoDB TLS negotiation timed out")))
      (accept-process-output proc 0.05)))
  (unless (process-live-p proc)
    (signal 'mongodb-error (list "MongoDB TLS connection closed"))))

(defun mongodb--wait-for-connect (proc host port timeout)
  "Wait for PROC to connect to HOST and PORT within TIMEOUT."
  (let ((deadline (+ (float-time) timeout)))
    (while (eq (process-status proc) 'connect)
      (let ((remaining (- deadline (float-time))))
        (when (<= remaining 0)
          (signal 'mongodb-error
                  (list (format "Timed out connecting to MongoDB at %s:%s"
                                host port))))
        (accept-process-output proc (min remaining 0.05))))
    (unless (memq (process-status proc) '(open run))
      (signal 'mongodb-error
              (list (format "Failed to connect to MongoDB at %s:%s"
                            host port))))))

(defun mongodb-connect (params)
  "Connect to MongoDB using PARAMS and return a connection object."
  (let* ((params (mongodb--normalize-params params))
         (host (plist-get params :host))
         (port (plist-get params :port))
         (database (plist-get params :database))
         (credential (mongodb--params-credential params))
         (buffer (generate-new-buffer (format " *mongodb %s:%s*" host port)))
         (proc nil)
         conn)
    (with-current-buffer buffer
      (set-buffer-multibyte nil))
    (condition-case err
        (progn
          (setq proc
                (make-network-process
                 :name (format "mongodb-%s:%s" host port)
                 :buffer buffer
                 :host host
                 :service port
                 :nowait t
                 :coding 'binary
                 :noquery t))
          (mongodb--wait-for-connect proc host port
                                     mongodb-connect-timeout-seconds)
          (when (plist-get params :tls)
            (mongodb--upgrade-to-tls
             proc host mongodb-connect-timeout-seconds
             (plist-get params :tls-verify)))
          (setq conn
                (make-mongodb-conn
                 :process proc
                 :buffer buffer
                 :host host
                 :port port
                 :database database
                 :params params
                 :credential credential
                 :closed nil
                 :live t))
          (let ((hello (mongodb--send-document
                        conn (mongodb--hello-command credential)
                        mongodb-connect-timeout-seconds)))
            (unless (mongodb--response-ok-p hello)
              (mongodb--signal-command-error hello))
            (mongodb--apply-hello-limits conn hello)
            (let ((min-wire (or (cdr (assoc "minWireVersion" hello)) 0))
                  (max-wire (or (cdr (assoc "maxWireVersion" hello)) 0)))
              (when (or (> min-wire mongodb--client-max-wire-version)
                        (< max-wire mongodb--client-min-wire-version))
                (signal 'mongodb-error
                        (list (format "Unsupported MongoDB wire version range: server %s-%s"
                                      min-wire max-wire)))))
            (when credential
              (mongodb--authenticate conn credential hello)))
          conn)
      (mongodb-error
       (when (process-live-p proc) (delete-process proc))
       (when (buffer-live-p buffer) (kill-buffer buffer))
       (signal (car err) (cdr err)))
      (error
       (when (process-live-p proc) (delete-process proc))
       (when (buffer-live-p buffer) (kill-buffer buffer))
       (signal 'mongodb-error (list (error-message-string err)))))))

(defun mongodb-disconnect (conn)
  "Disconnect MongoDB CONN."
  (when (mongodb-conn-p conn)
    (setf (mongodb-conn-live conn) nil)
    (setf (mongodb-conn-closed conn) t)
    (let ((process (mongodb-conn-process conn))
          (buffer (mongodb-conn-buffer conn)))
      (when (process-live-p process)
        (delete-process process))
      (when (buffer-live-p buffer)
        (kill-buffer buffer))))
  nil)

(defun mongodb-live-p (conn)
  "Return non-nil when CONN is live."
  (and (mongodb-conn-p conn)
       (not (mongodb-conn-closed conn))
       (mongodb-conn-live conn)
       (let ((process (mongodb-conn-process conn)))
         (and process (process-live-p process)))))

(defun mongodb-hello (conn &optional timeout)
  "Run MongoDB hello through CONN within optional TIMEOUT."
  (mongodb-command conn "admin" '(("hello" . 1)) timeout))

(defun mongodb--cursor-batch (cursor key)
  "Return cursor KEY batch from CURSOR."
  (or (cdr (assoc key cursor)) nil))

(defun mongodb--cursor-id (cursor)
  "Return numeric cursor id from CURSOR."
  (or (cdr (assoc "id" cursor)) 0))

(defun mongodb--cursor-namespace-collection (cursor database fallback)
  "Return collection name for CURSOR in DATABASE, falling back to FALLBACK."
  (let ((ns (cdr (assoc "ns" cursor))))
    (if (and (stringp ns) (string-prefix-p (concat database ".") ns))
        (substring ns (1+ (length database)))
      fallback)))

(defun mongodb-kill-cursors (conn database collection cursor-ids)
  "Kill CURSOR-IDS for COLLECTION in DATABASE on CONN."
  (mongodb-command conn database
                   `(("killCursors" . ,collection)
                     ("cursors" . ,(vconcat cursor-ids)))))

(defun mongodb--cursor-results
    (conn database collection response first-batch-key &optional get-more-options)
  "Return all cursor results from RESPONSE using CONN.
DATABASE, COLLECTION, FIRST-BATCH-KEY, and GET-MORE-OPTIONS describe the cursor
and subsequent getMore commands."
  (let* ((cursor (cdr (assoc "cursor" response)))
         (batches (list (mongodb--cursor-batch cursor first-batch-key)))
         (cursor-id (mongodb--cursor-id cursor))
         (collection (mongodb--cursor-namespace-collection cursor database collection)))
    (while (and (integerp cursor-id) (/= cursor-id 0))
      (let* ((reply
              (mongodb-command
               conn database
               `(("getMore" . ,cursor-id)
                 ("collection" . ,collection)
                 ,@(mongodb--option-pairs get-more-options))))
             (next (cdr (assoc "cursor" reply))))
        (push (mongodb--cursor-batch next "nextBatch") batches)
        (setq cursor-id (mongodb--cursor-id next))))
    (apply #'append (nreverse batches))))

;;;; Public command helpers

(defun mongodb-list-databases (conn)
  "Return database names visible to CONN."
  (let ((response (mongodb-command conn "admin" '(("listDatabases" . 1)))))
    (mapcar (lambda (db) (cdr (assoc "name" db)))
            (cdr (assoc "databases" response)))))

(defun mongodb-list-collection-docs (conn database &optional filter options)
  "Return collection metadata documents for DATABASE on CONN."
  (let ((response
         (mongodb-command
          conn database
          `(("listCollections" . 1)
            ("cursor" . ,(mongodb-document nil))
            ,@(when filter `(("filter" . ,filter)))
            ,@(mongodb--option-pairs options)))))
    (mongodb--cursor-results conn database "$cmd.listCollections" response "firstBatch")))

(defun mongodb-list-collections (conn database)
  "Return collection names for DATABASE on CONN."
  (mapcar (lambda (doc) (cdr (assoc "name" doc)))
          (mongodb-list-collection-docs conn database)))

(defun mongodb-create-collection (conn database collection &optional options)
  "Create COLLECTION in DATABASE on CONN."
  (mongodb-command conn database
                   `(("create" . ,collection)
                     ,@(mongodb--option-pairs options))))

(defun mongodb-list-indexes (conn database collection)
  "Return index documents for COLLECTION in DATABASE on CONN."
  (let ((response
         (mongodb-command conn database
                          `(("listIndexes" . ,collection)
                            ("cursor" . ,(mongodb-document nil))))))
    (mongodb--cursor-results conn database collection response "firstBatch")))

(defun mongodb-find-command
    (collection &optional filter projection limit skip sort options)
  "Return a MongoDB find command document for COLLECTION.
FILTER, PROJECTION, LIMIT, SKIP, SORT, and OPTIONS map to find command fields."
  (let* ((option-pairs (mongodb--option-pairs options))
         (batch-size (or (cdr (assoc "batchSize" option-pairs)) 1000))
         (extra (mongodb--remove-option-pairs '("batchSize" "maxAwaitTimeMS")
                                             option-pairs)))
    `(("find" . ,collection)
      ("filter" . ,(or filter (mongodb-document nil)))
      ("batchSize" . ,batch-size)
      ,@(when projection `(("projection" . ,projection)))
      ,@(when limit `(("limit" . ,limit)))
      ,@(when skip `(("skip" . ,skip)))
      ,@(when sort `(("sort" . ,sort)))
      ,@extra)))

(defun mongodb-find
    (conn database collection &optional filter projection limit skip sort options)
  "Return documents from COLLECTION in DATABASE on CONN."
  (let* ((option-pairs (mongodb--option-pairs options))
         (response
          (mongodb-command conn database
                           (mongodb-find-command collection filter projection
                                                 limit skip sort option-pairs))))
    (mongodb--cursor-results
     conn database collection response "firstBatch"
     (let ((max-await (cdr (assoc "maxAwaitTimeMS" option-pairs))))
       (when max-await `(("maxTimeMS" . ,max-await)))))))

(defun mongodb-count-documents (conn database collection &optional filter options)
  "Return count for COLLECTION in DATABASE on CONN."
  (let ((response
         (mongodb-command conn database
                          `(("count" . ,collection)
                            ,@(when filter `(("query" . ,filter)))
                            ,@(mongodb--option-pairs options)))))
    (cdr (assoc "n" response))))

(defun mongodb-distinct (conn database collection field &optional filter options)
  "Return distinct FIELD values for COLLECTION in DATABASE on CONN."
  (let ((response
         (mongodb-command conn database
                          `(("distinct" . ,collection)
                            ("key" . ,field)
                            ,@(when filter `(("query" . ,filter)))
                            ,@(mongodb--option-pairs options)))))
    (cdr (assoc "values" response))))

(defun mongodb--cursor-option (options)
  "Return aggregate cursor option document from OPTIONS."
  (let* ((pairs (mongodb--option-pairs options))
         (cursor (cdr (assoc "cursor" pairs)))
         (batch-size (cdr (assoc "batchSize" pairs))))
    (or cursor
        (and batch-size (mongodb-document `(("batchSize" . ,batch-size))))
        (mongodb-document nil))))

(defun mongodb-aggregate-command (collection pipeline &optional options)
  "Return a MongoDB aggregate command document for COLLECTION and PIPELINE.
OPTIONS are appended to the aggregate command after cursor normalization."
  (let* ((pairs (mongodb--option-pairs options))
         (extra (mongodb--remove-option-pairs '("cursor" "batchSize") pairs)))
    `(("aggregate" . ,collection)
      ("pipeline" . ,(if (vectorp pipeline) pipeline (vconcat pipeline)))
      ("cursor" . ,(mongodb--cursor-option options))
      ,@extra)))

(defun mongodb-aggregate (conn database collection pipeline &optional options)
  "Return aggregation results for COLLECTION in DATABASE on CONN."
  (let ((response
         (mongodb-command conn database
                          (mongodb-aggregate-command collection pipeline options))))
    (mongodb--cursor-results conn database collection response "firstBatch")))

(defun mongodb-aggregate-database (conn database pipeline &optional options)
  "Return database-level aggregation results for DATABASE on CONN."
  (let ((response
         (mongodb-command conn database
                          (mongodb-aggregate-command 1 pipeline options))))
    (mongodb--cursor-results conn database "$cmd.aggregate" response "firstBatch")))

(defun mongodb--explain-verbosity (verbosity)
  "Return MongoDB explain VERBOSITY."
  (cond
   ((or (null verbosity) (eq verbosity :false)) nil)
   ((eq verbosity t) "queryPlanner")
   (t verbosity)))

(defun mongodb-explain (conn database command &optional verbosity)
  "Explain MongoDB COMMAND on DATABASE over CONN."
  (mongodb-command conn database
                   `(("explain" . ,(mongodb-document command))
                     ,@(when-let* ((v (mongodb--explain-verbosity verbosity)))
                         `(("verbosity" . ,v))))))

(defun mongodb--document-with-generated-id (document)
  "Return DOCUMENT with generated _id when it has none."
  (let ((pairs (copy-sequence (mongodb--document-pairs document))))
    (if (assoc "_id" pairs)
        pairs
      (cons (cons "_id" (mongodb-new-object-id)) pairs))))

(defun mongodb-insert (conn database collection documents &optional ordered)
  "Insert DOCUMENTS into COLLECTION in DATABASE on CONN."
  (let* ((docs (cond
                ((vectorp documents) (append documents nil))
                ((or (mongodb-document-p documents)
                     (hash-table-p documents)
                     (and (consp documents)
                          (consp (car documents))
                          (stringp (caar documents))))
                 (list documents))
                ((listp documents) documents)
                (t (list documents))))
         (docs (mapcar #'mongodb--document-with-generated-id docs))
         (response
          (mongodb-command conn database
                           `(("insert" . ,collection)
                             ("documents" . ,(vconcat docs))
                             ("ordered" . ,(if (eq ordered :false) :false t))))))
    (mongodb--check-write-response response)))

(defun mongodb-delete (conn database collection filter &optional multi)
  "Delete documents from COLLECTION in DATABASE on CONN."
  (mongodb--check-write-response
   (mongodb-command conn database
                    `(("delete" . ,collection)
                      ("deletes" . ,(vector
                                      `(("q" . ,(or filter (mongodb-document nil)))
                                        ("limit" . ,(if multi 0 1)))))))))

(defun mongodb-update (conn database collection filter update &optional multi options)
  "Update documents in COLLECTION in DATABASE on CONN."
  (let* ((pairs (mongodb--option-pairs options))
         (upsert (cdr (assoc "upsert" pairs)))
         (extra (mongodb--remove-option-pairs '("upsert" "multi") pairs)))
    (mongodb--check-write-response
     (mongodb-command conn database
                      `(("update" . ,collection)
                        ("updates" . ,(vector
                                        (append
                                         `(("q" . ,(or filter (mongodb-document nil)))
                                           ("u" . ,update)
                                           ("multi" . ,(if multi t :false)))
                                         (when upsert `(("upsert" . ,upsert)))
                                         extra))))))))

(defun mongodb--index-name (keys)
  "Return a MongoDB index name for key document KEYS."
  (mapconcat (lambda (pair) (format "%s_%s" (car pair) (cdr pair)))
             (mongodb--document-pairs keys) "_"))

(defun mongodb-create-index (conn database collection keys &optional options)
  "Create one index with KEYS on COLLECTION in DATABASE on CONN."
  (let* ((pairs (mongodb--option-pairs options))
         (name (or (cdr (assoc "name" pairs)) (mongodb--index-name keys)))
         (extra (mongodb--remove-option-pairs '("key" "name") pairs)))
    (mongodb-command conn database
                     `(("createIndexes" . ,collection)
                       ("indexes" . ,(vector
                                       (append `(("key" . ,keys)
                                                 ("name" . ,name))
                                               extra)))))))

(defun mongodb-drop-index (conn database collection index)
  "Drop INDEX from COLLECTION in DATABASE on CONN."
  (mongodb-command conn database
                   `(("dropIndexes" . ,collection)
                     ("index" . ,index))))

(defun mongodb-drop-collection (conn database collection)
  "Drop COLLECTION in DATABASE on CONN."
  (mongodb-command conn database `(("drop" . ,collection))))

(defun mongodb-drop-database (conn database)
  "Drop DATABASE on CONN."
  (mongodb-command conn database '(("dropDatabase" . 1))))

(provide 'mongodb)

;;; mongodb.el ends here
