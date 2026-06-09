;;; mongodb-bson.el --- BSON codecs and byte primitives -*- lexical-binding: t; -*-

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

;; BSON value wrappers, BSON encode/decode, byte primitives, checksums, and
;; cryptographic byte helpers used by the MongoDB wire protocol client.

;;; Code:

(require 'cl-lib)
(require 'gnutls)
(require 'subr-x)

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
  (apply #'unibyte-string
         (cl-loop for shift from 0 below (* 8 bytes) by 8
                  collect (logand (ash value (- shift)) #xff))))

(defun mongodb--pack-int32 (value)
  "Return VALUE packed as little-endian int32."
  (mongodb--pack-uint-le value 4))

(defun mongodb--pack-int64 (value)
  "Return VALUE packed as little-endian int64."
  (mongodb--pack-uint-le value 8))

(defun mongodb--pack-uint16-le (value)
  "Return VALUE packed as little-endian uint16."
  (mongodb--pack-uint-le value 2))

(defun mongodb--pack-uint16-be (value)
  "Return VALUE packed as big-endian uint16."
  (unibyte-string (logand (ash value -8) #xff)
                  (logand value #xff)))

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
  (cl-loop for shift from 0 below (* 8 bytes) by 8
           sum (ash (mongodb--read-byte reader) shift)))

(defun mongodb--signed (value bits)
  "Return unsigned VALUE interpreted as a signed BITS-bit integer.

Arguments: VALUE, BITS."
  (let ((sign (expt 2 (1- bits)))
        (modulus (expt 2 bits)))
    (if (>= value sign)
        (- value modulus)
      value)))

(defun mongodb--read-int32 (reader)
  "Read a little-endian int32 from READER."
  (mongodb--signed
   (mongodb--read-uint-le reader 4)
   32))

(defun mongodb--read-int64 (reader)
  "Read a little-endian int64 from READER."
  (mongodb--signed
   (mongodb--read-uint-le reader 8)
   64))

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

(defun mongodb--adler32 (data)
  "Return the Adler-32 checksum for byte string DATA."
  (setq data (mongodb--byte-string data))
  (let ((a 1)
        (b 0))
    (dotimes (i (length data))
      (setq a (mod (+ a (aref data i)) 65521))
      (setq b (mod (+ b a) 65521)))
    (logior (ash b 16) a)))

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


(provide 'mongodb-bson)

;;; mongodb-bson.el ends here
