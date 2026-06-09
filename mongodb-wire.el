;;; mongodb-wire.el --- Wire message framing -*- lexical-binding: t; -*-

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

;; MongoDB OP_MSG, OP_COMPRESSED, legacy OP_REPLY framing, and wire
;; compression helpers.  Connection-state send/receive glue stays in mongodb.el.

;;; Code:

(require 'cl-lib)
(require 'mongodb-bson)
(require 'subr-x)

(defconst mongodb--op-msg 2013)

(defconst mongodb--op-compressed 2012)

(defconst mongodb--op-query 2004)

(defconst mongodb--op-reply 1)

(defconst mongodb--compressor-noop 0)

(defconst mongodb--compressor-snappy 1)

(defconst mongodb--compressor-zlib 2)

(defconst mongodb--compressor-zstd 3)

(defcustom mongodb-zstd-program "zstd"
  "Executable used for MongoDB zstd wire compression.
Set this to nil to disable zstd support.  zstd is optional and is only used
when the connection explicitly requests or receives zstd OP_COMPRESSED frames."
  :type '(choice (const :tag "Disable zstd" nil) string)
  :group 'mongodb)

(defconst mongodb--uncompressed-command-names
  '("hello" "isMaster" "ismaster" "saslStart" "saslContinue"
    "getnonce" "authenticate" "createUser" "updateUser"
    "copydbSaslStart" "copydbgetnonce" "copydb")
  "MongoDB commands that must not be wrapped in OP_COMPRESSED.")

(defconst mongodb--op-msg-checksum-present #x1)

(defconst mongodb--op-msg-more-to-come #x2)

(defconst mongodb--op-msg-exhaust-allowed #x10000)

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

(defun mongodb--make-op-query (request-id database document)
  "Return a legacy OP_QUERY command for initial handshake DOCUMENT.

Arguments: REQUEST-ID, DATABASE, DOCUMENT."
  (let* ((body (concat (mongodb--pack-int32 0)
                       (mongodb--encode-cstring (format "%s.$cmd" database))
                       (mongodb--pack-int32 0)
                       (mongodb--pack-int32 -1)
                       (mongodb--encode-document document)))
         (length (+ 16 (length body))))
    (concat (mongodb--pack-int32 length)
            (mongodb--pack-int32 request-id)
            (mongodb--pack-int32 0)
            (mongodb--pack-int32 mongodb--op-query)
            body)))

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

(defun mongodb--compressor-id (compressor)
  "Return the MongoDB wire compressor id for COMPRESSOR."
  (pcase compressor
    ("noop" mongodb--compressor-noop)
    ("snappy" mongodb--compressor-snappy)
    ("zlib" mongodb--compressor-zlib)
    ("zstd" mongodb--compressor-zstd)
    (_
     (signal 'mongodb-error
             (list (format "Unsupported negotiated MongoDB compressor: %s"
                           compressor))))))

(defun mongodb--compress-message-body (compressor data)
  "Return DATA compressed using negotiated COMPRESSOR."
  (pcase compressor
    ("noop" (mongodb--byte-string data))
    ("snappy" (mongodb--snappy-compress data))
    ("zlib" (mongodb--zlib-compress data))
    ("zstd" (mongodb--zstd-compress data))
    (_
     (signal 'mongodb-error
             (list (format "Unsupported negotiated MongoDB compressor: %s"
                           compressor))))))

(defun mongodb--make-op-compressed (message compressor)
  "Return MESSAGE wrapped as OP_COMPRESSED using COMPRESSOR."
  (setq message (mongodb--byte-string message))
  (let* ((reader (make-mongodb--reader :data message :pos 0))
         (message-length (mongodb--read-int32 reader))
         (request-id (mongodb--read-int32 reader))
         (response-to (mongodb--read-int32 reader))
         (opcode (mongodb--read-int32 reader)))
    (unless (= message-length (length message))
      (signal 'mongodb-error
              (list "MongoDB wire message length mismatch")))
    (when (= opcode mongodb--op-compressed)
      (signal 'mongodb-error
              (list "MongoDB wire message is already compressed")))
    (let* ((body (substring message 16 message-length))
           (compressed-body (mongodb--compress-message-body compressor body))
           (length (+ 16 4 4 1 (length compressed-body))))
      (concat (mongodb--pack-int32 length)
              (mongodb--pack-int32 request-id)
              (mongodb--pack-int32 response-to)
              (mongodb--pack-int32 mongodb--op-compressed)
              (mongodb--pack-int32 opcode)
              (mongodb--pack-int32 (length body))
              (unibyte-string (mongodb--compressor-id compressor))
              compressed-body))))

(defun mongodb--command-compressible-p (document)
  "Return non-nil when DOCUMENT may be sent as OP_COMPRESSED."
  (let* ((pairs (mongodb--document-pairs document))
         (command-name (caar pairs)))
    (not (member command-name mongodb--uncompressed-command-names))))


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

(defun mongodb--decode-op-msg (message &optional allow-more-to-come)
  "Decode an OP_MSG MESSAGE and return its body document.
Signal when a reply sets moreToCome unless ALLOW-MORE-TO-COME is non-nil."
  (mongodb--decoded-message-document
   (mongodb--decode-op-msg-frame message allow-more-to-come)))

(defun mongodb--snappy-varint (value)
  "Return VALUE encoded as a Snappy unsigned varint."
  (unless (and (integerp value)
               (>= value 0))
    (signal 'mongodb-error
            (list (format "Invalid MongoDB snappy varint value: %S"
                          value))))
  (let (bytes)
    (while (>= value #x80)
      (push (logior #x80 (logand value #x7f)) bytes)
      (setq value (ash value -7)))
    (push value bytes)
    (apply #'unibyte-string (nreverse bytes))))

(defun mongodb--read-snappy-varint (reader)
  "Read a Snappy unsigned varint from READER."
  (let ((shift 0)
        (value 0)
        byte)
    (while (progn
             (when (> shift 63)
               (signal 'mongodb-error
                       (list "MongoDB snappy varint is too large")))
             (setq byte (mongodb--read-byte reader))
             (setq value
                   (logior value
                           (ash (logand byte #x7f) shift)))
             (setq shift (+ shift 7))
             (not (zerop (logand byte #x80)))))
    value))

(defun mongodb--snappy-literal (literal)
  "Return one Snappy literal chunk for LITERAL."
  (setq literal (mongodb--byte-string literal))
  (let* ((length (length literal))
         (stored (1- length)))
    (unless (> length 0)
      (signal 'mongodb-error
              (list "MongoDB snappy literal chunks cannot be empty")))
    (cond
     ((< stored 60)
      (concat (unibyte-string (ash stored 2)) literal))
     ((<= stored #xff)
      (concat (unibyte-string (ash 60 2))
              (unibyte-string stored)
              literal))
     ((<= stored #xffff)
      (concat (unibyte-string (ash 61 2))
              (mongodb--pack-uint-le stored 2)
              literal))
     ((<= stored #xffffff)
      (concat (unibyte-string (ash 62 2))
              (mongodb--pack-uint-le stored 3)
              literal))
     ((<= stored #xffffffff)
      (concat (unibyte-string (ash 63 2))
              (mongodb--pack-uint-le stored 4)
              literal))
     (t
      (signal 'mongodb-error
              (list "MongoDB snappy literal is too large"))))))

(defun mongodb--snappy-compress (data)
  "Return DATA encoded as a Snappy block.
The encoder emits literal chunks only.  This is valid Snappy wire data and keeps
the MongoDB protocol path independent from external compression libraries."
  (setq data (mongodb--byte-string data))
  (if (zerop (length data))
      (mongodb--snappy-varint 0)
    (concat (mongodb--snappy-varint (length data))
            (mongodb--snappy-literal data))))

(defun mongodb--snappy-read-literal (reader tag)
  "Read a Snappy literal from READER using TAG."
  (let* ((length-code (ash tag -2))
         (length
          (if (< length-code 60)
              (1+ length-code)
            (1+ (mongodb--read-uint-le reader (- length-code 59))))))
    (mongodb--read-bytes reader length)))

(defun mongodb--snappy-copy-1-offset (reader tag)
  "Read a Snappy COPY_1 offset from READER using TAG."
  (let ((upper (ash (logand tag #xe0) 3))
        (lower (mongodb--read-byte reader)))
    (logior upper lower)))

(defun mongodb--snappy-copy-into-current-buffer (offset length)
  "Append a Snappy copy of LENGTH at OFFSET to the current buffer."
  (unless (and (> offset 0)
               (<= offset (1- (point))))
    (signal 'mongodb-error
            (list "MongoDB snappy copy offset is invalid")))
  (let ((source (- (point) offset)))
    (dotimes (_ length)
      (insert (unibyte-string (or (char-after source)
                                  (signal 'mongodb-error
                                          (list "MongoDB snappy copy exceeded output")))))
      (setq source (1+ source)))))

(defun mongodb--snappy-decompress (data)
  "Return DATA decoded from a Snappy block."
  (let* ((reader (make-mongodb--reader :data (mongodb--byte-string data) :pos 0))
         (expected-length (mongodb--read-snappy-varint reader)))
    (with-temp-buffer
      (set-buffer-multibyte nil)
      (while (< (mongodb--reader-pos reader)
                (length (mongodb--reader-data reader)))
        (let* ((tag (mongodb--read-byte reader))
               (type (logand tag #x03)))
          (pcase type
            (0
             (insert (mongodb--snappy-read-literal reader tag)))
            (1
             (mongodb--snappy-copy-into-current-buffer
              (mongodb--snappy-copy-1-offset reader tag)
              (+ 4 (logand (ash tag -2) #x7))))
            (2
             (mongodb--snappy-copy-into-current-buffer
              (mongodb--read-uint-le reader 2)
              (+ 1 (ash tag -2))))
            (3
             (mongodb--snappy-copy-into-current-buffer
              (mongodb--read-uint-le reader 4)
              (+ 1 (ash tag -2)))))))
      (unless (= (buffer-size) expected-length)
        (signal 'mongodb-error
                (list (format "MongoDB snappy length mismatch: expected %s, got %s"
                              expected-length
                              (buffer-size)))))
      (buffer-string))))

(defun mongodb--zlib-compress (data)
  "Return DATA as a zlib stream using DEFLATE stored blocks."
  (setq data (mongodb--byte-string data))
  (let ((offset 0)
        (parts (list (unibyte-string #x78 #x01))))
    (while (< offset (length data))
      (let* ((remaining (- (length data) offset))
             (chunk-size (min remaining #xffff))
             (final (= (+ offset chunk-size) (length data)))
             (nlen (logxor chunk-size #xffff)))
        (push (unibyte-string (if final 1 0)) parts)
        (push (mongodb--pack-uint16-le chunk-size) parts)
        (push (mongodb--pack-uint16-le nlen) parts)
        (push (substring data offset (+ offset chunk-size)) parts)
        (setq offset (+ offset chunk-size))))
    (when (zerop (length data))
      (push (unibyte-string 1 0 0 #xff #xff) parts))
    (push (mongodb--pack-uint32-be (mongodb--adler32 data)) parts)
    (apply #'concat (nreverse parts))))

(defun mongodb--zlib-decompress (data)
  "Return zlib-decompressed DATA as a unibyte string."
  (unless (and (fboundp 'zlib-available-p)
               (zlib-available-p))
    (signal 'mongodb-error
            (list "MongoDB zlib wire compression requires zlib support in Emacs")))
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert data)
    (unless (zlib-decompress-region (point-min) (point-max))
      (signal 'mongodb-error
              (list "MongoDB zlib-compressed wire message could not be decompressed")))
    (buffer-string)))

(defun mongodb--zstd-program ()
  "Return the configured zstd executable, or signal `mongodb-error'."
  (or (and (stringp mongodb-zstd-program)
           (not (string-empty-p mongodb-zstd-program))
           (executable-find mongodb-zstd-program))
      (signal 'mongodb-error
              (list "MongoDB zstd wire compression requires `mongodb-zstd-program' executable"))))

(defun mongodb--zstd-available-p ()
  "Return non-nil when zstd wire compression is available."
  (and (stringp mongodb-zstd-program)
       (not (string-empty-p mongodb-zstd-program))
       (executable-find mongodb-zstd-program)))

(defun mongodb--zstd-call (data &rest args)
  "Run zstd over DATA with ARGS and return stdout as a unibyte string."
  (setq data (mongodb--byte-string data))
  (let ((program (mongodb--zstd-program))
        (output (generate-new-buffer " *mongodb-zstd-output*"))
        (stderr-file (make-temp-file "mongodb-zstd-stderr-")))
    (unwind-protect
        (progn
          (with-current-buffer output
            (set-buffer-multibyte nil))
          (with-temp-buffer
            (set-buffer-multibyte nil)
            (insert data)
            (let ((coding-system-for-read 'binary)
                  (coding-system-for-write 'binary)
                  (status
                   (apply #'call-process-region
                          (point-min) (point-max)
                          program nil (list output stderr-file) nil
                          args)))
              (unless (zerop status)
                (let ((stderr
                       (with-temp-buffer
                         (when (> (nth 7 (file-attributes stderr-file)) 0)
                           (insert-file-contents-literally stderr-file))
                         (string-trim (buffer-string)))))
                  (signal 'mongodb-error
                          (list (if (string-empty-p stderr)
                                    "MongoDB zstd wire compression failed"
                                  (format "MongoDB zstd wire compression failed: %s"
                                          stderr))))))))
          (with-current-buffer output
            (buffer-string)))
      (when (buffer-live-p output)
        (kill-buffer output))
      (when (file-exists-p stderr-file)
        (delete-file stderr-file)))))

(defun mongodb--zstd-compress (data)
  "Return DATA compressed as a zstd frame."
  (mongodb--zstd-call data "-q" "-c"))

(defun mongodb--zstd-decompress (data)
  "Return zstd-decompressed DATA as a unibyte string."
  (mongodb--zstd-call data "-q" "-d" "-c"))

(defun mongodb--decompress-message-body (compressor-id data)
  "Return decompressed MongoDB DATA for COMPRESSOR-ID."
  (pcase compressor-id
    ((pred (lambda (id) (= id mongodb--compressor-noop)))
     data)
    ((pred (lambda (id) (= id mongodb--compressor-zlib)))
     (mongodb--zlib-decompress data))
    ((pred (lambda (id) (= id mongodb--compressor-snappy)))
     (mongodb--snappy-decompress data))
    ((pred (lambda (id) (= id mongodb--compressor-zstd)))
     (mongodb--zstd-decompress data))
    (_
     (signal 'mongodb-error
             (list (format "Unknown MongoDB wire compressor id: %s"
                           compressor-id))))))

(defun mongodb--decode-op-compressed (message)
  "Decode OP_COMPRESSED MESSAGE and return the wrapped full wire message."
  (let* ((reader (make-mongodb--reader :data message :pos 0))
         (length (mongodb--read-int32 reader))
         (request-id (mongodb--read-int32 reader))
         (response-to (mongodb--read-int32 reader))
         (opcode (mongodb--read-int32 reader)))
    (unless (= length (length message))
      (signal 'mongodb-error
              (list "MongoDB compressed wire message length mismatch")))
    (unless (= opcode mongodb--op-compressed)
      (signal 'mongodb-error
              (list (format "Unexpected MongoDB compressed opcode: %s"
                            opcode))))
    (let* ((original-opcode (mongodb--read-int32 reader))
           (uncompressed-size (mongodb--read-int32 reader))
           (compressor-id (mongodb--read-byte reader))
           (compressed (mongodb--read-bytes
                        reader
                        (- length (mongodb--reader-pos reader))))
           (body (mongodb--decompress-message-body compressor-id compressed)))
      (unless (= (length body) uncompressed-size)
        (signal 'mongodb-error
                (list (format "MongoDB decompressed wire message size mismatch: expected %s, got %s"
                              uncompressed-size
                              (length body)))))
      (concat (mongodb--pack-int32 (+ 16 uncompressed-size))
              (mongodb--pack-int32 request-id)
              (mongodb--pack-int32 response-to)
              (mongodb--pack-int32 original-opcode)
              body))))

(defun mongodb--decode-message-frame (message &optional allow-more-to-come)
  "Decode a MongoDB OP_MSG wire MESSAGE and return a decoded frame.

Arguments: MESSAGE, ALLOW-MORE-TO-COME."
  (let* ((reader (make-mongodb--reader :data message :pos 0))
         (_length (mongodb--read-int32 reader))
         (_request-id (mongodb--read-int32 reader))
         (_response-to (mongodb--read-int32 reader))
         (opcode (mongodb--read-int32 reader)))
    (cond
     ((= opcode mongodb--op-compressed)
      (mongodb--decode-message-frame
       (mongodb--decode-op-compressed message)
       allow-more-to-come))
     ((= opcode mongodb--op-msg)
      (mongodb--decode-op-msg-frame message allow-more-to-come))
     (t
      (signal 'mongodb-error
              (list (format "Unexpected MongoDB opcode: %s" opcode)))))))

(defun mongodb--decode-message (message &optional allow-more-to-come)
  "Decode a MongoDB wire MESSAGE and return its body document.

Arguments: MESSAGE, ALLOW-MORE-TO-COME."
  (mongodb--decoded-message-document
   (mongodb--decode-message-frame message allow-more-to-come)))

(defun mongodb--decode-op-reply-frame (message)
  "Decode a legacy OP_REPLY MESSAGE and return a decoded frame."
  (let* ((reader (make-mongodb--reader :data message :pos 0))
         (length (mongodb--read-int32 reader))
         (request-id (mongodb--read-int32 reader))
         (response-to (mongodb--read-int32 reader))
         (opcode (mongodb--read-int32 reader)))
    (unless (= length (length message))
      (signal 'mongodb-error
              (list "MongoDB wire message length mismatch")))
    (unless (= opcode mongodb--op-reply)
      (signal 'mongodb-error
              (list (format "Unexpected MongoDB handshake opcode: %s" opcode))))
    (let ((response-flags (mongodb--read-int32 reader))
          (_cursor-id (mongodb--read-int64 reader))
          (_starting-from (mongodb--read-int32 reader))
          (number-returned (mongodb--read-int32 reader)))
      (unless (> number-returned 0)
        (signal 'mongodb-error
                (list "MongoDB handshake returned no documents")))
      (make-mongodb--decoded-message
       :request-id request-id
       :response-to response-to
       :opcode opcode
       :flags response-flags
       :document (mongodb--decode-document reader)))))

(defun mongodb--decode-op-reply (message)
  "Decode a legacy OP_REPLY MESSAGE and return its first document."
  (mongodb--decoded-message-document
   (mongodb--decode-op-reply-frame message)))

(defun mongodb--validate-response-to (frame expected-response-to)
  "Signal unless FRAME's responseTo matches EXPECTED-RESPONSE-TO."
  (when (and expected-response-to
             (/= (mongodb--decoded-message-response-to frame)
                 expected-response-to))
    (signal 'mongodb-error
            (list (format "MongoDB responseTo mismatch: expected %s, got %s"
                          expected-response-to
                          (mongodb--decoded-message-response-to frame))))))


(provide 'mongodb-wire)

;;; mongodb-wire.el ends here
