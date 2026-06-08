;;; mongo-wire.el --- Wire message framing -*- lexical-binding: t; -*-

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

;; MongoDB OP_MSG, OP_COMPRESSED, legacy OP_REPLY framing, and wire
;; compression helpers.  Connection-state send/receive glue stays in mongo.el.

;;; Code:

(require 'cl-lib)
(require 'mongo-bson)
(require 'subr-x)

(defconst mongo--op-msg 2013)

(defconst mongo--op-compressed 2012)

(defconst mongo--op-query 2004)

(defconst mongo--op-reply 1)

(defconst mongo--compressor-noop 0)

(defconst mongo--compressor-snappy 1)

(defconst mongo--compressor-zlib 2)

(defconst mongo--compressor-zstd 3)

(defcustom mongo-zstd-program "zstd"
  "Executable used for MongoDB zstd wire compression.
Set this to nil to disable zstd support.  zstd is optional and is only used
when the connection explicitly requests or receives zstd OP_COMPRESSED frames."
  :type '(choice (const :tag "Disable zstd" nil) string)
  :group 'mongo)

(defconst mongo--uncompressed-command-names
  '("hello" "isMaster" "ismaster" "saslStart" "saslContinue"
    "getnonce" "authenticate" "createUser" "updateUser"
    "copydbSaslStart" "copydbgetnonce" "copydb")
  "MongoDB commands that must not be wrapped in OP_COMPRESSED.")

(defconst mongo--op-msg-checksum-present #x1)

(defconst mongo--op-msg-more-to-come #x2)

(defconst mongo--op-msg-exhaust-allowed #x10000)

(defconst mongo--op-msg-required-flag-mask #xffff)

(defconst mongo--op-msg-known-required-flag-mask
  (logior mongo--op-msg-checksum-present
          mongo--op-msg-more-to-come))

(cl-defstruct mongo--decoded-message
  request-id
  response-to
  opcode
  flags
  document)

;;;; OP_MSG framing

(defun mongo--make-op-query (request-id database document)
  "Return a legacy OP_QUERY command for initial handshake DOCUMENT."
  (let* ((body (concat (mongo--pack-int32 0)
                       (mongo--encode-cstring (format "%s.$cmd" database))
                       (mongo--pack-int32 0)
                       (mongo--pack-int32 -1)
                       (mongo--encode-document document)))
         (length (+ 16 (length body))))
    (concat (mongo--pack-int32 length)
            (mongo--pack-int32 request-id)
            (mongo--pack-int32 0)
            (mongo--pack-int32 mongo--op-query)
            body)))

(defun mongo--encode-op-msg-document-sequence (sequence)
  "Return a kind 1 OP_MSG document SEQUENCE section.
SEQUENCE is a cons cell whose car is the sequence identifier and whose cdr is
a vector or list of BSON documents."
  (let* ((identifier (car sequence))
         (documents (cdr sequence))
         (document-list (if (vectorp documents)
                            (append documents nil)
                          documents)))
    (unless (stringp identifier)
      (signal 'mongo-error
              (list (format "MongoDB OP_MSG sequence identifier must be a string: %S"
                            identifier))))
    (unless (listp document-list)
      (signal 'mongo-error
              (list (format "MongoDB OP_MSG sequence documents must be a list or vector: %S"
                            documents))))
    (let* ((document-bytes (apply #'concat
                                  (mapcar #'mongo--encode-document
                                          document-list)))
           (identifier-bytes (mongo--encode-cstring identifier))
           (section-size (+ 4
                            (length identifier-bytes)
                            (length document-bytes))))
      (concat (unibyte-string 1)
              (mongo--pack-int32 section-size)
              identifier-bytes
              document-bytes))))

(defun mongo--make-op-msg
    (request-id document &optional flag-bits checksum sequences response-to)
  "Return an OP_MSG request REQUEST-ID containing DOCUMENT.
FLAG-BITS defaults to zero.  CHECKSUM, when t, appends a computed CRC-32C
checksum; when an integer, appends that explicit uint32 checksum.  Either
CHECKSUM value sets the checksumPresent flag.  SEQUENCES is a list of kind 1
document sequence sections.  RESPONSE-TO defaults to zero."
  (let* ((body-document (mongo--encode-document document))
         (sequence-bytes (apply #'concat
                                (mapcar #'mongo--encode-op-msg-document-sequence
                                        sequences)))
         (flag-bits (if checksum
                        (logior (or flag-bits 0)
                                mongo--op-msg-checksum-present)
                      (or flag-bits 0)))
         (body-without-checksum (concat (mongo--pack-int32 flag-bits)
                                        (unibyte-string 0)
                                        body-document
                                        sequence-bytes))
         (length (+ 16
                    (length body-without-checksum)
                    (if checksum 4 0)))
         (message-without-checksum
          (concat (mongo--pack-int32 length)
                  (mongo--pack-int32 request-id)
                  (mongo--pack-int32 (or response-to 0))
                  (mongo--pack-int32 mongo--op-msg)
                  body-without-checksum)))
    (if checksum
        (concat
         message-without-checksum
         (mongo--pack-int32
          (cond
           ((eq checksum t)
            (mongo--crc32c message-without-checksum))
           ((integerp checksum)
            checksum)
           (t
            (signal 'mongo-error
                    (list (format "Invalid MongoDB OP_MSG checksum value: %S"
                                  checksum)))))))
      message-without-checksum)))

(defun mongo--compressor-id (compressor)
  "Return the MongoDB wire compressor id for COMPRESSOR."
  (pcase compressor
    ("noop" mongo--compressor-noop)
    ("snappy" mongo--compressor-snappy)
    ("zlib" mongo--compressor-zlib)
    ("zstd" mongo--compressor-zstd)
    (_
     (signal 'mongo-error
             (list (format "Unsupported negotiated MongoDB compressor: %s"
                           compressor))))))

(defun mongo--compress-message-body (compressor data)
  "Return DATA compressed using negotiated COMPRESSOR."
  (pcase compressor
    ("noop" (mongo--byte-string data))
    ("snappy" (mongo--snappy-compress data))
    ("zlib" (mongo--zlib-compress data))
    ("zstd" (mongo--zstd-compress data))
    (_
     (signal 'mongo-error
             (list (format "Unsupported negotiated MongoDB compressor: %s"
                           compressor))))))

(defun mongo--make-op-compressed (message compressor)
  "Return MESSAGE wrapped as OP_COMPRESSED using COMPRESSOR."
  (setq message (mongo--byte-string message))
  (let* ((reader (make-mongo--reader :data message :pos 0))
         (message-length (mongo--read-int32 reader))
         (request-id (mongo--read-int32 reader))
         (response-to (mongo--read-int32 reader))
         (opcode (mongo--read-int32 reader)))
    (unless (= message-length (length message))
      (signal 'mongo-error
              (list "MongoDB wire message length mismatch")))
    (when (= opcode mongo--op-compressed)
      (signal 'mongo-error
              (list "MongoDB wire message is already compressed")))
    (let* ((body (substring message 16 message-length))
           (compressed-body (mongo--compress-message-body compressor body))
           (length (+ 16 4 4 1 (length compressed-body))))
      (concat (mongo--pack-int32 length)
              (mongo--pack-int32 request-id)
              (mongo--pack-int32 response-to)
              (mongo--pack-int32 mongo--op-compressed)
              (mongo--pack-int32 opcode)
              (mongo--pack-int32 (length body))
              (unibyte-string (mongo--compressor-id compressor))
              compressed-body))))

(defun mongo--command-compressible-p (document)
  "Return non-nil when DOCUMENT may be sent as OP_COMPRESSED."
  (let* ((pairs (mongo--document-pairs document))
         (command-name (caar pairs)))
    (not (member command-name mongo--uncompressed-command-names))))


(defun mongo--read-int32-from-string (data)
  "Read the first little-endian int32 from DATA."
  (mongo--read-int32
   (make-mongo--reader :data data :pos 0)))

(defun mongo--validate-op-msg-flags (flag-bits)
  "Signal when OP_MSG FLAG-BITS contain unknown required flags."
  (let ((unknown-required
         (logand flag-bits
                 (logxor mongo--op-msg-required-flag-mask
                         mongo--op-msg-known-required-flag-mask))))
    (unless (zerop unknown-required)
      (signal 'mongo-error
              (list (format "Unknown MongoDB OP_MSG required flag bits: %s"
                            unknown-required))))))

(defun mongo--decode-op-msg-frame (message &optional allow-more-to-come)
  "Decode OP_MSG MESSAGE and return a `mongo--decoded-message'.
Signal when a reply sets moreToCome unless ALLOW-MORE-TO-COME is non-nil."
  (let* ((reader (make-mongo--reader :data message :pos 0))
         (length (mongo--read-int32 reader))
         (request-id (mongo--read-int32 reader))
         (response-to (mongo--read-int32 reader))
         (opcode (mongo--read-int32 reader))
         (flag-bits nil)
         (sections-end nil)
         document)
    (unless (= length (length message))
      (signal 'mongo-error
              (list "MongoDB wire message length mismatch")))
    (unless (= opcode mongo--op-msg)
      (signal 'mongo-error
              (list (format "Unexpected MongoDB opcode: %s" opcode))))
    (setq flag-bits (mongo--read-int32 reader))
    (mongo--validate-op-msg-flags flag-bits)
    (when (and (not allow-more-to-come)
               (not (zerop (logand flag-bits
                                    mongo--op-msg-more-to-come))))
      (signal 'mongo-error
              (list "MongoDB OP_MSG moreToCome flag received without exhaustAllowed request")))
    (setq sections-end
          (if (not (zerop (logand flag-bits
                                   mongo--op-msg-checksum-present)))
              (- length 4)
            length))
    (when (< sections-end (mongo--reader-pos reader))
      (signal 'mongo-error
              (list "MongoDB OP_MSG checksum flag set on a truncated message")))
    (while (< (mongo--reader-pos reader) sections-end)
      (pcase (mongo--read-byte reader)
        (0
         (setq document (mongo--decode-document reader))
         (when (> (mongo--reader-pos reader) sections-end)
           (signal 'mongo-error
                   (list "MongoDB OP_MSG body section exceeds message length"))))
        (1
         (let* ((section-start (mongo--reader-pos reader))
                (section-size (mongo--read-int32 reader))
                (section-end (+ section-start section-size)))
           (when (or (< section-size 5)
                     (> section-end sections-end))
             (signal 'mongo-error
                     (list "MongoDB OP_MSG document sequence section has invalid size")))
           (mongo--read-cstring reader)
           (while (< (mongo--reader-pos reader) section-end)
             (mongo--decode-document reader))
           (setf (mongo--reader-pos reader) section-end)))
        (kind
         (signal 'mongo-error
                 (list (format "Unexpected MongoDB OP_MSG section kind: %s"
                               kind))))))
    (unless (= (mongo--reader-pos reader) sections-end)
      (signal 'mongo-error
              (list "MongoDB OP_MSG sections ended at an unexpected offset")))
    (when (not (zerop (logand flag-bits mongo--op-msg-checksum-present)))
      (let ((expected (mongo--read-uint-le reader 4))
            (actual (mongo--crc32c (substring message 0 sections-end))))
        (unless (= expected actual)
          (signal 'mongo-error
                  (list (format
                         "MongoDB OP_MSG checksum mismatch: expected %08x, got %08x"
                         expected actual))))))
    (make-mongo--decoded-message
     :request-id request-id
     :response-to response-to
     :opcode opcode
     :flags flag-bits
     :document
     (or document
         (signal 'mongo-error
                 (list "MongoDB OP_MSG reply contained no body document"))))))

(defun mongo--decode-op-msg (message &optional allow-more-to-come)
  "Decode an OP_MSG MESSAGE and return its body document.
Signal when a reply sets moreToCome unless ALLOW-MORE-TO-COME is non-nil."
  (mongo--decoded-message-document
   (mongo--decode-op-msg-frame message allow-more-to-come)))

(defun mongo--snappy-varint (value)
  "Return VALUE encoded as a Snappy unsigned varint."
  (unless (and (integerp value)
               (>= value 0))
    (signal 'mongo-error
            (list (format "Invalid MongoDB snappy varint value: %S"
                          value))))
  (let (bytes)
    (while (>= value #x80)
      (push (logior #x80 (logand value #x7f)) bytes)
      (setq value (ash value -7)))
    (push value bytes)
    (apply #'unibyte-string (nreverse bytes))))

(defun mongo--read-snappy-varint (reader)
  "Read a Snappy unsigned varint from READER."
  (let ((shift 0)
        (value 0)
        byte)
    (while (progn
             (when (> shift 63)
               (signal 'mongo-error
                       (list "MongoDB snappy varint is too large")))
             (setq byte (mongo--read-byte reader))
             (setq value
                   (logior value
                           (ash (logand byte #x7f) shift)))
             (setq shift (+ shift 7))
             (not (zerop (logand byte #x80)))))
    value))

(defun mongo--snappy-literal (literal)
  "Return one Snappy literal chunk for LITERAL."
  (setq literal (mongo--byte-string literal))
  (let* ((length (length literal))
         (stored (1- length)))
    (unless (> length 0)
      (signal 'mongo-error
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
              (mongo--pack-uint-le stored 2)
              literal))
     ((<= stored #xffffff)
      (concat (unibyte-string (ash 62 2))
              (mongo--pack-uint-le stored 3)
              literal))
     ((<= stored #xffffffff)
      (concat (unibyte-string (ash 63 2))
              (mongo--pack-uint-le stored 4)
              literal))
     (t
      (signal 'mongo-error
              (list "MongoDB snappy literal is too large"))))))

(defun mongo--snappy-compress (data)
  "Return DATA encoded as a Snappy block.
The encoder emits literal chunks only.  This is valid Snappy wire data and keeps
the MongoDB protocol path independent from external compression libraries."
  (setq data (mongo--byte-string data))
  (if (zerop (length data))
      (mongo--snappy-varint 0)
    (concat (mongo--snappy-varint (length data))
            (mongo--snappy-literal data))))

(defun mongo--snappy-read-literal (reader tag)
  "Read a Snappy literal from READER using TAG."
  (let* ((length-code (ash tag -2))
         (length
          (if (< length-code 60)
              (1+ length-code)
            (1+ (mongo--read-uint-le reader (- length-code 59))))))
    (mongo--read-bytes reader length)))

(defun mongo--snappy-copy-1-offset (reader tag)
  "Read a Snappy COPY_1 offset from READER using TAG."
  (let ((upper (ash (logand tag #xe0) 3))
        (lower (mongo--read-byte reader)))
    (logior upper lower)))

(defun mongo--snappy-copy-into-current-buffer (offset length)
  "Append a Snappy copy of LENGTH at OFFSET to the current buffer."
  (unless (and (> offset 0)
               (<= offset (1- (point))))
    (signal 'mongo-error
            (list "MongoDB snappy copy offset is invalid")))
  (let ((source (- (point) offset)))
    (dotimes (_ length)
      (insert (unibyte-string (or (char-after source)
                                  (signal 'mongo-error
                                          (list "MongoDB snappy copy exceeded output")))))
      (setq source (1+ source)))))

(defun mongo--snappy-decompress (data)
  "Return DATA decoded from a Snappy block."
  (let* ((reader (make-mongo--reader :data (mongo--byte-string data) :pos 0))
         (expected-length (mongo--read-snappy-varint reader)))
    (with-temp-buffer
      (set-buffer-multibyte nil)
      (while (< (mongo--reader-pos reader)
                (length (mongo--reader-data reader)))
        (let* ((tag (mongo--read-byte reader))
               (type (logand tag #x03)))
          (pcase type
            (0
             (insert (mongo--snappy-read-literal reader tag)))
            (1
             (mongo--snappy-copy-into-current-buffer
              (mongo--snappy-copy-1-offset reader tag)
              (+ 4 (logand (ash tag -2) #x7))))
            (2
             (mongo--snappy-copy-into-current-buffer
              (mongo--read-uint-le reader 2)
              (+ 1 (ash tag -2))))
            (3
             (mongo--snappy-copy-into-current-buffer
              (mongo--read-uint-le reader 4)
              (+ 1 (ash tag -2)))))))
      (unless (= (buffer-size) expected-length)
        (signal 'mongo-error
                (list (format "MongoDB snappy length mismatch: expected %s, got %s"
                              expected-length
                              (buffer-size)))))
      (buffer-string))))

(defun mongo--zlib-compress (data)
  "Return DATA as a zlib stream using DEFLATE stored blocks."
  (setq data (mongo--byte-string data))
  (let ((offset 0)
        (parts (list (unibyte-string #x78 #x01))))
    (while (< offset (length data))
      (let* ((remaining (- (length data) offset))
             (chunk-size (min remaining #xffff))
             (final (= (+ offset chunk-size) (length data)))
             (nlen (logxor chunk-size #xffff)))
        (push (unibyte-string (if final 1 0)) parts)
        (push (mongo--pack-uint16-le chunk-size) parts)
        (push (mongo--pack-uint16-le nlen) parts)
        (push (substring data offset (+ offset chunk-size)) parts)
        (setq offset (+ offset chunk-size))))
    (when (zerop (length data))
      (push (unibyte-string 1 0 0 #xff #xff) parts))
    (push (mongo--pack-uint32-be (mongo--adler32 data)) parts)
    (apply #'concat (nreverse parts))))

(defun mongo--zlib-decompress (data)
  "Return zlib-decompressed DATA as a unibyte string."
  (unless (and (fboundp 'zlib-available-p)
               (zlib-available-p))
    (signal 'mongo-error
            (list "MongoDB zlib wire compression requires zlib support in Emacs")))
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert data)
    (unless (zlib-decompress-region (point-min) (point-max))
      (signal 'mongo-error
              (list "MongoDB zlib-compressed wire message could not be decompressed")))
    (buffer-string)))

(defun mongo--zstd-program ()
  "Return the configured zstd executable, or signal `mongo-error'."
  (or (and (stringp mongo-zstd-program)
           (not (string-empty-p mongo-zstd-program))
           (executable-find mongo-zstd-program))
      (signal 'mongo-error
              (list "MongoDB zstd wire compression requires `mongo-zstd-program' executable"))))

(defun mongo--zstd-available-p ()
  "Return non-nil when zstd wire compression is available."
  (and (stringp mongo-zstd-program)
       (not (string-empty-p mongo-zstd-program))
       (executable-find mongo-zstd-program)))

(defun mongo--zstd-call (data &rest args)
  "Run zstd over DATA with ARGS and return stdout as a unibyte string."
  (setq data (mongo--byte-string data))
  (let ((program (mongo--zstd-program))
        (output (generate-new-buffer " *mongo-zstd-output*"))
        (stderr-file (make-temp-file "mongo-zstd-stderr-")))
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
                  (signal 'mongo-error
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

(defun mongo--zstd-compress (data)
  "Return DATA compressed as a zstd frame."
  (mongo--zstd-call data "-q" "-c"))

(defun mongo--zstd-decompress (data)
  "Return zstd-decompressed DATA as a unibyte string."
  (mongo--zstd-call data "-q" "-d" "-c"))

(defun mongo--decompress-message-body (compressor-id data)
  "Return decompressed MongoDB DATA for COMPRESSOR-ID."
  (pcase compressor-id
    ((pred (lambda (id) (= id mongo--compressor-noop)))
     data)
    ((pred (lambda (id) (= id mongo--compressor-zlib)))
     (mongo--zlib-decompress data))
    ((pred (lambda (id) (= id mongo--compressor-snappy)))
     (mongo--snappy-decompress data))
    ((pred (lambda (id) (= id mongo--compressor-zstd)))
     (mongo--zstd-decompress data))
    (_
     (signal 'mongo-error
             (list (format "Unknown MongoDB wire compressor id: %s"
                           compressor-id))))))

(defun mongo--decode-op-compressed (message)
  "Decode OP_COMPRESSED MESSAGE and return the wrapped full wire message."
  (let* ((reader (make-mongo--reader :data message :pos 0))
         (length (mongo--read-int32 reader))
         (request-id (mongo--read-int32 reader))
         (response-to (mongo--read-int32 reader))
         (opcode (mongo--read-int32 reader)))
    (unless (= length (length message))
      (signal 'mongo-error
              (list "MongoDB compressed wire message length mismatch")))
    (unless (= opcode mongo--op-compressed)
      (signal 'mongo-error
              (list (format "Unexpected MongoDB compressed opcode: %s"
                            opcode))))
    (let* ((original-opcode (mongo--read-int32 reader))
           (uncompressed-size (mongo--read-int32 reader))
           (compressor-id (mongo--read-byte reader))
           (compressed (mongo--read-bytes
                        reader
                        (- length (mongo--reader-pos reader))))
           (body (mongo--decompress-message-body compressor-id compressed)))
      (unless (= (length body) uncompressed-size)
        (signal 'mongo-error
                (list (format "MongoDB decompressed wire message size mismatch: expected %s, got %s"
                              uncompressed-size
                              (length body)))))
      (concat (mongo--pack-int32 (+ 16 uncompressed-size))
              (mongo--pack-int32 request-id)
              (mongo--pack-int32 response-to)
              (mongo--pack-int32 original-opcode)
              body))))

(defun mongo--decode-message-frame (message &optional allow-more-to-come)
  "Decode a MongoDB OP_MSG wire MESSAGE and return a decoded frame."
  (let* ((reader (make-mongo--reader :data message :pos 0))
         (_length (mongo--read-int32 reader))
         (_request-id (mongo--read-int32 reader))
         (_response-to (mongo--read-int32 reader))
         (opcode (mongo--read-int32 reader)))
    (cond
     ((= opcode mongo--op-compressed)
      (mongo--decode-message-frame
       (mongo--decode-op-compressed message)
       allow-more-to-come))
     ((= opcode mongo--op-msg)
      (mongo--decode-op-msg-frame message allow-more-to-come))
     (t
      (signal 'mongo-error
              (list (format "Unexpected MongoDB opcode: %s" opcode)))))))

(defun mongo--decode-message (message &optional allow-more-to-come)
  "Decode a MongoDB wire MESSAGE and return its body document."
  (mongo--decoded-message-document
   (mongo--decode-message-frame message allow-more-to-come)))

(defun mongo--decode-op-reply-frame (message)
  "Decode a legacy OP_REPLY MESSAGE and return a decoded frame."
  (let* ((reader (make-mongo--reader :data message :pos 0))
         (length (mongo--read-int32 reader))
         (request-id (mongo--read-int32 reader))
         (response-to (mongo--read-int32 reader))
         (opcode (mongo--read-int32 reader)))
    (unless (= length (length message))
      (signal 'mongo-error
              (list "MongoDB wire message length mismatch")))
    (unless (= opcode mongo--op-reply)
      (signal 'mongo-error
              (list (format "Unexpected MongoDB handshake opcode: %s" opcode))))
    (let ((response-flags (mongo--read-int32 reader))
          (_cursor-id (mongo--read-int64 reader))
          (_starting-from (mongo--read-int32 reader))
          (number-returned (mongo--read-int32 reader)))
      (unless (> number-returned 0)
        (signal 'mongo-error
                (list "MongoDB handshake returned no documents")))
      (make-mongo--decoded-message
       :request-id request-id
       :response-to response-to
       :opcode opcode
       :flags response-flags
       :document (mongo--decode-document reader)))))

(defun mongo--decode-op-reply (message)
  "Decode a legacy OP_REPLY MESSAGE and return its first document."
  (mongo--decoded-message-document
   (mongo--decode-op-reply-frame message)))

(defun mongo--validate-response-to (frame expected-response-to)
  "Signal unless FRAME's responseTo matches EXPECTED-RESPONSE-TO."
  (when (and expected-response-to
             (/= (mongo--decoded-message-response-to frame)
                 expected-response-to))
    (signal 'mongo-error
            (list (format "MongoDB responseTo mismatch: expected %s, got %s"
                          expected-response-to
                          (mongo--decoded-message-response-to frame))))))


(provide 'mongo-wire)

;;; mongo-wire.el ends here
