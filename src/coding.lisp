(in-package #:dns)

(defgeneric encode-message (message buffer)
  (:documentation "Encode `MESSAGFE' into `BUFFER'."))

(defgeneric decode-message (type buffer)
  (:documentation "Decode a message of type `TYPE' from `BUFFER'."))

(defun encode-to-vector (message)
  "Encodes `MESSAGE' into an octet `VECTOR'"
  (fast-io:with-fast-output (buffer :vector)
    (encode-message message buffer)))

(defun decode-from-vector (vector)
  "Decodes a `MESSAGE' from an octet  `VECTOR'"
  (fast-io:with-fast-input (buffer vector)
    (decode-message 'message buffer)))

(defun decode-flags (flag-value)
  "Decode the flags from `FLAG-VALUE', which is a 16 bit unisgned integer, into a `FLAGS' object."
  (make-instance 'flags
                 :qr     (ldb-test (byte 1 15) flag-value)
                 :opcode (ldb (byte 4 11) flag-value)
                 :aa     (ldb-test (byte 1 10) flag-value)
                 :tc     (ldb-test (byte 1 9) flag-value)
                 :rd     (ldb-test (byte 1 8) flag-value)
                 :ra     (ldb-test (byte 1 7) flag-value)
                 :z      (ldb-test (byte 1 6) flag-value)
                 :rcode  (ldb (byte 4 1) flag-value)))

(defun encode-flags (flags)
  "Encode the `FLAGS' object into a 16 bit unsigned integer."
  (let ((encoded-flags 0))
    (with-slots (qr opcode aa tc rd ra z ad rcode) flags
      (setf (ldb (byte 1 15) encoded-flags) qr)
      (setf (ldb (byte 4 11) encoded-flags) opcode)
      (setf (ldb (byte 1 10) encoded-flags) (if aa 1 0))
      (setf (ldb (byte 1 9) encoded-flags)  (if tc 1 0))
      (setf (ldb (byte 1 8) encoded-flags)  (if rd 1 0))
      (setf (ldb (byte 1 7) encoded-flags)  (if ra 1 0))
      (setf (ldb (byte 1 6) encoded-flags)  (if z 1 0))
      (setf (ldb (byte 1 5) encoded-flags)  (if ad 1 0))
      (setf (ldb (byte 4 1) encoded-flags) rcode)
      encoded-flags)))

(defmethod encode-message ((message message) buffer)
  (with-slots (header questions) message
    (encode-message header buffer)
    (when questions
      (loop :for question :in questions
            :do (encode-message question buffer)))))

(defmethod decode-message ((type (eql 'message)) buffer)
  (let ((header (decode-message 'message-header buffer)))
    (with-slots (qdcount ancount nscount arcount) header
      (make-instance 'message
                     :header      header
                     :questions   (loop :repeat qdcount :collect (decode-message 'message-question buffer))
                     :answers     (loop :repeat ancount :collect (decode-message 'resource-record buffer))
                     :authorities (loop :repeat nscount :collect (decode-message 'resource-record buffer))
                     :additionals (loop :repeat arcount :collect (decode-message 'resource-record buffer))))))

(defmethod encode-message ((header message-header) buffer)
  (with-slots (id flags qdcount ancount nscount arcount) header
    (fast-io:writeu16-be id buffer)
    (fast-io:writeu16-be (encode-flags flags) buffer)
    (fast-io:writeu16-be qdcount buffer)
    (fast-io:writeu16-be ancount buffer)
    (fast-io:writeu16-be nscount buffer)
    (fast-io:writeu16-be arcount buffer)))

(defmethod decode-message ((type (eql 'message-header)) buffer)
  (make-instance 'message-header
                 :id      (fast-io:readu16-be buffer)
                 :flags   (decode-flags (fast-io:readu16-be buffer))
                 :qdcount (fast-io:readu16-be buffer)
                 :ancount (fast-io:readu16-be buffer)
                 :nscount (fast-io:readu16-be buffer)
                 :arcount (fast-io:readu16-be buffer)))

(defmethod encode-message ((question message-question) buffer)
  (with-slots (qname qtype qclass) question
    (encode-message qname buffer)
    (fast-io:writeu16-be qtype buffer)
    (fast-io:writeu16-be qclass buffer)))

(defmethod decode-message ((type (eql 'message-question)) buffer)
  (make-instance 'message-question
                 :qname  (decode-message 'domain-name buffer)
                 :qtype  (fast-io:readu16-be buffer)
                 :qclass (fast-io:readu16-be buffer)))

(defmethod encode-message ((qname domain-name) buffer)
  (with-slots (name-labels) qname
    (dolist (label name-labels)
      (fast-io:writeu8-be (length label) buffer)
      (loop :for char :across label :do (fast-io:writeu8-be (char-code char) buffer)))
    (fast-io:writeu8-be 0 buffer)))

(defmethod decode-message ((type (eql 'domain-name)) buffer)
  (let ((bytes (decompress-labels buffer)))
    (length-encoded-labels-to-domain-name bytes)))

(defun decompress-labels (buffer)
  "Decompress the labels in `BUFFER' and return the decompressed data as a vector.
   The vector contains the lenght encoded labels, which means a byte denoting the label length is followed by label itself
  "
  (fast-io:with-fast-output (out :vector)
    (loop :for len = (fast-io:fast-read-byte buffer nil nil)
          :until (or (null len) (zerop len))
          :if (plusp (logand len #b11000000))
            :do (return-from decompress-labels (decompress-label len buffer))
          :else
            :do
               (fast-io:writeu8-be len out)
               (loop :repeat len :do (fast-io:writeu8-be (fast-io:readu8-be buffer) out)))))

(defun decompress-label (length buffer)
  (let ((offset (+ (fast-io:readu8-be buffer) (logand length #b00111111)))
        (current-position (fast-io:buffer-position buffer)))
    (setf (fast-io:buffer-position buffer) offset)
    (prog1 (decompress-labels buffer)
      (setf (fast-io:buffer-position buffer) current-position))))

(defmethod decode-message ((type (eql 'resource-record)) buffer)
  (let ((name (decode-message 'domain-name buffer))
        (type (fast-io:readu16-be buffer))
        (class (fast-io:readu16-be buffer))
        (ttl (fast-io:readu32-be buffer))
        (rdlength (fast-io:readu16-be buffer)))
    (make-instance 'resource-record
                   :name name
                   :type type
                   :class class
                   :ttl ttl
                   :rdata (decode-rdata type rdlength buffer))))

(defun decode-rdata (type len buffer)
  ;; only special case NS and CNAME for now
  ;; as they require decompression of domain names
  (cond
    ((= type +rr-type-ns+)
     (decompress-labels buffer))
    ((= type +rr-type-cname+)
     (decompress-labels buffer))
    (t
     (let ((result (make-array len :element-type '(unsigned-byte 8))))
       (loop :for i :from 0 :below len :do (setf (aref result i) (fast-io:readu8-be buffer)))
       result))))
