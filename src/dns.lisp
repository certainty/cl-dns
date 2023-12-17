(in-package #:dns)

(deftype uint16 () '(unsigned-byte 16))
(deftype uint32 () '(unsigned-byte 32))
(deftype octet () '(unsigned-byte 8))

(defclass message ()
  ((header
    :initarg :header
    :initform (error "Must supply a header")
    :type message-header)
   (questions
    :initarg :questions
    :initform nil
    :type (or null (vector message-question)))
   (answers
    :initarg :answers
    :initform nil
    :type (or null (vector resource-record)))
   (authorities
    :initarg :authorities
    :initform nil
    :type (or null (vector resource-record)))
   (additionals
    :initarg :additionals
    :initform nil
    :type (or null (vector resource-record)))))

(defmethod print-object ((message message) stream)
  (with-slots (header questions answers authorities additionals) message
    (print-unreadable-object (message stream :type t)
      (format stream " Header: ~A~%Questions: ~A~%Answers: ~A~%Authorities: ~A~%Additionals: ~A"
              header questions answers authorities additionals))))

(s:defconst +dns-qr-query+ 0)
(s:defconst +dns-qr-response+ 1)

(s:defconst +dns-opcode-query+ 0)
(s:defconst +dns-opcode-iquery+ 1)
(s:defconst +dns-opcode-status+ 2)

(s:defconst +dns-type-a+ 1)
(s:defconst +dns-class-in+ 1)

(defclass message-header ()
  ((id
    :initarg :id
    :initform (error "Must supply an id")
    :type uint16
    :documentation
    "A 16 bit identifier assigned by the program that generates any kind of query.
     This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.")
   (flags
    :initarg :flags
    :initform (error "Must supply flags")
    :type uint16)
   (qdcount
    :initarg :qdcount
    :initform (error "Must supply a qdcount")
    :type uint16
    :documentation "An unsigned 16 bit integer specifying the number of entries in the question section.")
   (ancount
    :initarg :ancount
    :initform 0
    :type uint16
    :documentation "An unsigned 16 bit integer specifying the number of resource records in the answer section.")
   (nscount
    :initarg :nscount
    :initform 0
    :type uint16
    :documentation "An unsigned 16 bit integer specifying the number of name server resource records in the authority records section.")
   (arcount
    :initarg :arcount
    :initform 0
    :type uint16
    :documentation "An unsigned 16 bit integer specifying the number of resource records in the additional records section.")))

(defmethod print-object ((header message-header) stream)
  (with-slots (id flags qdcount ancount nscount arcount) header
    (print-unreadable-object (header stream :type t)
      (format stream "ID: ~A~%Flags: ~A~%QDCOUNT: ~A~%ANCOUNT: ~A~%NSCOUNT: ~A~%ARCOUNT: ~A"
              id flags qdcount ancount nscount arcount))))

(defclass message-question ()
  ((qname
    :initarg :qname
    :initform (error "Must supply a qname")
    :type domain-name 
    :documentation
    "A domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets.
     The domain name terminates with the zero length octet for the null label of the root.
     Note that this field may be an odd number of octets; no padding is used.")
   (qtype
    :initarg :qtype
    :initform (error "Must supply a qtype")
    :type uint16
    :documentation "A two octet code which specifies the type of the query.")
   (qclass
    :initarg :qclass
    :initform (error "Must supply a qclass")
    :type uint16
    :documentation
    "A two octet code that specifies the class of the query.
     For example, the QCLASS field is IN for the Internet.")))

(defclass domain-name ()
  ((name-labels
    :initarg :labels
    :initform (error "Must supply labels")
    :type list)))

(defmethod print-object ((domain-name domain-name) stream)
  (with-slots (name-labels) domain-name
    (print-unreadable-object (domain-name stream :type t)
      (format stream "~{~A~^.~}" name-labels)
      (format stream "."))))

(defun make-domain-name (name)
  (if (typep name 'domain-name)
      name
      (make-instance 'domain-name :labels (str:split "." name))))

;; TODO: implement different types of resource records using a class hierarchy
;;
(defclass resource-record ()
  ((name
    :initarg :name
    :initform  (error "Must supply a name")
    :type domain-name)
   (type
    :initarg :type
    :initform (error "Must supply a type")
    :type uint16)
   (class
    :initarg :class
    :initform (error "Must supply a class")
    :type uint16)
   (ttl
    :initarg :ttl
    :initform (error "Must supply a ttl")
    :type uint32)
   (rdata
    :initarg :rdata
    :initform (error "Must supply a rdata")
    :type (vector octet))))

(defun hex-string (vector &optional (stream *standard-output*))
  (format stream "~{0x~2,'0x~^ ~}" (coerce vector 'list)))

;;; Encoding of messages to bytes

(defun encode-to-vector (message)
  (fast-io:with-fast-output (buffer :vector)
    (encode-message message buffer)))

(defun decode-from-vector (vector)
  (fast-io:with-fast-input (buffer vector)
    (decode-message 'message buffer)))

(defgeneric encode-message (message buffer))
(defgeneric decode-message (type buffer))

(defmethod encode-message ((message message) buffer)
  (with-slots (header questions) message
    (encode-message header buffer)
    (when questions
      (loop :for question :across questions
            :do (encode-message question buffer)))))

(defmethod decode-message ((type (eql 'message)) buffer)
  (let ((header (decode-message 'message-header buffer)))
    (with-slots (qdcount ancount nscount arcount) header
      (let ((questions (loop :repeat qdcount :collect (decode-message 'message-question buffer)))
            (answers (loop :repeat ancount :collect (decode-message 'resource-record buffer)))
            (authorities (loop :repeat nscount :collect (decode-message 'resource-record buffer)))
            (additionals (loop :repeat arcount :collect (decode-message 'resource-record buffer))))
        (make-instance 'message
                       :header header
                       :questions questions
                       :answers answers
                       :authorities authorities
                       :additionals additionals)))))

(defmethod encode-message ((header message-header) buffer)
  (with-slots (id flags qdcount ancount nscount arcount) header
    (fast-io:writeu16-be id buffer)
    (fast-io:writeu16-be flags buffer)
    (fast-io:writeu16-be qdcount buffer)
    (fast-io:writeu16-be ancount buffer)
    (fast-io:writeu16-be nscount buffer)
    (fast-io:writeu16-be arcount buffer)))

(defmethod decode-message ((type (eql 'message-header)) buffer)
  (make-instance 'message-header
                 :id (fast-io:readu16-be buffer)
                 :flags (fast-io:readu16-be buffer)
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
                 :qname (decode-message 'domain-name buffer)
                 :qtype (fast-io:readu16-be buffer)
                 :qclass (fast-io:readu16-be buffer)))

(defmethod encode-message ((qname domain-name) buffer)
  (with-slots (name-labels) qname
    (loop :for label :in name-labels
          :do
             (fast-io:writeu8-be (length label) buffer)
             (loop :for char :across label :do (fast-io:writeu8-be (char-code char) buffer)))
    (fast-io:writeu8-be 0 buffer)))

(s:defconst +compression-mask+ #b11000000)
(s:defconst +decompression-mask+ #b00111111)

(defmethod decode-message ((type (eql 'domain-name)) buffer)
  (make-instance 'domain-name :labels (%decode-labels buffer)))

(defun %decode-labels (buffer)
  (loop :for len = (fast-io:fast-read-byte buffer :eof-error-p nil)
        :until (or (null len) (zerop len))
        :if (plusp (logand len +compression-mask+))
          :do (return-from %decode-labels (%decode-compressed-label len buffer))
        :else
          :collect (coerce (loop :repeat len :collect (code-char (fast-io:readu8-be buffer))) 'string)))

(defun %decode-compressed-label (length buffer)
  (let ((offset (+ (fast-io:readu8-be buffer) (logand length +decompression-mask+)))
        (current-position (fast-io:buffer-position buffer)))
    (setf (fast-io:buffer-position buffer) offset)
    (prog1 (%decode-labels buffer)
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
                   :rdata (loop :repeat rdlength :collect (fast-io:readu8-be buffer)))))

(defun build-query (domain-name &key (record-type +dns-type-a+) (record-class +dns-class-in+))
  "Build query message for the given domain name."
  (let* ((id (random (ash 1 16)))
         (want-recursion (ash 1 8))
         (flags want-recursion))
    (make-instance 'message
                   :header  (make-instance 'message-header :id id :flags flags :qdcount 1)
                   :questions
                   (vector (make-instance 'message-question :qname (make-domain-name domain-name) :qtype record-type :qclass record-class)))))

(s:defconst +dns-port+ 53)

(defclass nameserver ()
  ((ip-address
    :initarg :ip-address
    :initform (error "Must supply an ip-address"))
   (port
    :initarg :port
    :initform (error "Must supply a port"))))

(defmethod print-object ((nameserver nameserver) stream)
  (with-slots (ip-address port) nameserver
    (print-unreadable-object (nameserver stream :type t)
      (format stream "~A:~A" ip-address port))))

(defun make-nameserver (ip-address &optional (port +dns-port+))
  (make-instance 'nameserver :ip-address ip-address :port port))

(defclass resolver ()
  ((nameserver
    :initarg :nameserver
    :initform (error "Must supply a nameserver")
    :type nameserver)))

(defmethod print-object ((resolver resolver) stream)
  (with-slots (nameserver) resolver
    (print-unreadable-object (resolver stream :type t)
      (format stream "Nameserver: ~A" nameserver))))


(defun make-resolver (&key (nameserver  *default-nameserver*))
  (make-instance 'resolver :nameserver nameserver ))

(defparameter *default-nameserver* (make-nameserver "8.8.8.8"))
(defparameter *default-resolver* (make-resolver))

(defun resolve (domain-name &key (record-type +dns-type-a+) (record-class +dns-class-in+) (resolver *default-resolver*))
  (with-slots (nameserver) resolver
    (let ((query (build-query domain-name :record-type record-type :record-class record-class)))
      (a:when-let ((response (send-request nameserver query)))
        (decode-from-vector response)))))

(defun send-request (nameserver query)
  (with-slots (ip-address port) nameserver
    (let* ((socket (usocket:socket-connect ip-address port :protocol :datagram :element-type '(unsigned-byte 8)))
           (request-buffer (encode-to-vector query))
           (response-size 1024)
           (response-buffer (make-array response-size :element-type '(unsigned-byte 8))))
      (unwind-protect
           (progn
             (usocket:socket-send socket request-buffer (length request-buffer))
             (usocket:socket-receive socket response-buffer response-size))
        (usocket:socket-close socket)))))
