(in-package #:dns)

(deftype uint16 () '(unsigned-byte 16))
(deftype uint32 () '(unsigned-byte 32))
(deftype octet ()  '(unsigned-byte 8))

(s:defconst +dns-qr-query+ 0)
(s:defconst +dns-qr-response+ 1)
(s:defconst +dns-opcode-query+ 0)
(s:defconst +dns-opcode-iquery+ 1)
(s:defconst +dns-opcode-status+ 2)

(defclass message ()
  ((header
    :initarg :header
    :initform (error "Must supply a header")
    :type message-header)
   (questions
    :initarg :questions
    :initform nil
    :type list)
   (answers
    :initarg :answers
    :initform nil
    :type list)
   (authorities
    :initarg :authorities
    :initform nil
    :type list)
   (additionals
    :initarg :additionals
    :initform nil
    :type list)))

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
    :type flags)
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

(defclass flags ()
  ((qr
    :initarg :qr
    :initform (error "Must supply a qr")
    :type (member +dns-qr-query+ +dns-qr-response+))
   (opcode
    :initarg :opcode
    :initform (error "Must supply an opcode")
    :type (member +dns-opcode-query+ +dns-opcode-iquery+ +dns-opcode-status+))
   (aa
    :initarg :aa
    :initform nil
    :type boolean)
   (tc
    :initarg :tc
    :initform nil
    :type boolean)
   (rd
    :initarg :rd
    :initform nil
    :type boolean)
   (ra
    :initarg :ra
    :initform nil
    :type boolean)
   (z
    :initarg :z
    :initform nil
    :type boolean)
   (ad
    :initarg :ad
    :initform nil
    :type boolean)
   (rcode
    :initarg :rcode
    :initform 0
    :type uint16)))

(defmethod print-object ((flags flags) stream)
  (with-slots (qr opcode aa tc rd ra z ad rcode) flags
    (print-unreadable-object (flags stream :type t)
      (format stream "QR: ~A~%OPCODE: ~A~%AA: ~A~%TC: ~A~%RD: ~A~%RA: ~A~%Z: ~A~%AD: ~A~%RCODE: ~A"
              qr opcode aa tc rd ra z ad rcode))))

(defun make-flags (&key (qr +dns-qr-query+) (opcode +dns-opcode-query+) (aa nil) (tc nil) (rd nil) (ra nil) (z nil) (ad nil) (rcode 0))
  (make-instance 'flags :qr qr :opcode opcode :aa aa :tc tc :rd rd :ra ra :z z :ad ad :rcode rcode))

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

(defun length-encoded-labels-to-domain-name (bytes)
  "Converts a sequence of bytes representing a length encoded domain name to a domain-name object."
  (fast-io:with-fast-input (buffer bytes)
    (loop :for len = (fast-io:fast-read-byte buffer nil nil)
          :until (or (null len) (zerop len))
          :collect (coerce (loop :repeat len :collect (code-char (fast-io:readu8-be buffer))) 'string) :into labels
          :finally (return (make-instance 'domain-name :labels labels)))))

(s:defconst +rr-types+
  (s:dict
   :a 1
   :ns 2
   :cname 5
   :soa 6
   :wks 11
   :ptr 12
   :hinfo 13
   :mx 15
   :txt 16
   :aaaa 28
   :srv 33
   :naptr 35
   :ds 43
   :rrsig 46))

(s:defconst +rr-class+ (s:dict :in 1 :cs 2 :ch 3 :hs 4 :any 255))

(deftype rr-type-t ()
  '(member :a :ns :cname :soa :wks :hinfo :mx :txt :aaaa :srv :ptr :naptr :ds :rrsig))

(deftype rr-class-t ()
  '(member :in :cs :ch :hs :any))

(-> rr-type (rr-type-t) fixnum)
(defun rr-type (tpe)
  (gethash tpe +rr-types+))

(-> rr-class (rr-class-t) fixnum)
(defun rr-class (cls)
  (gethash cls +rr-class+))

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

(defun authoritive-nameservers (message)
  (with-slots (authorities) message
    (loop :for rr :in authorities
          :when (= (slot-value rr 'type) (rr-type :ns))
            :collect (domain-name-string (length-encoded-labels-to-domain-name (slot-value rr 'rdata))))))
