(in-package #:dns)

(defclass nameserver ()
  ((ip-address
    :initarg :ip-address
    :initform (error "Must supply an ip-address")
    :type string)
   (port
    :initarg :port
    :initform 53
    :type fixnum)))

(defun make-nameserver (ip-address port)
  (make-instance 'nameserver :ip-address ip-address :port port))

(defparameter *nameserver* (make-nameserver "8.8.8.8" 53))

(defun resolve (domain-name &key (record-type +dns-type-a+) (record-class +dns-class-in+) (nameserver *nameserver*))
  "Resolves the `domain-name' using `nameserver', which defaults to `8.8.8.8'.
   You can specify the `record-type' and `record-class' to query for.
  "
  (let ((query (build-query domain-name :record-type record-type :record-class record-class)))
    (a:when-let ((response (send-request query nameserver)))
      (decode-from-vector response))))

(defun build-query (domain-name &key (record-type +dns-type-a+) (record-class +dns-class-in+))
  "Build query message for the given domain name."
  (let* ((id        (random (ash 1 16)))
         (flags     (make-flags :rd nil))
         (header    (make-instance 'message-header :id id :flags flags :qdcount 1))
         (questions (list (make-instance 'message-question :qname (make-domain-name domain-name) :qtype record-type :qclass record-class))))
    (make-instance
     'message
     :header header
     :questions questions)))

(defun send-request (query nameserver)
  (with-slots (ip-address port) nameserver
    (let* ((socket (usocket:socket-connect ip-address port :protocol :datagram :element-type 'octet))
           (request-buffer (encode-to-vector query))
           (response-size 512)
           (response-buffer (make-array response-size :element-type 'octet)))
      (unwind-protect
           (progn
             (usocket:socket-send socket request-buffer (length request-buffer))
             (usocket:socket-receive socket response-buffer response-size))
        (usocket:socket-close socket)))))
