(in-package #:dns)

(defparameter *debug* nil)

(defun debug-print (format-string &rest args)
  (when *debug*
    (format *debug-io* "DEBUG: ~A~%" (apply #'format nil format-string args))))

(defclass nameserver ()
  ((ip-address
    :initarg :ip-address
    :initform (error "Must supply an ip-address")
    :type string)
   (port
    :initarg :port
    :initform 53
    :type fixnum)))

(defmethod print-object ((nameserver nameserver) stream)
  (with-slots (ip-address port) nameserver
    (print-unreadable-object (nameserver stream :type t :identity nil)
      (format stream "~A:~A" ip-address port))))

(defun make-nameserver (ip-address &optional (port 53))
  (make-instance 'nameserver :ip-address ip-address :port port))

(defparameter *nameserver* (make-nameserver "8.8.8.8"))

(defparameter *root-nameservers*
  (list (make-nameserver "198.41.0.4" 53)
        (make-nameserver "192.58.128.30" 53)
        (make-nameserver "192.36.148.17" 53)))

(defun root-nameserver ()
  (nth (random (length *root-nameservers*)) *root-nameservers*))

(defun query (domain-name &key (type :a) (class :in) (recurse nil) (nameserver *nameserver*))
  "Queries the `domain-name' using `nameserver', which defaults to `"
  (send-query nameserver domain-name type class :recurse recurse))

(defun resolve (domain-name &key (nameserver *nameserver*))
  "Resolves the `domain-name' and returns the IP address as a string.
   You can specify the `record-type' and `record-class' to query for."
  (let ((response (query domain-name :type :a :class :in :recurse t :nameserver nameserver)))
    (find-a-record response domain-name)))

(defun resolve* (domain-name &key (root (root-nameserver)))
  "Recursively resolves the `domain-name' and returns the IP address as a string.
   You can specify the `record-type' and `record-class' to query for."
  (let ((ns root))
    (debug-print "resolving ~a with nameserver ~a" domain-name ns)
    (loop
      (let ((response (query domain-name :type :a :class :in :recurse nil :nameserver ns)))
        (unless response
          (return nil))
        (a:when-let ((answer (find-a-record response domain-name)))
          (debug-print "found answer ~a" answer)
          (return answer))
        (debug-print "nameserver didn't know the anser")
        (let ((next-ns (next-nameserver-ip response)))
          (unless next-ns
            (debug-print "no next nameserver")
            (return nil))
          (debug-print "next nameserver ~a" next-ns)
          (setf ns (make-nameserver next-ns)))))))

(defun next-nameserver-ip (response)
  ;; the next nameserver to ask is either the first a record in the additionals section
  ;; or we need to grab the name of the first nameserver in the authority section and resolve it recursively
  (debug-print "looking for next nameserver in response")
  (with-slots (additionals authorities) response
    (a:when-let ((ns (find-if (lambda (record) (= (slot-value record 'type) (rr-type :a))) additionals)))
      (debug-print "found next nameserver in additionals section")
      (return-from next-nameserver-ip (dotted-quad (slot-value ns 'rdata))))

    (a:when-let ((ns (first authorities)))
      (debug-print "found next nameserver in authorities section")
      (let ((ns-domain-name (domain-name-string (length-encoded-labels-to-domain-name (slot-value ns 'rdata)))))
        (resolve* ns-domain-name)))))

(defun find-a-record (response domain-name)
  (with-slots (answers) response
    (a:when-let ((answer (find-if (lambda (answer)
                                    (and
                                     (= (slot-value answer 'type) (rr-type :a))
                                     (string= (domain-name-string (slot-value answer 'name)) (absolute-domain-name domain-name))))
                                  answers)))
      (dotted-quad (slot-value answer 'rdata)))))

(defun dotted-quad (rdata)
  (format nil "~{~a~^.~}" (loop :for quad :across rdata :collect quad)))

(defun absolute-domain-name (domain-name)
  "Appends a trailing dot to the domain name if it doesn't already have one."
  (let ((last-char (char domain-name (1- (length domain-name)))))
    (unless (char= last-char #\.)
      (concatenate 'string domain-name "."))))

(defun send-query (nameserver domain-name record-type record-class &key (recurse nil))
  (let ((query (build-query domain-name record-type record-class :recurse recurse)))
    (a:when-let ((response (send-request query nameserver)))
      (debug-print "received response ~a" response)
      (decode-from-vector response))))

(defun build-query (domain-name record-type record-class &key (recurse nil))
  "Build query message for the given domain name."
  (let* ((id        (random (ash 1 16)))
         (flags     (make-flags :rd recurse))
         (header    (make-instance 'message-header :id id :flags flags :qdcount 1))
         (questions (list (make-instance 'message-question :qname (make-domain-name domain-name) :qtype (rr-type record-type) :qclass (rr-class record-class)))))
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
      (debug-print "sending request ~a" request-buffer)
      (unwind-protect
           (progn
             (usocket:socket-send socket request-buffer (length request-buffer))
             (usocket:socket-receive socket response-buffer response-size))
        (usocket:socket-close socket)))))
