(in-package #:dns)

(defun pp (message &optional (stream *standard-output*))
  "Prints the `message' in a human readable format, similar to the format used by the dig command, to the `stream'."
  (with-slots (header questions answers authorities additionals) message
    (print-header header stream)
    (terpri stream)
    (print-questions questions stream)
    (terpri stream)
    (print-answers answers "ANSWER" stream)
    (terpri stream)
    (print-answers authorities "AUTHORITY" stream)
    (terpri stream)
    (print-answers additionals "ADDITIONAL" stream)
    (terpri stream)))

(defun print-header (header &optional (stream *standard-output*))
  (with-slots (id flags qdcount ancount nscount arcount) header
    (with-slots (qr opcode aa tc rd ra z rcode) flags
      (format stream ";; ->>HEADER<<- opcode: ~a, status: ~a, id: ~a~%" opcode rcode id)
      (format stream ";; flags: ~{~a~^, ~}; QUERY: ~a, ANSWER: ~a, AUTHORITY: ~a, ADDITIONAL: ~a~%" (flag-list flags) qdcount ancount nscount arcount))))

(defun flag-list (flags)
  (with-slots (aa tc rd ra z ad) flags
    (let ((flags (list)))
      (when aa (push 'aa flags))
      (when tc (push 'tc flags))
      (when rd (push 'rd flags))
      (when ra (push 'ra flags))
      (when z (push 'z flags))
      (when ad (push 'ad flags))
      flags)))

(defun print-question (question &optional (stream *standard-output*))
  (with-slots (qname qtype qclass) question
    (format stream ";; ~20a ~8a ~8a~%" (domain-name-string qname) (record-class-name qclass) (type-name qtype))))

(defun print-questions (questions &optional (stream *standard-output*))
  (when questions
    (format stream ";; QUESTION SECTION:~%")
    (dolist (question questions)
      (print-question question stream))))

(defun print-answer (answer &optional (stream *standard-output*))
  (with-slots (name type class ttl rdata) answer
    (format stream ";; ~20a ~8a ~8a ~8a ~a~%" (domain-name-string name) (type-name type) (record-class-name class) ttl (rdata-string type rdata))))

(defun print-answers (answers section-name &optional (stream *standard-output*))
  (when answers
    (format stream ";; ~a SECTION:~%" section-name)
    (dolist (answer answers)
      (print-answer answer stream))))

(defun type-name (type)
  (s:select type
    (+rr-type-a+ "A")
    (+rr-type-ns+ "NS")
    (+rr-type-cname+ "CNAME")
    (+rr-type-soa+ "SOA")
    (+rr-type-ptr+ "PTR")
    (+rr-type-mx+ "MX")
    (+rr-type-txt+ "TXT")
    (+rr-type-aaaa+ "AAAA")
    (+rr-type-srv+ "SRV")
    (+rr-type-opt+ "OPT")
    (t (format nil "~a" type))))

(defun record-class-name (class)
  (s:select class
    (+rr-class-in+ "IN")
    (+rr-class-cs+ "CS")
    (+rr-class-ch+ "CH")
    (+rr-class-hs+ "HS")
    (+rr-class-none+ "NONE")
    (+rr-class-any+ "ANY")
    (t (format nil "~a" class))))

(defun domain-name-string (domain-name)
  (with-output-to-string (stream)
    (with-slots (name-labels) domain-name
      (dolist (label name-labels)
        (format stream "~a." label)))))

(defun rdata-string (type rdata)
  (with-output-to-string (stream)
    (s:select type
      (+rr-type-a+ (format stream "~{~a~^.~}" (loop :for label :across rdata :collect (format nil "~a" label))))
      (+rr-type-aaaa+ ;; format as ipv6 address
       (format stream "~{~a~^:~}" (loop :for label :across rdata :collect (format nil "~a" label))))
      (+rr-type-ns+ (format stream "~a" (domain-name-string (length-encoded-labels-to-domain-name rdata))))
      (+rr-type-cname+ (format stream "~a" (domain-name-string (length-encoded-labels-to-domain-name rdata))))
      (t (format stream "~a" rdata)))))
