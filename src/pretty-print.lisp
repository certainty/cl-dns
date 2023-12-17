(in-package #:cl-dns)

(defun pretty-print-message (message &optional (stream *standard-output*))
  "Prints the `message' in a human readable format, similar to the format used by the dig command, to the `stream'."
  (with-slots (header questions answers authorities additionals) message
    (print-header header stream)
    (terpri stream)
    (print-questions questions stream)
    (terpri stream)
    (print-answers answers stream)
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

(defun print-answers (answers &optional (stream *standard-output*))
  (when answers
    (format stream ";; ANSWER SECTION:~%")
    (dolist (answer answers)
      (print-answer answer stream))))

(defun type-name (type)
  (case type
    (1 "A")
    (2 "NS")
    (5 "CNAME")
    (6 "SOA")
    (12 "PTR")
    (15 "MX")
    (16 "TXT")
    (28 "AAAA")
    (33 "SRV")
    (41 "OPT")
    (else (format nil "~a" type))))

(defun record-class-name (class)
  (case class
    (1 "IN")
    (2 "CS")
    (3 "CH")
    (4 "HS")
    (255 "ANY")
    (else (format nil "~a" class))))

(defun domain-name-string (domain-name)
  (with-output-to-string (stream)
    (with-slots (name-labels) domain-name
      (dolist (label name-labels)
        (format stream "~a." label)))))

(defun rdata-string (type rdata)
  (with-output-to-string (stream)
    (if (eq type 1)
        (format stream "~a" (format nil "~{~a~^.~}" rdata))
        (format stream "~a" (rdata-generic-string rdata)))))

(defun rdata-generic-string (rdata)
  (coerce (mapcar #'char-code rdata) 'string))
