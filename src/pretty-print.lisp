(in-package #:cl-dns)

(defun pretty-print-message (message &optional (stream *standard-output*))
  "Prints the `message' in a human readable format to the `stream'.")
