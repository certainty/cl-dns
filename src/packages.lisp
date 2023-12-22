(in-package #:cl-user)

(defpackage #:dns
  (:use :cl)
  (:local-nicknames (:a :alexandria) (:s :serapeum))
  (:import-from :serapeum :->)
  (:export
   #:*debug*
   #:resolve
   #:resolve*
   #:query
   #:*nameserver*
   #:*root-nameservers*
   #:root-nameserver
   #:make-nameserver
   #:authoritive-nameservers
   #:pp))
