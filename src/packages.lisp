(in-package #:cl-user)

(defpackage #:dns
  (:use :cl)
  (:local-nicknames (:a :alexandria) (:s :serapeum))
  (:import-from :serapeum :->))
