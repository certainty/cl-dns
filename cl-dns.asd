(in-package :asdf-user)

(defsystem "cl-dns"
  :description "Just a playground for algorithms and datastrucuturesin lisp"
  :author "David Krentzlin <david.krentzlin@gmail.com>"
  :source-control (:git "https://github.com/certainty/cl-stuff.git")
  :serial t
  :pathname "src"
  :depends-on (:serapeum :alexandria :usocket :fast-io :str)
  :components
  ((:file "packages")
   (:file "dns")))
