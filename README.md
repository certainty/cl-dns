# DNS in common lisp 

My take on [Implement DNS in a weekend](https://implement-dns.wizardzines.com/)


## Usage

```common-lisp
(dns:pp (dns:query "example.com")) ; send a query and pretty print the result

(dns:resolve "example.com")  ; resolve with recursion on nameserver
(dns:resolve* "example.com") ; resolve with recursion on the client
```

