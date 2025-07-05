#lang racket/base

(require rackunit
         "../private/impl.rkt")

(module+ test
  (define p 101) ; prime kecil untuk testing
  (define a 7)
  (define P0 '(1 1))
  
  (test-case "H function"
    (check-true (integer? (H 1 2 3 p))))
  
  (test-case "sqrt-mod"
    (check-equal? (sqrt-mod 0 p) 0)
    (check-equal? (modulo (* (sqrt-mod 4 p) (sqrt-mod 4 p)) p) 4))
  
  (test-case "Key generation and encryption/decryption"
    (define-values (k Q) (keygen p a P0))
    (define m 42)
    (define-values (C1 C2 r) (encrypt m Q k p a P0))
    (define decrypted (decrypt C1 C2 k r a p))
    (check-equal? decrypted m)))
