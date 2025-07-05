#lang racket/base

(require rackunit
         "../private/impl.rkt")

(module+ test
  (define p 101) ; Test prime
  (define a 7)
  (define P0 '(1 1))
  
  (test-case "Core functionality"
    (check-true (integer? (H 1 2 3 p)))
    (check-equal? (modulo (* (sqrt-mod 4 p) (sqrt-mod 4 p)) p) 4))
  
  (test-case "Full encryption/decryption cycle"
    (define-values (k Q) (keygen p a P0))
    (define m 42)
    (define-values (C1 C2 r) (encrypt m Q k p a P0))
    (define decrypted (decrypt C1 C2 k r a p))
    (check-equal? decrypted m)))
