#lang racket/base

(require crypto crypto/libcrypto racket/random)

(module+ test
  (require rackunit))

;; ========== Fungsi Utama ==========

;; H(x, y, s, p) = SHA-256(x || y || s) mod p
(define (H x y s p)
  (define data (string-append (number->string x) "|" (number->string y) "|" (number->string s)))
  (define digest (sha256 (string->bytes/utf-8 data)))
  (modulo (bytes->integer digest) p))

;; Tonelli-Shanks algorithm for square roots modulo a prime
(define (sqrt-mod a p)
  (cond
    [(= (modulo a p) 0) 0]
    [else
     (define legendre (modular-expt a (quotient (- p 1) 2) p))
     (cond
       [(= legendre (- p 1)) #f] ; no square root exists
       [(= (modulo p 4) 3) (modular-expt a (quotient (+ p 1) 4) p)]
       [else (tonelli-shanks a p)])]))

(define (tonelli-shanks a p)
  (define (find-z)
    (for/first ([z (in-naturals 2)]
                #:when (= (modular-expt z (quotient (- p 1) 2) p) (- p 1)))
      z))
  
  (define q (- p 1))
  (define s 0)
  (let loop ()
    (when (even? q)
      (set! q (quotient q 2))
      (set! s (+ s 1))
      (loop)))
  
  (define z (find-z))
  (define c (modular-expt z q p))
  (define t (modular-expt a q p))
  (define r (modular-expt a (quotient (+ q 1) 2) p))
  
  (let loop ([m s] [c c] [t t] [r r])
    (cond
      [(= t 1) r]
      [else
       (define i
         (for/first ([i (in-range 1 m)]
                     #:when (= (modular-expt t (expt 2 i) p) 1))
           i))
       
       (define b (modular-expt c (expt 2 (- m i 1)) p))
       (define new-c (modulo (* b b) p))
       (define new-t (modulo (* t new-c) p))
       (define new-r (modulo (* r b) p))
       
       (loop i new-c new-t new-r)])))

;; Transformasi T
(define (T point s a p [max-trials 10])
  (match-define (list x y) point)
  (define inv2 (modular-inverse 2 p))
  
  (let loop ([s-current s] [trials 0])
    (when (>= trials max-trials)
      (error 'T "Gagal menemukan sqrt setelah ~a percobaan" trials))
    
    (define h (H x y s-current p))
    (define x-candidate (modulo (* (+ x a h) inv2) p))
    (define y-sq (modulo (+ (* x y) h) p))
    (define y-candidate (sqrt-mod y-sq p))
    
    (if y-candidate
        (list x-candidate y-candidate)
        (loop (+ s-current 1) (+ trials 1)))))

;; Aplikasi T berurutan
(define (_pow-T-range P start-s exp a p)
  (for/fold ([result P])
            ([i (in-range exp)])
    (T result (+ start-s i) a p)))

;; Key generation
(define (keygen p a P0)
  (let loop ()
    (define k (+ (random p (- p 1)) 1))
    (with-handlers ([exn:fail? (λ (e) (loop))])
      (define Q (_pow-T-range P0 1 k a p))
      (values k Q))))

;; Enkripsi
(define (encrypt m public-Q k p a P0)
  (let loop ()
    (define r (+ (random p (- p 1)) 1))
    (with-handlers ([exn:fail? (λ (e) (loop))])
      (define C1 (_pow-T-range P0 1 r a p))
      (define Sr (_pow-T-range public-Q (+ k 1) r a p))
      (define M (list (modulo m p) 0))
      (define C2 (list (modulo (+ (first M) (first Sr)) p)
                       (modulo (+ (second M) (second Sr)) p)))
      (values C1 C2 r))))

;; Dekripsi
(define (decrypt C1 C2 k r a p)
  (define S (_pow-T-range C1 (+ r 1) k a p))
  (modulo (- (first C2) (first S)) p))

;; ========== Ekspor Fungsi ==========
(provide
 H
 sqrt-mod
 T
 _pow-T-range
 keygen
 encrypt
 decrypt)
