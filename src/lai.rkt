#lang racket

;; pqcrypto-lai: Lemniscate-AGM Isogeny (LAI) Encryption
;; Quantum-Resistant Cryptography via Lemniscate Lattices and AGM Transformations.

(provide H sqrt-mod T _pow-T-range keygen encrypt decrypt)

(require math/bigint
         racket/random
         racket/base
         crypto/sha2) ;; sha256

;; H(x, y, s, p) = SHA-256(x || y || s) mod p
(define (H x y s p)
  (define data-bytes (string->bytes/utf-8 (format "~a|~a|~a" x y s)))
  (define digest-bytes (sha256 data-bytes))
  (define digest-hex  (bytes->hex-string digest-bytes))
  (modulo (string->number digest-hex 16) p))

;; sqrt-mod: Tonelli–Shanks for p prime
(define (sqrt-mod a p)
  (define a-mod (modulo a p))
  (cond
    [(zero? a-mod) 0]
    [else
     ;; Legendre symbol
     (define ls (expmod a-mod (quotient (- p 1) 2) p))
     (when (= ls (- p 1))
       #f)
     (cond
       [(= (modulo p 4) 3)
        (expmod a-mod (quotient (+ p 1) 4) p)]
       [else
        ;; Tonelli–Shanks
        (define-values (q s)
          (let loop ([q0 (- p 1)] [s0 0])
            (if (even? q0)
                (loop (quotient q0 2) (add1 s0))
                (values q0 s0))))
        ;; find z non-residue
        (define z
          (for/first ([cand (in-naturals 2)]
                      #:when (= (expmod cand (quotient (- p 1) 2) p) (- p 1)))
            cand))
        (define c (expmod z q p))
        (define t (expmod a-mod q p))
        (define r (expmod a-mod (quotient (+ q 1) 2) p))
        (let loop-ts ([m s] [c c] [t t] [r r])
          (if (= t 1)
              r
              (let* ([i
                      (for/first ([j (in-range 1 m)]
                                  #:when (= (expmod t (expt 2 j) p) 1))
                        j)]
                     [b (expmod c (expt 2 (- m i 1)) p)]
                     [m-next i]
                     [c-next (modulo (expt b 2) p)]
                     [t-next (modulo (* t c-next) p)]
                     [r-next (modulo (* r b) p)])
                (loop-ts m-next c-next t-next r-next))))])]))

;; T: transformasi pada titik
(define (T point s a p)
  (define-values (x y) point)
  (define inv2 (expmod 2 (- p 2) p))
  (let loop ([trials 0] [s-cur s])
    (when (> trials 10)
      (error 'T
             (format "Gagal menemukan sqrt untuk y^2 mod p setelah ~a percobaan" trials)))
    (define h (H x y s-cur p))
    (define x-cand (modulo (* inv2 (+ x a h)) p))
    (define y2    (modulo (+ (* x y) h) p))
    (define y-cand (sqrt-mod y2 p))
    (if y-cand
        (values x-cand y-cand)
        (loop (add1 trials) (add1 s-cur)))))

;; _pow-T-range: aplikasikan T berulang
(define (_pow-T-range P start-s exp a p)
  (let loop ([res P] [s-cur start-s] [n exp])
    (if (zero? n)
        res
        (let-values ([(x y) (T res s-cur a p)])
          (loop (values x y) (add1 s-cur) (sub1 n))))))

;; keygen: generasi kunci (k, Q)
(define (keygen p a P0)
  (let recur ()
    (define k (+ 1 (random (sub1 p))))
    (with-handlers ([exn:fail? (lambda (_) (recur))])
      (define Q (_pow-T-range P0 1 k a p))
      (values k Q))))

;; encrypt: enkripsi pesan m
(define (encrypt m public-Q k p a P0)
  (let recur ()
    (define r (+ 1 (random (sub1 p))))
    (with-handlers ([exn:fail? (lambda (_) (recur))])
      (define C1 (_pow-T-range P0 1 r a p))
      (define Sr (_pow-T-range public-Q (+ k 1) r a p))
      (define M (cons (modulo m p) 0))
      (define C2 (cons (modulo (+ (car M) (car Sr)) p)
                       (modulo (+ (cdr M) (cdr Sr)) p)))
      (values C1 C2 r))))

;; decrypt: dekripsi C1, C2 dengan k, r
(define (decrypt C1 C2 k r a p)
  (define S (_pow-T-range C1 (+ r 1) k a p))
  (modulo (- (car C2) (car S)) p))
