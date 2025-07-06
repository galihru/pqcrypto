#lang racket/base

(require crypto crypto/libcrypto racket/random)

;; =============================================
;; Lemniscate-AGM Isogeny Cryptosystem (LAI-Crypto)
;; Post-Quantum Secure Encryption Scheme
;; Based on:
;; - Lemniscate Lattices
;; - Arithmetic-Geometric Mean (AGM) Transformations
;; - Isogeny-Based Cryptography
;; =============================================

(module+ test
  (require rackunit))

;; ---------------------------------------------
;; Core Cryptographic Primitives
;; ---------------------------------------------

(define (H x y s p)
  "Cryptographic hash function H(x,y,s) = SHA256(x||y||s) mod p
   Provides non-linear seeding for each iteration.
   
   Parameters:
   - x, y: Coordinates of current point
   - s: Iteration seed
   - p: Prime modulus
   
   Returns: Hash value modulo p"
  (define data (string-append (number->string x) "|" (number->string y) "|" (number->string s)))
  (define digest (sha256 (string->bytes/utf-8 data)))
  (modulo (bytes->integer digest) p))

(define (sqrt-mod a p)
  "Tonelli-Shanks algorithm for modular square roots
   Computes √a mod p where p is prime.
   
   Parameters:
   - a: Quadratic residue
   - p: Prime modulus
   
   Returns: #f if no solution exists, otherwise x where x² ≡ a mod p"
  (cond
    [(= (modulo a p) 0) 0]
    [else
     (define legendre (modular-expt a (quotient (- p 1) 2) p))
     (cond
       [(= legendre (- p 1)) #f]
       [(= (modulo p 4) 3) (modular-expt a (quotient (+ p 1) 4) p)]
       [else (tonelli-shanks a p)])]))

(define (tonelli-shanks a p)
  "Helper function for Tonelli-Shanks algorithm"
  (define (find-z)
    (for/first ([z (in-naturals 2)]
                #:when (= (modular-expt z (quotient (- p 1) 2) p) (- p 1)))
      z))
  
  (define-values (q s)
    (let loop ([q (- p 1)] [s 0])
      (if (even? q)
          (loop (quotient q 2) (+ s 1))
          (values q s))))
  
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
       (loop i (modulo (* b b) p) (modulo (* t b b) p) (modulo (* r b) p))]))

;; ---------------------------------------------
;; Lemniscate-AGM Transformation
;; ---------------------------------------------

(define (T point s a p #:max-trials [max-trials 10])
  "Lemniscate-AGM Transformation T(x,y;s)
   Core transformation function for the LAI cryptosystem.
   
   Parameters:
   - point: (list x y) coordinates
   - s: Transformation seed
   - a: Curve parameter
   - p: Prime modulus
   - #:max-trials: Maximum attempts for sqrt finding
   
   Returns: (list x' y') transformed coordinates
   Throws: ValueError if no sqrt found after max-trials"
  (match-define (list x y) point)
  (define inv2 (modular-inverse 2 p))
  
  (let loop ([s-current s] [trials 0])
    (when (>= trials max-trials)
      (error 'T "Failed to find sqrt after ~a trials" trials))
    
    (define h (H x y s-current p))
    (define x-candidate (modulo (* (+ x a h) inv2) p))
    (define y-sq (modulo (+ (* x y) h) p))
    (define y-candidate (sqrt-mod y-sq p))
    
    (if y-candidate
        (list x-candidate y-candidate)
        (loop (+ s-current 1) (+ trials 1)))))

;; ---------------------------------------------
;; Cryptographic Operations
;; ---------------------------------------------

(define (iterated-T P start-s exp a p)
  "Apply T transformation iteratively
   Parameters:
   - P: Initial point
   - start-s: Starting seed index
   - exp: Number of iterations
   - a, p: System parameters
   
   Returns: T^exp(P)"
  (for/fold ([result P])
            ([i (in-range exp)])
    (T result (+ start-s i) a p)))

(define (keygen p a P0)
  "Generate LAI cryptographic key pair
   Parameters:
   - p: Prime modulus
   - a: Curve parameter
   - P0: Base point
   
   Returns: (values private-key public-key)"
  (let loop ()
    (define k (+ (random p (- p 1)) 1))
    (with-handlers ([exn:fail? (λ (e) (loop))])
      (define Q (iterated-T P0 1 k a p))
      (values k Q))))

;; PERBAIKAN DI SINI: Kesalahan sintaks pada definisi C2
(define (encrypt m public-Q k p a P0)
  "LAI Encryption function
   Parameters:
   - m: Message (integer)
   - public-Q: Recipient's public key
   - k: Recipient's private key (for seed calculation)
   - p, a: System parameters
   - P0: Base point
   
   Returns: (values C1 C2 r) ciphertext components"
  (let loop ()
    (define r (+ (random p (- p 1)) 1))
    (with-handlers ([exn:fail? (λ (e) (loop))])
      (define C1 (iterated-T P0 1 r a p))
      (define Sr (iterated-T public-Q (+ k 1) r a p))
      (define M (list (modulo m p) 0))
      
      ;; PERBAIKAN: Sintaks yang benar untuk membuat list C2
      (define C2 (list 
                  (modulo (+ (first M) (first Sr)) p)
                  (modulo (+ (second M) (second Sr)) p)))
      
      (values C1 C2 r))))

(define (decrypt C1 C2 k r a p)
  "LAI Decryption function
   Parameters:
   - C1, C2: Ciphertext components
   - k: Recipient's private key
   - r: Randomness from encryption
   - a, p: System parameters
   
   Returns: Decrypted message"
  (define S (iterated-T C1 (+ r 1) k a p))
  (modulo (- (first C2) (first S)) p))

(provide
 H
 sqrt-mod
 T
 iterated-T
 keygen
 encrypt
 decrypt)
