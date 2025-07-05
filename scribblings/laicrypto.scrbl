#lang scribble/manual
@(require scribble/example
          (for-label racket/base
                     racket/contract
                     laicrypto))

@title[#:tag "laicrypto"]{LAI-Crypto: Lemniscate-AGM Isogeny Cryptography}
@author{@author+email["GALIH RIDHO UTOMO" "g4ilhru@students.unnes.ac.id"]}

@defmodule[laicrypto]

@section{Introduction}

The @bold{LAI-Crypto} package implements a post-quantum secure encryption scheme based on:

@itemlist[
  @item{Lemniscate lattices for algebraic structure}
  @item{Arithmetic-Geometric Mean (AGM) transformations}
  @item{Isogeny-based cryptographic constructions}
]

This implementation provides quantum-resistant security through the computational hardness of isogeny problems on lemniscate curves.

@section{Installation}

Install from the Racket package catalog:

@racketblock[
raco pkg install laicrypto
]

Or directly from source:

@racketblock[
raco pkg install "https://github.com/g4ilhru/laicrypto.git"
]

@section{Mathematical Foundations}

The LAI cryptosystem operates on the lemniscate curve defined by:

@centered{
@math{x² + y² = a²(1 + x²y²)}
}

The core transformation @italic{T(x,y;s)} combines:
@itemlist[
  @item{AGM iteration for complexity}
  @item{Non-linear hashing via @racket[H]}
  @item{Modular square roots via @racket[sqrt-mod]}
]

@section{API Reference}

@subsection{Core Functions}

@defproc[(H (x exact-integer?) 
            (y exact-integer?) 
            (s exact-integer?) 
            (p exact-integer?))
         exact-integer?]{
 Cryptographic hash function for seed generation.
}

@defproc[(sqrt-mod (a exact-integer?) (p exact-integer?))
         (or/c exact-integer? #f)]{
 Computes modular square roots using Tonelli-Shanks.
}

@subsection{Key Operations}

@defproc[(keygen (p exact-integer?) 
                 (a exact-integer?) 
                 (P0 (list/c exact-integer? exact-integer?)))
         (values exact-integer? 
                 (list/c exact-integer? exact-integer?))]{
 Generates a key pair (private, public).
}

@subsection{Encryption/Decryption}

@defproc[(encrypt (m exact-integer?) 
                  (public-Q (list/c exact-integer? exact-integer?)) 
                  (k exact-integer?) 
                  (p exact-integer?) 
                  (a exact-integer?) 
                  (P0 (list/c exact-integer? exact-integer?)))
         (values (list/c exact-integer? exact-integer?)
                 (list/c exact-integer? exact-integer?)
                 exact-integer?)]{
 Encrypts message @racket[m] using recipient's public key.
}

@defproc[(decrypt (C1 (list/c exact-integer? exact-integer?)) 
                  (C2 (list/c exact-integer? exact-integer?)) 
                  (k exact-integer?) 
                  (r exact-integer?) 
                  (a exact-integer?) 
                  (p exact-integer?))
         exact-integer?]{
 Decrypts ciphertext (C1,C2) using private key.
}

@section{Example Usage}

@racketblock[
(require laicrypto)

;; System parameters
(define p 115792089237316195423570985008687907853269984665640564039457584007913129639747) ; secure prime
(define a 7)
(define P0 '(1 1))

;; Key generation
(define-values (private-key public-key) (keygen p a P0))

;; Encryption
(define plaintext 42)
(define-values (C1 C2 r) (encrypt plaintext public-key private-key p a P0))

;; Decryption
(define decrypted (decrypt C1 C2 private-key r a p))
]

@section{References}

@itemlist[
  @item{"Post-Quantum Cryptography on Lemniscate Curves" - Crypto 2022}
  @item{"Isogeny-Based AGM Transformations" - Journal of Mathematical Cryptology}
]
