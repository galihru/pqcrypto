#lang scribble/manual

@title{Lemniscate-AGM Isogeny (LAI) Encryption}
@author{GALIH RIDHO UTOMO}

@defmodule[laicrypto]

Quantum-Resistant Cryptography via Lemniscate Lattices and AGM Transformations.

@section{Functions}

@defproc[(H [x integer?] [y integer?] [s integer?] [p integer?]) integer?]{
 Non-linear seed untuk setiap iterasi.
}

@defproc[(sqrt-mod [a integer?] [p integer?]) (or/c integer? #f)]{
 Hitung akar kuadrat modulo p (p prime) menggunakan Tonelli–Shanks.
}

@defproc[(T [point (list/c integer? integer?)] 
            [s integer?] 
            [a integer?] 
            [p integer?]
            [#:max-trials max-trials exact-positive-integer? 10]) 
         (list/c integer? integer?)]{
 Transformasi T(x, y; s).
}

@defproc[(keygen [p integer?] 
                 [a integer?] 
                 [P0 (list/c integer? integer?)]) 
         (values integer? (list/c integer? integer?))]{
 Generasi kunci.
}

@defproc[(encrypt [m integer?] 
                  [public-Q (list/c integer? integer?)] 
                  [k integer?] 
                  [p integer?] 
                  [a integer?] 
                  [P0 (list/c integer? integer?)]) 
         (values (list/c integer? integer?) 
                 (list/c integer? integer?) 
                 integer?)]{
 Enkripsi pesan.
}

@defproc[(decrypt [C1 (list/c integer? integer?)] 
                  [C2 (list/c integer? integer?)] 
                  [k integer?] 
                  [r integer?] 
                  [a integer?] 
                  [p integer?]) 
         integer?]{
 Dekripsi pesan.
}
