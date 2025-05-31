require "digest"
require_relative "laicrypto/version"

module Laicrypto
  class Error < StandardError; end

  # H(x, y, s, p) = SHA256(x || y || s) mod p
  def self.H(x, y, s, p)
    data      = "#{x}|#{y}|#{s}"
    digest    = Digest::SHA256.digest(data)
    digest_bn = digest.unpack1("H*").to_i(16)
    digest_bn % p
  end

  # mod_pow(base, exp, mod): base^exp mod mod (exponentiation by squaring)
  def self.mod_pow(base, exp, mod)
    result = 1
    b      = base % mod
    e      = exp

    while e > 0
      result = (result * b) % mod if (e & 1) != 0
      b = (b * b) % mod
      e >>= 1
    end

    result
  end

  # sqrt_mod(a, p): Tonelli–Shanks to find sqrt modulo p (p prime). Return nil if no root.
  def self.sqrt_mod(a, p)
    a = a % p
    return 0 if a == 0

    # Legendre symbol: a^((p-1)//2) mod p
    ls = mod_pow(a, (p - 1) / 2, p)
    return nil if ls == p - 1

    # Shortcut if p % 4 == 3
    if p % 4 == 3
      return mod_pow(a, (p + 1) / 4, p)
    end

    # Tonelli–Shanks for p ≡ 1 (mod 4)
    q = p - 1
    s = 0
    while (q & 1) == 0
      q >>= 1
      s += 1
    end

    # Find z: a quadratic non-residue
    z = 2
    while mod_pow(z, (p - 1) / 2, p) != p - 1
      z += 1
    end

    m = s
    c = mod_pow(z, q, p)
    t = mod_pow(a, q, p)
    r = mod_pow(a, (q + 1) / 2, p)

    loop do
      return r if t == 1
      # Find smallest i: t^(2^i) ≡ 1 (mod p)
      t2i = t
      i   = 0
      (1...m).each do |j|
        t2i = (t2i * t2i) % p
        if t2i == 1
          i = j
          break
        end
      end
      # Compute next values
      b = mod_pow(c, 1 << (m - i - 1), p)
      m = i
      c = (b * b) % p
      t = (t * c) % p
      r = (r * b) % p
    end
  end

  # T(point, s, a, p): transformation
  #   x' = (x + a + H(x,y,s)) * inv2 mod p
  #   y' = sqrt_mod(x*y + H(x,y,s), p)
  # If sqrt_mod returns nil, increment s (up to 10 tries)
  def self.T(point, s, a, p)
    x, y   = point
    inv2   = mod_pow(2, p - 2, p)  # modular inverse of 2 mod p
    trials = 0
    s_current = s

    while trials < 10
      h = H(x, y, s_current, p)
      x_candidate = ((x + a + h) * inv2) % p
      y_sq = (x * y + h) % p
      y_candidate = sqrt_mod(y_sq, p)
      return [x_candidate, y_candidate] unless y_candidate.nil?

      s_current += 1
      trials += 1
    end

    raise Error, "T: Gagal menemukan sqrt untuk y^2=#{y_sq} mod #{p} setelah #{trials} percobaan."
  end

  # _pow_T_range(P, start_s, exp, a, p): apply T iteratively exp times, starting seed = start_s
  def self._pow_T_range(P, start_s, exp, a, p)
    result = P.dup
    curr_s = start_s
    exp.times do
      result = T(result, curr_s, a, p)
      curr_s += 1
    end
    result
  end

  # keygen(p, a, P0) → { k: Integer, Q: [x,y] }
  def self.keygen(p, a, P0)
    loop do
      k_candidate = rand(1...p)
      begin
        Q = _pow_T_range(P0, 1, k_candidate, a, p)
        return { k: k_candidate, Q: Q }
      rescue Error
        next
      end
    end
  end

  # encrypt(m, public_Q, k, p, a, P0) → { C1: [x,y], C2: [x,y], r: Integer }
  def self.encrypt(m, public_Q, k, p, a, P0)
    loop do
      r = rand(1...p)
      # Compute C1 = T^r(P0) with seeds 1..r
      begin
        C1 = _pow_T_range(P0, 1, r, a, p)
      rescue Error
        next
      end

      # Compute Sr = T^r(public_Q) with seeds (k+1)..(k+r)
      begin
        Sr = _pow_T_range(public_Q, k + 1, r, a, p)
      rescue Error
        next
      end

      M0 = m % p
      M  = [ M0 < 0 ? M0 + p : M0, 0 ]
      C2 = [ (M[0] + Sr[0]) % p, (M[1] + Sr[1]) % p ]
      return { C1: C1, C2: C2, r: r }
    end
  end

  # decrypt(C1, C2, k, r, a, p) → Integer (original message)
  def self.decrypt(C1, C2, k, r, a, p)
    S  = _pow_T_range(C1, r + 1, k, a, p)
    M0 = (C2[0] - S[0]) % p
    M0 < 0 ? M0 + p : M0
  end
end
