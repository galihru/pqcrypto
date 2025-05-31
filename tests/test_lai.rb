require "pqcrypto"

p = 23
a = 5
P0 = [3, 10]

result = PqcryptoLai.keygen(p, a, P0)
k = result[:k]
Q = result[:Q]
puts "k: #{k}, Q: #{Q.inspect}"

enc = PqcryptoLai.encrypt(7, Q, k, p, a, P0)
C1 = enc[:C1]
C2 = enc[:C2]
r = enc[:r]
puts "C1: #{C1.inspect}, C2: #{C2.inspect}, r: #{r}"

decrypted = PqcryptoLai.decrypt(C1, C2, k, r, a, p)
puts "Pesan asli: #{decrypted}"
