import pytest
from pqcrypto.lai import keygen, encrypt, decrypt

@pytest.mark.parametrize("p,a,P0", [
    (10007, 5, (1, 0)),
])
def test_lai_roundtrip(p, a, P0):
    # generate key
    k, Q = keygen(p, a, P0)
    # enkripsi
    m = 1234
    C1, C2 = encrypt(m, Q, p, a, P0)
    # dekripsi
    m2 = decrypt(C1, C2, k, a, p)
    assert m2 == m
