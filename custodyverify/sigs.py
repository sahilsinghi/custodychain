"""Signature verification written from the specifications, standard library only.

* Ed25519 - RFC 8032 section 5.1.7 (extended twisted Edwards coordinates)
* RSA     - RFC 8017 RSASSA-PKCS1-v1_5 and RSASSA-PSS
* ECDSA   - FIPS 186-4 / SEC 1 on P-256, P-384 and P-521 (Jacobian coordinates)

Verification only: no secrets are handled, so constant-time arithmetic is
not required. Cross-checked against ``cryptography`` in the test suite.
"""

from __future__ import annotations

import hashlib

# --------------------------------------------------------------------------
# Ed25519
# --------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _ed_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % _P
    bb = (y1 + x1) * (y2 + x2) % _P
    cc = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ed_mul(s: int, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _ed_add(q, pt)
        pt = _ed_add(pt, pt)
        s >>= 1
    return q


def _ed_equal(a, b) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _ed_recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _ed_decode(data: bytes):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _ed_recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _ed_decode(public)
    r = _ed_decode(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    return _ed_equal(_ed_mul(s, _G), _ed_add(r, _ed_mul(k, a)))


# --------------------------------------------------------------------------
# RSA
# --------------------------------------------------------------------------

_DIGEST_INFO_PREFIX = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def rsa_pkcs1v15_verify(n: int, e: int, message: bytes, signature: bytes, hash_name: str) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    digest = hashlib.new(hash_name, message).digest()
    t = _DIGEST_INFO_PREFIX[hash_name] + digest
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return em == expected


def _mgf1(seed: bytes, length: int, hash_name: str) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.new(hash_name, seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def rsa_pss_verify(n: int, e: int, message: bytes, signature: bytes, hash_name: str, salt_len: int,
                   mgf_hash: str | None = None) -> bool:
    mod_bits = n.bit_length()
    k = (mod_bits + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em_bits = mod_bits - 1
    em_len = (em_bits + 7) // 8
    em = pow(s, e, n).to_bytes(k, "big")[-em_len:]
    m_hash = hashlib.new(hash_name, message).digest()
    h_len = len(m_hash)
    if em_len < h_len + salt_len + 2 or em[-1] != 0xBC:
        return False
    masked_db, h = em[: em_len - h_len - 1], em[em_len - h_len - 1: -1]
    zero_bits = 8 * em_len - em_bits
    if zero_bits and masked_db[0] >> (8 - zero_bits):
        return False
    db = bytes(a ^ b for a, b in zip(masked_db, _mgf1(h, len(masked_db), mgf_hash or hash_name)))
    db = bytes([db[0] & (0xFF >> (8 * em_len - em_bits))]) + db[1:]
    pad = em_len - h_len - salt_len - 2
    if db[:pad] != b"\x00" * pad or db[pad] != 0x01:
        return False
    salt = db[len(db) - salt_len:] if salt_len else b""
    return hashlib.new(hash_name, b"\x00" * 8 + m_hash + salt).digest() == h


# --------------------------------------------------------------------------
# ECDSA over NIST prime curves
# --------------------------------------------------------------------------

class Curve:
    def __init__(self, name, p, a, b, gx, gy, n):
        self.name, self.p, self.a, self.b, self.g, self.n = name, p, a, b, (gx, gy), n
        self.size = (p.bit_length() + 7) // 8


CURVES = {
    "1.2.840.10045.3.1.7": Curve(
        "P-256",
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        -3,
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    ),
    "1.3.132.0.34": Curve(
        "P-384",
        int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16),
        -3,
        int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16),
        int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
        int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
        int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16),
    ),
    "1.3.132.0.35": Curve(
        "P-521",
        2**521 - 1,
        -3,
        int("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16),
        int("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
        int("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16),
        # group order n (decimal form from FIPS 186-4 D.1.2.5; n*G = O is checked in the tests)
        6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449,
    ),
}


def _jac_double(pt, c: Curve):
    x, y, z = pt
    if y == 0 or z == 0:
        return (0, 1, 0)
    p = c.p
    ysq = y * y % p
    s = 4 * x * ysq % p
    zz = z * z % p
    m = (3 * x * x + c.a * zz * zz) % p
    nx = (m * m - 2 * s) % p
    ny = (m * (s - nx) - 8 * ysq * ysq) % p
    nz = 2 * y * z % p
    return (nx, ny, nz)


def _jac_add(a, b, c: Curve):
    if a[2] == 0:
        return b
    if b[2] == 0:
        return a
    p = c.p
    z1z1, z2z2 = a[2] * a[2] % p, b[2] * b[2] % p
    u1, u2 = a[0] * z2z2 % p, b[0] * z1z1 % p
    s1, s2 = a[1] * b[2] * z2z2 % p, b[1] * a[2] * z1z1 % p
    if u1 == u2:
        return _jac_double(a, c) if s1 == s2 else (0, 1, 0)
    h, r = (u2 - u1) % p, (s2 - s1) % p
    hh = h * h % p
    hhh = h * hh % p
    v = u1 * hh % p
    nx = (r * r - hhh - 2 * v) % p
    ny = (r * (v - nx) - s1 * hhh) % p
    nz = h * a[2] * b[2] % p
    return (nx, ny, nz)


def _jac_mul(k: int, pt, c: Curve):
    q = (0, 1, 0)
    for bit in bin(k)[2:]:
        q = _jac_double(q, c)
        if bit == "1":
            q = _jac_add(q, pt, c)
    return q


def _to_affine(pt, c: Curve):
    if pt[2] == 0:
        return None
    zinv = pow(pt[2], c.p - 2, c.p)
    z2 = zinv * zinv % c.p
    return (pt[0] * z2 % c.p, pt[1] * z2 * zinv % c.p)


def ec_point(curve: Curve, data: bytes) -> tuple[int, int] | None:
    if data[:1] == b"\x04" and len(data) == 1 + 2 * curve.size:
        x = int.from_bytes(data[1:1 + curve.size], "big")
        y = int.from_bytes(data[1 + curve.size:], "big")
    elif data[:1] in (b"\x02", b"\x03") and len(data) == 1 + curve.size:
        x = int.from_bytes(data[1:], "big")
        rhs = (pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p
        y = pow(rhs, (curve.p + 1) // 4, curve.p)  # all three curves have p = 3 mod 4
        if (y & 1) != (data[0] & 1):
            y = curve.p - y
    else:
        return None
    if (y * y - (pow(x, 3, curve.p) + curve.a * x + curve.b)) % curve.p != 0:
        return None
    return (x, y)


def ecdsa_verify(curve: Curve, point: tuple[int, int], message: bytes, r: int, s: int, hash_name: str) -> bool:
    n = curve.n
    if not (0 < r < n and 0 < s < n):
        return False
    digest = hashlib.new(hash_name, message).digest()
    e = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - n.bit_length()
    if excess > 0:
        e >>= excess
    w = pow(s, n - 2, n)
    u1, u2 = e * w % n, r * w % n
    g = (curve.g[0], curve.g[1], 1)
    q = (point[0], point[1], 1)
    x = _to_affine(_jac_add(_jac_mul(u1, g, curve), _jac_mul(u2, q, curve), curve), curve)
    return x is not None and x[0] % n == r
