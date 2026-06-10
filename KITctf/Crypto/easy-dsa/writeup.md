# Easy DSA

**Category:** Crypto  
**Event:** GPN CTF 2026  

## Description

We connect to a Mongolian barbecue-themed ECDSA signing oracle running on the P-521 curve. The server lets us sign arbitrary "recipes," retrieve the public key, and claim the flag — but only if we present a valid signature on a message we haven't previously asked the server to sign. In other words, we need to forge a signature.

## Step 1: Gathering Data

The service exposes three commands: `sign <hex>`, `get pkey`, and `flag please`. We start by grabbing the public key and signing two arbitrary messages.

```
> get pkey
x: 2474698413378672...
y: 3174048597392106...

> sign 6e6f6f646c6573
s1: 0x56c8a3c058ecb5ae...
s2: 0x12ed6024fd2e9aa6...

> sign 62656566
s1: 0x1750400df6c09c4c...
s2: 0x406a4a20a9f6e917...
```

Two signatures and the public key — that's all we need. Now we look for what's broken in the signing implementation.

## Step 2: Identifying the Vulnerability — Small Nonces

Standard ECDSA security requires the per-signature nonce `k` to be a full-size random value (521 bits for P-521). The server's "secure" nonce generation does this:

```python
def secure_random(sk: ECC.EccKey, message: bytes) -> int:
    key_id = uuid3(secure_namespace, sk.export_key(format="PEM")).bytes   # 16 bytes
    msg_id = uuid3(secure_namespace, message).bytes                       # 16 bytes

    random_generator = sha256(key_id)
    random_generator.update(msg_id)

    return int.from_bytes(random_generator.digest()) % (int(sk._curve.order) - 1) + 1
```

The nonce is derived from `sha256(key_id || msg_id)`, which produces a **256-bit** output. After reduction modulo `n` (~2^521), the nonce `k` is at most 256 bits — less than half the size it should be. This is the classic **hidden number problem**: when nonces are biased (i.e., their upper bits are known to be zero), the private key can be recovered using lattice techniques.

## Step 3: Lattice Attack to Recover the Private Key

From the ECDSA signature equation `s = k^{-1}(z + r * d) mod n`, we can rearrange to express `k` in terms of the unknown private key `d`:

```
k = s^{-1} * z + s^{-1} * r * d  (mod n)
  = a + t * d                     (mod n)
```

where `a = s^{-1} * z mod n` and `t = s^{-1} * r mod n`.

With two signatures, we can eliminate `d` and get a single equation relating the two nonces:

```python
# From signature 1: k1 = a1 + t1*d (mod n)
# From signature 2: k2 = a2 + t2*d (mod n)
# Eliminate d:
u = t2 * pow(t1, -1, n) % n
A = (u * a1 - a2) % n
# Now: u*k1 - k2 ≡ A (mod n)
```

This means the lattice point `k1 * (u, 1) + j * (n, 0) = (A + k2, k1)` is close to the target `(A, 0)`, because both `k1` and `k2` are small (~256 bits) compared to `n` (~521 bits). This means we have a 2-dimensional problem. 

We set up a 2D lattice with basis vectors `(n, 0)` and `(u, 1)`. At first, we reach for LLL but, since there are so few unknown points and the spirit of a CTF is to learn, I looked for a new algorithm to reduce these points that is better scoped for these smaller-dimension problems.

Since our team competed under the "Organic" category, I wanted to lean as little on generative AI as possible. The rules of engagement allowed us to use LLMs as search engines. So, I asked Claude for algorithms geared toward smaller dimension problems, and it suggested the Gauss-Schmidt redcution and Babai's nearest plane algorithm. After reading some short papers about Gauss-Schmidt Reduction and Babai's Nearest Plane Algorithm, I felt that it was a viable path forward. Next step was to write it.

So after much trial and error I wrote the following to find the closest lattice point to `(A, 0)`:

```python
def rdiv(a, b):
    return round(a / b)

def babai_cvp(reduced_basis, target):
    b1, b2 = reduced_basis
    dot_b2_b1 = b2[0]*b1[0] + b2[1]*b1[1]
    dot_b1_b1 = b1[0]**2 + b1[1]**2
    b2s_0 = (b2[0] * dot_b1_b1 - dot_b2_b1 * b1[0]) / dot_b1_b1
    b2s_1 = (b2[1] * dot_b1_b1 - dot_b2_b1 * b1[1]) / dot_b1_b1
    dot_b2s = b2s_0**2 + b2s_1**2
    t = target
    c2 = round((t[0]*b2s_0 + t[1]*b2s_1) / dot_b2s)
    t = (t[0] - c2*b2[0], t[1] - c2*b2[1])
    c1 = rdiv(t[0]*b1[0] + t[1]*b1[1], dot_b1_b1)
    closest = (c1*b1[0] + c2*b2[0], c1*b1[1] + c2*b2[1])
    return closest
```
But this was failing due to float division rounding 521-bit integers to 64-bit integers. So, I use the fractions library which solved the rounding issue.

```python
from fractions import Fraction

def rdiv(a, b):
    return round(Fraction(a, b))

def gauss_reduce(v1, v2):
    while True:
        n1 = v1[0]**2 + v1[1]**2
        n2 = v2[0]**2 + v2[1]**2
        if n2 < n1:
            v1, v2 = v2, v1
            n1 = n2
        m = rdiv(v1[0]*v2[0] + v1[1]*v2[1], n1)
        if m == 0:
            return v1, v2
        v2 = (v2[0] - m*v1[0], v2[1] - m*v1[1])

def babai_cvp(reduced_basis, target):
    b1, b2 = reduced_basis
    dot_b2_b1 = b2[0]*b1[0] + b2[1]*b1[1]
    dot_b1_b1 = b1[0]**2 + b1[1]**2
    b2s_0 = Fraction(b2[0] * dot_b1_b1 - dot_b2_b1 * b1[0], dot_b1_b1)
    b2s_1 = Fraction(b2[1] * dot_b1_b1 - dot_b2_b1 * b1[1], dot_b1_b1)
    dot_b2s = b2s_0**2 + b2s_1**2
    t = target
    c2 = round((t[0]*b2s_0 + t[1]*b2s_1) / dot_b2s)
    t = (t[0] - c2*b2[0], t[1] - c2*b2[1])
    c1 = rdiv(t[0]*b1[0] + t[1]*b1[1], dot_b1_b1)
    closest = (c1*b1[0] + c2*b2[0], c1*b1[1] + c2*b2[1])
    return closest

v1, v2 = gauss_reduce((n, 0), (u, 1))
closest = babai_cvp((v1, v2), (A, 0))
k1 = abs(closest[1])
```

The second component of the closest vector gives us `k1`. From there, recovering the private key is straightforward:

```python
d = pow(t1, -1, n) * (k1 - a1) % n
# Verify against the public key
from Crypto.PublicKey import ECC
curve = ECC.generate(curve="p521")._curve
Q = int(d) * curve.G
assert int(Q.x) == pk_x and int(Q.y) == pk_y
```

## Step 4: Forging a Signature

With the private key `d` in hand, we forge a valid ECDSA signature on a message (and probably flavor) the server hasn't seen:

```python
forge_msg = b"cincinnati-chili"

e_forge = int.from_bytes(sha256(forge_msg).digest())
z_forge = e_forge & ~(1 << n.bit_length())

k_forge = secrets.randbelow(n - 1) + 1
P_forge = k_forge * curve.G
r_forge = int(P_forge.x) % n
s_forge = pow(k_forge, -1, n) * (z_forge + r_forge * d) % n
```

We submit the forged signature to the server:

```
> flag please
recipe (hex): 63696e63696e6e6174692d6368696c69
s1 (hex): <r_forge>
s2 (hex): <s_forge>
Congratulations. Here is your flag: GPNCTF{m4yb3_w3_sh0uld_us3_RFC_6979_n3xt_t1m3}

```

## Takeaway

ECDSA is extremely sensitive to nonce quality. Even when a nonce looks "random" (it's derived from SHA-256), if it's too short relative to the curve order, just two signatures are enough to recover the private key via a simple 2D lattice attack. The fix is to use a full-length nonce. RFC 6979 deterministic nonces, for example, would have prevented this entirely.
