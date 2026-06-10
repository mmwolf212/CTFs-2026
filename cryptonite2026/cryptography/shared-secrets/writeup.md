# Shared Secrets: Writeup

## Overview

This challenge presents us with a classic RSA setup, but with a glaring vulnerability: the same plaintext message has been encrypted twice using two different public exponents under the same modulus. This is vulnerable to what is known as a Common Modulus Attack.

## Understanding the Challenge

Let's start by looking at what `chall.py` does:

```python
from Crypto.Util.number import *
from secret import flag

m = bytes_to_long(flag)

p = getPrime(1024)
q = getPrime(1024)

n = p * q

e1 = 65537
e2 = 65539

c1 = pow(m, e1, n)
c2 = pow(m, e2, n)
```

In normal RSA, you have a public key consisting of two values: a modulus `n` and an exponent `e`. A message `m` is encrypted by computing `c = m^e mod n`. Decryption normally requires knowing the private key, which depends on the prime factorization of `n`.

Here, the same message `m` is encrypted twice with two different exponents (`e1 = 65537` and `e2 = 65539`), but using the same modulus `n`. We are given both ciphertexts (`c1` and `c2`), both exponents, and the shared modulus. Since we cannot know `p` and `q`, we'll have to take a different approach. 

## The Vulnerability: Common Modulus Attack

The key insight is that `e1` and `e2` are coprime, meaning their greatest common divisor (gcd) is 1. You can verify this yourself: 65537 and 65539 share no common factors other than 1.

When two numbers are coprime, a result from number theory called Bezout's Identity guarantees that there exist integers `s1` and `s2` such that:

```
e1 * s1 + e2 * s2 = 1
```

We can find these integers using the Extended Euclidean Algorithm, which is a standard algorithm taught in most introductory number theory or cryptography courses. It extends the basic Euclidean Algorithm (which finds the gcd of two numbers) to also produce the coefficients `s1` and `s2`.

## Why This Lets Us Recover the Message

Once we have `s1` and `s2`, we can recover the original message without ever factoring `n`. Here is the math:

We know that:

```
c1 = m^e1 mod n
c2 = m^e2 mod n
```

If we compute `c1^s1 * c2^s2 mod n`, we get:

```
c1^s1 * c2^s2 = (m^e1)^s1 * (m^e2)^s2
              = m^(e1*s1) * m^(e2*s2)
              = m^(e1*s1 + e2*s2)
              = m^1
              = m
```

The message falls right out. No factoring required.

One small detail: one of `s1` or `s2` will be negative. Raising a number to a negative exponent modulo `n` means we need to compute the modular inverse of that ciphertext first. In Python 3.8 and later, this is as simple as calling `pow(c, -1, n)`.

## Solve Script

```python
from Crypto.Util.number import long_to_bytes

n = 15613484457778220039654980022958049872188444253536664521878299346186299690596318997570659826434425721731355370867138953213026989976743377142765504571260215527294553654271781118212391204159518990968596261295168948440228041082301965364441584458294798204816467467908512566839304154861242122515409061246841994536031227773267237489476565872647263855436518839434244445147544831375630611604780739609297263212880689033429083233944328446260315066792177513234981491811498730902716481483964992285351131375028474577146777612691751569767048371788903417264587467014081622284179248112287589493777512320561114613569144195800437234229
e1 = 65537
e2 = 65539
c1 = 9993101309645876502949976287351370837087212167463601135659111788912319726915093674009462120594008269989008925333217460421430203800047071767579752710054483432224346596053896659465738808575198886663715562845557687700402715816367297769270518664187091496291749035092716942598505777700905531276887268308717281893126466300494901891672682998412050742915841266547122291660915410868923631123588939260269452921830387151231234789601092989858662523545385249240016725050116847916335240805667958853225966905850197851020285337377665991491289079417071778155413318565685381549602247790265946594726923972917864945191029562424733812524
c2 = 1459990896005860319581605016387430715096561756375928594932709277269470162996773374417666359991498904474234027848805093551270183052672717877677016566803102633601483736045973272091574131607667228774747601427437246567833005924484611585275742766787330814784819766302018961967282308860312651304011031214767071494208834399731910492783951824755536020781340507015496313124672307894535740061398743388902728605193621115124288349678071989303084136247288974179307747576149265328334715814354203355283998097003259121570840175049215292066138969738944431506461055176325857467753743848408609930624101141775509515316985830281107115623

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x

_, s1, s2 = egcd(e1, e2)

# Handle negative exponents by using modular inverse
if s1 < 0:
    c1 = pow(c1, -1, n)
    s1 = -s1
if s2 < 0:
    c2 = pow(c2, -1, n)
    s2 = -s2

m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
print(long_to_bytes(m).decode())
```

## Flag

```
TACHYON{c0mm0n_m0dulu5_att4ck!}
```

## Conclusion

The lesson here is that in RSA, you should never encrypt the same message under different exponents using the same modulus. If an attacker obtains both ciphertexts, they can recover the plaintext without knowing the private key at all. This is why real-world RSA implementations use unique moduli for each key pair and apply padding schemes (like OAEP) that randomize the plaintext before encryption. TL;DR - Don't roll your own crypto.
