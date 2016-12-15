# SYFR
Hybrid AES-RSA Encryption for Python

## Motivation
There needs to be a ready-made Hybrid Symmetric-Asymmetric
encryption solution in Python.  There are a lot of implementations
out there in which the cryptographic primitives are exposed, but no
pre-assembled, working solution is in place.  In the case of Hybrid
Encryption, it is easy to do the wrong thing with the right primitives.

Optional parameters on cryptographic parameters are a potential pitfall,
as well as the overall architecture of Hybrid Encryption.  Do sensible things
in the wrong order, like encrypt-then-sign, or encrypt-then-mac, and
potential attacks become available to adversaries.  This library aims to
simply do the *right* things up front, providing a minimum of fuss
for end users.

## Design Principles
- Simplicity
- Ease of Use
- Reinvent nothing.  Reuse known-good cryptographic tools.
- Make safe choices for the user ahead of time.

## Disclaimer

This is a personal project and should not be considered *safe*.  It has not
been reviewed.  It has not survived out in the wild for any length of time.
It may have glaring flaws.  *Use at your own risk.*

The primitives are taken from Python's cryptography library.  While they may
have their own security issues, they are much more thoroughly vetted.

## How it works at a high level.
- Encrypt arbitrary data using symmetric AES key encryption.  This is a fast operation.  The AES ciphertext is published.
- Handling the AES symmetric key is the tricky part.  The sender encrypts
the AES key with the RSA public key of the intended recipient.  This is published.
- To ensure integrity and to prevent 'Surreptitious Forwarding', an HMAC is
produced with the published data, including the public keys of the sender and
recipient.  Including this sender/receiver metadata in the HMAC prevents 'Surreptitious Forwarding' and makes encrypt-then-sign acceptable.  The resulting HMAC is RSA signed by the sender and published.  

## Some Cryptographic Concerns

- Data Authentication (HMAC)
- Entity Authentication (RSA Signatures)
- Prevent Surreptitious Forwarding (Metadata in signed HMAC)
- Replay attacks (IV tracking)
