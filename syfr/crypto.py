import base64
import hashlib
import os

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.padding import PKCS7

def generate_rsa_priv(complexity=4096):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=complexity,
        backend=default_backend()
     )
    return private_key

def serialize_privkey(key, encrypted=False):
    return base64.b64encode(key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

def serialize_pubkey(pubkey):
    return base64.b64encode(pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

def load_pubkey(pubkey_text):
    return serialization.load_der_public_key(
        base64.b64decode(pubkey_text),
        backend=default_backend())

def write_key(key, file_path='mykey.pem'):
    with open(file_path, 'w+') as fh:
        fh.write(key)

def sign(message, key):
    signer = key.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    signer.update(message)
    return base64.b64encode(signer.finalize())

def verify_signature(signature, message, pubkey):
    verifier = pubkey.verifier(
        base64.b64decode(signature),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    verifier.update(message)
    try:
        verifier.verify()
        return True
    except cryptography.exceptions.InvalidSignature:
        print "Invalid Signature"
        return False

def rsa_encrypt(message, pubkey):
    ciphertext = pubkey.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()), # SHA1 is suspect
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return base64.b64encode(ciphertext)

def rsa_decrypt(ciphertext, key):
    plaintext = key.decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return plaintext

def create_aes_key(complexity=32):
    return base64.b64encode(os.urandom(complexity))

def create_hmac(key, message_list):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    message = "?".join([str(x) for x in message_list])
    h.update(message)
    return base64.b64encode(h.finalize())

def pad(message):
    padder = PKCS7(128).padder()
    padded_data = padder.update(message)
    padded_data += padder.finalize()
    return padded_data

def unpad(padded_data):
    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(padded_data)
    return data + unpadder.finalize()

def aes_encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(
            algorithms.AES(base64.b64decode(key)),
            modes.CBC(iv),
            backend=default_backend()
        )
    message = pad(message)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return base64.b64encode(ciphertext), base64.b64encode(iv)

def aes_decrypt(ciphertext, key, iv):
    cipher = Cipher(
            algorithms.AES(base64.b64decode(key)),
            modes.CBC(base64.b64decode(iv)),
            backend=default_backend()
        )
    decryptor = cipher.decryptor()
    padded = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
    return unpad(padded)

def encrypt(message, rsa_priv, recipient_rsa_pub):
    aes_key = create_aes_key()
    aes_ciphertext, iv = aes_encrypt(message, aes_key)
    hmac_key = hashlib.sha256(aes_key).hexdigest()
    sender_pubkey = serialize_pubkey(rsa_priv.public_key())
    receiver_pubkey = serialize_pubkey(recipient_rsa_pub)
    metadata = "sender_pubkey:{0};receiver_pubkey:{1}".format(sender_pubkey, receiver_pubkey)

    encry_aes_key = rsa_encrypt(aes_key, recipient_rsa_pub)

    hmac_list = [metadata, iv, aes_ciphertext, encry_aes_key]
    hmac = create_hmac(hmac_key, hmac_list)
    hmac_signature = sign(hmac, rsa_priv)

    return aes_ciphertext, encry_aes_key, hmac, hmac_signature, iv, metadata

def decrypt(aes_ciphertext, encry_aes_key, hmac, hmac_signature, rsa_priv, iv, metadata):
    aes_key = rsa_decrypt(encry_aes_key, rsa_priv)

    hmac_key = hashlib.sha256(aes_key).hexdigest()
    hmac_list = [metadata, iv, aes_ciphertext, encry_aes_key]
    independent_hmac = create_hmac(hmac_key, hmac_list)
    assert hmac == independent_hmac

    sender_pub, receiver_pub = [x.split(':')[-1] for x in metadata.split(';')]
    sender_pub = load_pubkey(sender_pub)
    assert verify_signature(hmac_signature, hmac, sender_pub)

    plaintext = aes_decrypt(aes_ciphertext, aes_key, iv)
    return plaintext
