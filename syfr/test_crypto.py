import crypto

def test_rsa_encrypt_and_decrypt():
    priv = crypto.generate_rsa_priv(complexity=512)
    message = "Attack at Calais"
    ciphertext = crypto.rsa_encrypt(message, priv.public_key())
    assert crypto.rsa_decrypt(ciphertext, priv) == message

def test_aes_encrypt_decrypt():
    priv = crypto.create_aes_key()
    message = "Sell Watermelons"
    ciphertext, iv = crypto.aes_encrypt(message, priv)
    assert crypto.aes_decrypt(ciphertext, priv, iv) == message

def test_full_encrypt():
    priv1 = crypto.generate_rsa_priv()
    priv2 = crypto.generate_rsa_priv()
    message = "Santa is not real."

    aes_ciphertext, encry_aes_key, hmac, hmac_signature, iv, metadata = \
        crypto.encrypt(message, priv1, priv2.public_key())

    aes_key = crypto.rsa_decrypt(encry_aes_key, priv2)

    assert crypto.aes_decrypt(aes_ciphertext, aes_key, iv) == message

    assert message == \
        crypto.decrypt(
                aes_ciphertext, encry_aes_key, hmac, hmac_signature,
                priv2, iv, metadata
            )

def test_sign():
    priv = crypto.generate_rsa_priv(complexity=512)
    message = "Secret wish list"
    sig = crypto.sign(message, priv)
    assert crypto.verify_signature(sig, message, priv.public_key())
