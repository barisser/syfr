import copy
import hashlib

import crypto

DATA_BLOCK_SIZE = 65536

def encrypt_file(file_path):
    contents = open(file_path).read()
    content_blocks = divide_contents(contents)
    master_block = create_master_block()
    blocks = content_blocks + master_block
    return blocks

def divide_contents(contents):
    subcontents = []
    n = 0
    while n < len(contents):
        m = min(len(contents), n + DATA_BLOCK_SIZE - crypto.bitsize_marker_length)
        subcontent = contents[n:m]
        subcontent = crypto.long_pad(subcontent, DATA_BLOCK_SIZE)
        subcontents.append(subcontent)
        n += DATA_BLOCK_SIZE - crypto.bitsize_marker_length
    return subcontents

def unite_contents(content_blocks):
    content = ""
    for n, x in enumerate(content_blocks):
        content += crypto.long_unpad(x)

    return content

def compute_block_hash(block_dict):
    b = copy.deepcopy(block_dict)
    if 'id' in b:
        del b['id']
    s = str(hash(frozenset(block_dict)))
    return hashlib.sha256(s).hexdigest()

def decompose_metadata(metadata):
    sender, receiver = [x.split(':')[-1] for x in metadata.split(';')]
    return sender, receiver

def recompose_metadata(sender, receiver):
    # TODO remove this
    return "sender_pubkey:{0};receiver_pubkey:{1}".format(sender, receiver)

def encrypt_block(content, rsa_priv, receiver_pubkey):
    assert len(content) == DATA_BLOCK_SIZE
    aes_ciphertext, encry_aes_key, hmac, hmac_signature, iv, metadata = \
        crypto.encrypt(content, rsa_priv, receiver_pubkey)
    sender, receiver = decompose_metadata(metadata)
    response = {
                'aes_ciphertext': aes_ciphertext,
                'encry_aes_key': encry_aes_key,
                'hmac': hmac,
                'hmac_signature': hmac_signature,
                'iv': iv,
                'sender_public_key': sender,
                'receiver_public_key': receiver
                }
    response['id'] = compute_block_hash(list(response.iteritems()))
    return response

def full_decrypt_block(response, receiver_privkey):
    assert compute_block_hash(response) == response['id']


    return crypto.decrypt(
            response['aes_ciphertext'],
            response['encry_aes_key'],
            response['hmac'],
            response['hmac_signature'],
            receiver_privkey,
            response['iv'],
            recompose_metadata(
                response['sender_public_key'], response['receiver_public_key'])
        )

def aes_decrypt_block(response, aes_key):
    return

def create_master_block():
    return
