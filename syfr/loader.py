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

def create_master_block():
    return
