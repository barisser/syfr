import base64
import hashlib
import math
import os

import loader

def test_divide_unite_contents():
    # random contents
    complexity = loader.DATA_BLOCK_SIZE * 100 # won't create exactly this length
    contents = base64.b64encode(os.urandom(complexity))
    size = len(contents)
    subcontents = loader.divide_contents(contents)
    assert len(subcontents) == math.ceil(float(size) / float(loader.DATA_BLOCK_SIZE))
    assert all([len(x) == loader.DATA_BLOCK_SIZE for x in subcontents])

    united = loader.unite_contents(subcontents)
    assert hashlib.sha256(united).hexdigest() == hashlib.sha256(contents).hexdigest()
