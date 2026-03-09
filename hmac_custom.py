from SHA_256 import sha256

BLOCK_SIZE = 64  


def hmac_sha256(key: bytes, message: bytes):

    if isinstance(message, str):
        message = message.encode()

    if len(key) > BLOCK_SIZE:
        key = bytes.fromhex(sha256(key))

    if len(key) < BLOCK_SIZE:
        key = key + b'\x00' * (BLOCK_SIZE - len(key))

    ipad = bytes([0x36] * BLOCK_SIZE)
    opad = bytes([0x5c] * BLOCK_SIZE)

    k_ipad = bytes([k ^ i for k, i in zip(key, ipad)])
    k_opad = bytes([k ^ o for k, o in zip(key, opad)])

    inner = bytes.fromhex(sha256(k_ipad + message))

    result = sha256(k_opad + inner)

    return bytes.fromhex(result)