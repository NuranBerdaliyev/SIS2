from SHA_256 import sha256

BLOCK_SIZE = 64 


def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)


def hmac_sha256(key, message):

    if isinstance(key, str):
        key = key.encode()

    if isinstance(message, str):
        message = message.encode()

    

    if len(key) > BLOCK_SIZE:
        key = hex_to_bytes(sha256(key))

    if len(key) < BLOCK_SIZE:
        key = key + b'\x00' * (BLOCK_SIZE - len(key))


    ipad = bytes([0x36] * BLOCK_SIZE)
    opad = bytes([0x5c] * BLOCK_SIZE)

    

    inner_key = bytes([k ^ i for k, i in zip(key, ipad)])

    inner_hash = sha256(inner_key + message)

    inner_hash_bytes = hex_to_bytes(inner_hash)

   

    outer_key = bytes([k ^ o for k, o in zip(key, opad)])

    hmac = sha256(outer_key + inner_hash_bytes)

    return hmac


if __name__ == "__main__":

    key = input("Enter key: ")
    message = input("Enter message: ")

    tag = hmac_sha256(key, message)

    print("HMAC-SHA256 =", tag)