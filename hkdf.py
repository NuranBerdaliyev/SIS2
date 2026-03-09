from hmac_custom import hmac_sha256


def hkdf_extract(salt: bytes, key_material: bytes):

    return hmac_sha256(salt, key_material)


def hkdf_expand(prk: bytes, info: bytes, length: int):

    output = b""
    t = b""
    counter = 1

    while len(output) < length:

        t = hmac_sha256(prk, t + info + bytes([counter]))
        output += t
        counter += 1

    return output[:length]