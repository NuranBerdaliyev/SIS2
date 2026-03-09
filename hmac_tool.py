from hmac_custom import hmac_sha256


def generate_hmac():

    key = input("Enter key: ").encode()
    message = input("Enter message: ").encode()

    h = hmac_sha256(key, message)

    print("HMAC:", h.hex())


def verify_hmac():

    key = input("Enter key: ").encode()
    message = input("Enter message: ").encode()

    expected = input("Enter HMAC: ")

    new_hmac = hmac_sha256(key, message).hex()

    if new_hmac == expected:
        print("HMAC valid")
    else:
        print("HMAC invalid")