import os
import json
from hmac_custom import hmac_sha256
from SHA_256 import sha256


def pbkdf2(password, salt, iterations, key_length):

    hash_length = 32
    blocks = (key_length + hash_length - 1) // hash_length

    derived_key = b""

    for i in range(1, blocks + 1):

        block_index = i.to_bytes(4, 'big')

        U = hmac_sha256(password, salt + block_index)

        result = U

        for j in range(iterations - 1):

            U = hmac_sha256(password, U)

            result = bytes(a ^ b for a, b in zip(result, U))

        derived_key += result

    return derived_key[:key_length]


def register(username, password):

    salt = os.urandom(16)

    password_hash = pbkdf2(password.encode(), salt, 100000, 32)

    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            users = json.load(f)
    else:
        users = {}

    users[username] = {
        "salt": salt.hex(),
        "hash": password_hash.hex()
    }

    with open("users.json", "w") as f:
        json.dump(users, f)

    print("User registered")


def login(username, password):

    with open("users.json", "r") as f:
        users = json.load(f)

    if username not in users:
        print("User not found")
        return

    salt = bytes.fromhex(users[username]["salt"])

    stored_hash = users[username]["hash"]

    new_hash = pbkdf2(password.encode(), salt, 100000, 32).hex()

    if new_hash == stored_hash:
        print("Login successful")
    else:
        print("Wrong password")


def hash_file(filename):

    with open(filename, "rb") as f:
        data = f.read()

    return sha256(data)


def create_manifest(filename):

    file_hash = hash_file(filename)

    with open("manifest.txt", "w") as f:
        f.write(filename + ":" + file_hash)

    print("Manifest created")


def verify_file(filename):

    with open("manifest.txt", "r") as f:
        line = f.read()

    stored_file, stored_hash = line.split(":")

    current_hash = hash_file(filename)

    if current_hash == stored_hash:
        print("File is unchanged")
    else:
        print("File has been modified")