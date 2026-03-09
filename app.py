from hmac_tool import generate_hmac, verify_hmac
from hkdf import hkdf_extract, hkdf_expand
from pbkdf2_tool import register, login, create_manifest, verify_file

def main():

    print("1) Generate HMAC")
    print("2)  Verify HMAC")
    print("3) Register user")
    print("4) Login user")
    print("5) Create file hash")
    print("6) Verify file")
    print("7) HKDF extract")
    print("8) HKDF expand")

    choice = input("Choice: ")

    if choice == "1":
        generate_hmac()

    elif choice == "2":
        verify_hmac()

    elif choice == "3":
        u = input("Username: ")
        p = input("Password: ")
        register(u, p)

    elif choice == "4":
        u = input("Username: ")
        p = input("Password: ")
        login(u, p)

    elif choice == "5":
        f = input("File name: ")
        create_manifest(f)

    elif choice == "6":
        f = input("File name: ")
        verify_file(f)
    elif choice == "7":
        salt = input("Salt: ").encode()
        key_material = input("Key material: ").encode()

        prk = hkdf_extract(salt, key_material)
        print("PRK:", prk.hex())

    elif choice == "8":
        prk = bytes.fromhex(input("PRK (hex): "))
        info = input("Info: ").encode()
        length = int(input("Length: "))

        okm = hkdf_expand(prk, info, length)
        print("Derived key:", okm.hex())

if __name__ == "__main__":
    main()