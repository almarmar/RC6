from Crypto.Cipher import ARC6
from Crypto import Random

def rc6_encrypt(key, plaintext):
    cipher = ARC6.new(key, mode=ARC6.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def rc6_decrypt(key, ciphertext):
    cipher = ARC6.new(key, mode=ARC6.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def main():
    key = input("Enter the secret key (16, 24, or 32 bytes): ").encode('utf-8')

    mode = input("Choose mode (encryption - 'e', decryption - 'd'): ")

    if mode == 'e':
        plaintext = input("Enter the text to encrypt: ").encode('utf-8')
        ciphertext = rc6_encrypt(key, plaintext)
        print("Encrypted text:", ciphertext.hex())
    elif mode == 'd':
        ciphertext_hex = input("Enter the encrypted text in hexadecimal format: ")
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = rc6_decrypt(key, ciphertext)
        print("Decrypted text:", plaintext.decode('utf-8'))
    else:
        print("Invalid mode. Choose 'e' for encryption or 'd' for decryption.")

if __name__ == "__main__":
    main()









