# 2. Python Script - AES-256 Encryption (Weak Key Length)
from Cryptodome.Cipher import AES

def weak_des_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext.ljust(8).encode())

def weak_des_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext).strip()

key = b'weak_key'
plaintext = "secret12"
encrypted = weak_des_encrypt(plaintext, key)
decrypted = weak_des_decrypt(encrypted, key)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted.decode())