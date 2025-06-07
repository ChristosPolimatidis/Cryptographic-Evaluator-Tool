# 2. Python Script - DES Encryption (Weak Key Length)
from Cryptodome.Cipher import DES

def weak_des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(plaintext.ljust(8).encode())

def weak_des_decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(ciphertext).strip()

key = b'weak_key'
plaintext = "secret12"
encrypted = weak_des_encrypt(plaintext, key)
decrypted = weak_des_decrypt(encrypted, key)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted.decode())