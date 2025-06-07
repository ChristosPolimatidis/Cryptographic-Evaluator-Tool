# 2. Python Script - AES Encryption (Secure Symmetric Encryption)
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import os

def secure_aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=os.urandom(16))
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ciphertext  # Prepend IV to ciphertext

def secure_aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]  # Extract IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return decrypted.decode()

key = os.urandom(32)  # Secure 256-bit key
plaintext = "securemessage"
encrypted = secure_aes_encrypt(plaintext, key)
decrypted = secure_aes_decrypt(encrypted, key)

print("Encrypted:", encrypted.hex())
print("Decrypted:", decrypted)