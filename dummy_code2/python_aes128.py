from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def encrypt_aes128(data, key):
    """Encrypts the input data using AES-128 in CBC mode."""
    iv = os.urandom(16)  # Generate a random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return iv + ciphertext  # Return IV + Ciphertext

def decrypt_aes128(encrypted_data, key):
    """Decrypts the input data using AES-128 in CBC mode."""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')

# Example usage
if __name__ == "__main__":
    key = os.urandom(16)  # 128-bit key
    data = "LowRiskAES128"
    encrypted = encrypt_aes128(data, key)
    decrypted = decrypt_aes128(encrypted, key)
    print("Encrypted AES-128 Data:", encrypted.hex())
    print("Decrypted AES-128 Data:", decrypted)
