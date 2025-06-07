from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes

# Generate a 3DES key (must be either 16 or 24 bytes long)
key = DES3.adjust_key_parity(get_random_bytes(24))

# Create a cipher object
cipher = DES3.new(key, DES3.MODE_ECB)  # ECB mode (insecure for real-world use!)

# Encrypt data
plaintext = b"SensitiveData123"
ciphertext = cipher.encrypt(plaintext.ljust(16))  # Padding manually

print("Encrypted:", ciphertext.hex())

# Decrypt data
decrypted = cipher.decrypt(ciphertext).strip()
print("Decrypted:", decrypted.decode())
