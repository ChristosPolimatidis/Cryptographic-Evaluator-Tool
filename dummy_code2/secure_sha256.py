# 1. Python Script - Secure Hashing (SHA-256)
import hashlib

def secure_sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

plaintext = "password123"
hashed_value = secure_sha256_hash(plaintext)

print("SHA-256 Hash:", hashed_value)