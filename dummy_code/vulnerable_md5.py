# 1. Python Script - MD5 Hashing (Weak Hash)
import hashlib

def weak_md5_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

plaintext = "password123"
hashed_value = weak_md5_hash(plaintext)

print("MD5 Hash:", hashed_value)