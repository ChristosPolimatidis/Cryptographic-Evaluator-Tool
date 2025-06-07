import hashlib

def hash_sha256(data):
    """Hashes the input data using SHA-256 (without HMAC)."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data.encode('utf-8'))
    return sha256_hash.hexdigest()

# Example usage
if __name__ == "__main__":
    data = "LowRiskExample"
    print("SHA-256 Hash:", hash_sha256(data))
