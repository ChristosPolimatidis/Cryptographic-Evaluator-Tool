from Crypto.PublicKey import RSA

# Generate a weak RSA key (1024-bit, vulnerable)
key = RSA.generate(1024)
private_key = key.export_key()
public_key = key.publickey().export_key()

print("Vulnerable RSA 1024-bit Private Key:")
print(private_key.decode())

print("Vulnerable RSA 1024-bit Public Key:")
print(public_key.decode())
