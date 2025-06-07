from Crypto.PublicKey import RSA

# Generate a secure RSA key (2048-bit)
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

print("Secure RSA 2048-bit Private Key:")
print(private_key.decode())

print("Secure RSA 2048-bit Public Key:")
print(public_key.decode())
