from cryptography.hazmat.primitives.asymmetric import x25519

# Generate a private key
private_key = x25519.X25519PrivateKey.generate()

# Get the corresponding public key
public_key = private_key.public_key()

print("Private Key:", private_key.private_bytes_raw().hex())
print("Public Key:", public_key.public_bytes_raw().hex())
