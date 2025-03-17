from cryptography.hazmat.primitives.asymmetric import ec

# Generate an EC private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Get the corresponding public key
public_key = private_key.public_key()

print("Private key:", private_key.private_numbers().private_value)
print("Public key:", public_key.public_numbers().x, public_key.public_numbers().y)
