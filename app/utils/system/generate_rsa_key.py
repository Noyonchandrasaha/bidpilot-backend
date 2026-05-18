from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys():
    # 1. Generate Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. Serialize Private Key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 3. Serialize Public Key
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 4. Save to files
    with open("private.pem", "wb") as f:
        f.write(private_pem)
    
    with open("public.pem", "wb") as f:
        f.write(public_pem)

    print("RSA Keys generated successfully!")
    print("Files created: private.pem, public.pem")
    print("\nCopy the content of these files into your .env as JWT_PRIVATE_KEY and JWT_PUBLIC_KEY.")

if __name__ == "__main__":
    generate_rsa_keys()
