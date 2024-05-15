import subprocess
from cryptography.x509 import load_pem_x509_certificate


def generate_certificates(username):
    """Generate certificates automatically using OpenSSL."""
    # Define file paths for private key, CSR, and certificate
    private_key_path = f"{username}_private_key.pem"
    csr_path = f"{username}_csr.pem"
    cert_path = f"{username}_certificate.pem"

    print(f"\nGenerating certificates for user: {username}")
    print(f"Private key path: {private_key_path}")
    print(f"CSR path: {csr_path}")
    print(f"Certificate path: {cert_path}")

    # Step 1: Generate a private key
    result = subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-out",
            private_key_path,
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"Error generating private key: {result.stderr}")
        return None

    # Step 2: Generate a certificate signing request (CSR)
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            private_key_path,
            "-out",
            csr_path,
            "-batch",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"Error generating CSR: {result.stderr}")
        return None

    # Step 3: Create a self-signed certificate
    result = subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-days",
            "365",
            "-in",
            csr_path,
            "-signkey",
            private_key_path,
            "-out",
            cert_path,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"Error creating certificate: {result.stderr}")
        return None

    print("\nCertificate generation process completed.")
    return cert_path
