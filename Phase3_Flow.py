import os
import json
import time
import hashlib
import secrets
import subprocess
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, DES
from Crypto import Random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as padding_module
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import load_pem_x509_certificate


# Authentication Module
class Authentication:
    def __init__(self, storage_file="auth_storage.json"):
        self.storage_file = storage_file
        self.auth_data = self.load_auth_data()

    def load_auth_data(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, "r") as file:
                return json.load(file)
        return {}

    def save_auth_data(self):
        with open(self.storage_file, "w") as file:
            json.dump(self.auth_data, file)

    def store_password_hash(self, username, password):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.auth_data[username] = {
            "password_hash": password_hash,
            "method": "password",
        }
        self.save_auth_data()

    def verify_password(self, username, password):
        user_data = self.auth_data.get(username)
        if user_data and user_data["method"] == "password":
            stored_hash = user_data["password_hash"]
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            return stored_hash == password_hash
        return False

    def store_certificate(self, username, cert_pem):
        self.auth_data[username] = {"certificate": cert_pem, "method": "certificate"}
        self.save_auth_data()

    def verify_certificate(self, username, cert_pem):
        user_data = self.auth_data.get(username)
        if user_data and user_data["method"] == "certificate":
            stored_cert = user_data["certificate"]
            stored_cert_obj = load_pem_x509_certificate(
                stored_cert.encode(), default_backend()
            )
            input_cert_obj = load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            )
            return stored_cert_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ) == input_cert_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        return False

    def handle_user_signup(self):
        print("\nUser not found in authentication data. Please sign up.")
        username = input("Enter a new username: ").strip()
        auth_method = (
            input("Choose authentication method (password or certificate): ")
            .strip()
            .lower()
        )

        if auth_method == "password":
            password = input("Enter a password: ").strip()
            self.store_password_hash(username, password)

        elif auth_method == "certificate":
            # Generate certificates automatically using OpenSSL
            cert_path = generate_certificates(username)
            if cert_path:
                with open(cert_path, "r") as file:
                    cert_pem = file.read()
                # Store the certificate in the authentication data
                self.store_certificate(username, cert_pem)
                print(f"Certificate generated and stored for user '{username}'.")
                print(
                    f"Certificate file path: {cert_path}"
                )  # Provide path for immediate access
            else:
                print("Error generating certificates. Please try again.")
                return self.handle_user_signup()
        else:
            print("Invalid method. Please try again.")
            return self.handle_user_signup()

        print(f"User '{username}' signed up successfully.")
        return username


# Token Management
class TokenManager:
    def __init__(self):
        self.token_expiration_time = 10 * 60  # 10 minutes in seconds
        self.tokens = {}

    def generate_token(self, username):
        token = secrets.token_hex(16)  # Generate a 16-byte hex token
        expiration = time.time() + self.token_expiration_time
        self.tokens[token] = {"username": username, "expiration": expiration}
        return token

    def validate_token(self, token):
        token_data = self.tokens.get(token)
        if token_data:
            current_time = time.time()
            if current_time < token_data["expiration"]:
                return True
            else:
                del self.tokens[token]  # Remove expired token
                return False
        return False


class KeyManagement:
    def __init__(self, storage_file="key_storage.json"):
        self.storage_file = storage_file
        self.keys = {}
        self.load_keys()

    def load_keys(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, "r") as file:
                self.keys = json.load(file)

    def save_keys(self):
        with open(self.storage_file, "w") as file:
            json.dump(self.keys, file)

    def store_key(self, key_id, key):
        self.keys[key_id] = b64encode(key).decode("utf-8")
        self.save_keys()

    def retrieve_key(self, key_id):
        key_data = self.keys.get(key_id)
        if key_data:
            return b64decode(key_data)
        else:
            raise ValueError(f"No key found for ID '{key_id}'")

    def generate_and_store_key_pair(self, key_type, key_id):
        if key_type == "RSA":
            private_key, public_key = generate_rsa_key_pair()
        elif key_type == "ECC":
            private_key, public_key = generate_ecc_key_pair()
        else:
            raise ValueError("Invalid key type. Choose 'RSA' or 'ECC'.")

        # Convert keys to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        self.store_key(f"{key_id}_private", private_key_pem)
        self.store_key(f"{key_id}_public", public_key_pem)

        return private_key, public_key

    def retrieve_key_pair(self, key_id):
        private_key = self.retrieve_key(f"{key_id}_private")
        public_key = self.retrieve_key(f"{key_id}_public")

        private_key_obj = serialization.load_pem_private_key(
            private_key, password=None, backend=default_backend()
        )
        public_key_obj = serialization.load_pem_public_key(
            public_key, backend=default_backend()
        )

        return private_key_obj, public_key_obj

    def generate_and_store_symmetric_key(self, key_id, key_size=32):
        symmetric_key = os.urandom(key_size)
        self.store_key(f"{key_id}_symmetric", symmetric_key)
        return symmetric_key

    def retrieve_symmetric_key(self, key_id):
        return self.retrieve_key(f"{key_id}_symmetric")


# AES Cipher class
class AESCipher:
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        encrypted_data = iv + encrypted_text
        return b64encode(encrypted_data).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_data = b64decode(encrypted_text)
        iv = encrypted_data[: self.block_size]
        encrypted_text = encrypted_data[self.block_size :]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = decrypted_text.decode("utf-8")
        return self.__unpad(decrypted_text)

    def __pad(self, plain_text):
        pad_length = self.block_size - len(plain_text) % self.block_size
        padding = chr(pad_length) * pad_length
        return plain_text + padding

    def __unpad(self, decrypted_text):
        pad_length = ord(decrypted_text[-1])
        return decrypted_text[:-pad_length]


# DES Cipher class
class DESCipher:
    def __init__(self, key):
        self.block_size = DES.block_size
        self.key = self.__adjust_key(key)

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        encrypted_data = iv + encrypted_text
        return b64encode(encrypted_data).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_data = b64decode(encrypted_text)
        iv = encrypted_data[: self.block_size]
        encrypted_text = encrypted_data[self.block_size :]
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = decrypted_text.decode("utf-8")
        return self.__unpad(decrypted_text)

    def __adjust_key(self, key):
        if len(key) < 8:
            key += b"0" * (8 - len(key))
        elif len(key) > 8:
            key = key[:8]
        return key

    def __pad(self, plain_text):
        pad_length = self.block_size - len(plain_text) % self.block_size
        padding = chr(pad_length) * pad_length
        return plain_text + padding

    def __unpad(self, decrypted_text):
        pad_length = ord(decrypted_text[-1])
        return decrypted_text[:-pad_length]


# RSA and ECC key pair generation
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


# RSA and ECC encryption and decryption
def encrypt_key_rsa(key, public_key):
    return public_key.encrypt(
        key,
        padding_module.OAEP(
            mgf=padding_module.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_key_rsa(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding_module.OAEP(
            mgf=padding_module.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_message_ecc(message, public_key):
    ephemeral_private_key = ec.generate_private_key(
        ec.SECP256R1(), backend=default_backend()
    )
    ephemeral_public_key = ephemeral_private_key.public_key()

    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    derived_key.update(shared_secret)
    key = derived_key.finalize()

    iv = os.urandom(12)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    return ephemeral_public_key, encryptor.tag, iv, ciphertext


def decrypt_message_ecc(ciphertext, ephemeral_public_key, tag, iv, private_key):
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
    derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    derived_key.update(shared_secret)
    key = derived_key.finalize()

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_message.decode()


# Hashing functions
def sha256_hash(data):
    sha256_hasher = hashlib.sha256()
    sha256_hasher.update(data)
    return sha256_hasher.hexdigest()


def md5_hash(data):
    md5_hasher = hashlib.md5()
    md5_hasher.update(data)
    return md5_hasher.hexdigest()


# Main function
def main():
    print("Welcome to the Encryption/Decryption Program!")

    # Initialize authentication, key management, and token management
    auth = Authentication()
    key_manager = KeyManagement()
    token_manager = TokenManager()

    token = None

    while True:
        if token and token_manager.validate_token(token):
            # Token is valid
            username = token_manager.tokens[token]["username"]
            print(f"\nAuthenticated automatically as '{username}'.")
            user_operations(auth, key_manager, token_manager, username, token)
        else:
            if token is not None and not token_manager.validate_token(token):
                print("\nToken is invalid or expired. Please re-authenticate.")
                token = None
            # Prompt for authentication
            print("\nPlease authenticate.")
            username = input("Enter username: ").strip()
            if auth.auth_data.get(username):
                # Continuously prompt for a valid authentication method
                while True:
                    auth_choice = (
                        input(
                            "Choose authentication method (password or certificate): "
                        )
                        .strip()
                        .lower()
                    )
                    if auth_choice == "password":
                        password = input("Enter password: ").strip()
                        if not auth.verify_password(username, password):
                            print("Authentication failed.")
                            continue  # Prompt again for a valid authentication method
                        else:
                            break  # Authentication succeeded

                    elif auth_choice == "certificate":
                        cert_pem_path = input(
                            "Enter the path to your certificate file (PEM format): "
                        ).strip()
                        if os.path.exists(cert_pem_path):
                            with open(cert_pem_path, "r") as file:
                                cert_pem = file.read()
                            if not auth.verify_certificate(username, cert_pem):
                                print("Authentication failed.")
                                continue  # Prompt again for a valid authentication method
                            else:
                                break  # Authentication succeeded
                        else:
                            print("Certificate file not found. Please try again.")
                            continue  # Prompt again for a valid authentication method
                    else:
                        print(
                            "Invalid authentication method. Please enter 'password' or 'certificate'."
                        )
                        continue  # Prompt again for a valid authentication method

                token = token_manager.generate_token(username)
                print("\nAuthenticated successfully.")
                user_operations(auth, key_manager, token_manager, username, token)
            else:
                username = auth.handle_user_signup()
                token = token_manager.generate_token(username)
                print("\nAuthenticated successfully.")
                user_operations(auth, key_manager, token_manager, username, token)


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


# Define user_operations function
def user_operations(auth, key_manager, token_manager, username, token):
    # Get user's choices for encryption methods
    block_cipher_choice = (
        input("\nChoose a block cipher (AES or DES): ").strip().upper()
    )
    while block_cipher_choice not in ["AES", "DES"]:
        block_cipher_choice = (
            input("Invalid choice. Choose AES or DES: ").strip().upper()
        )

    public_key_choice = (
        input("\nChoose a public key encryption method (RSA or ECC): ").strip().upper()
    )
    while public_key_choice not in ["RSA", "ECC"]:
        public_key_choice = input("Invalid choice. Choose RSA or ECC: ").strip().upper()

    hash_choice = (
        input("\nChoose a hashing function (SHA-256 or MD5): ").strip().upper()
    )
    while hash_choice not in ["SHA-256", "MD5"]:
        hash_choice = input("Invalid choice. Choose SHA-256 or MD5: ").strip().upper()

    print("\nYour Choices:")
    print(f"Block Cipher: {block_cipher_choice}")
    print(f"Public Key Encryption: {public_key_choice}")
    print(f"Hashing Function: {hash_choice}\n")

    # Define key IDs
    asymmetric_key_id = f"{username}_user_keys"
    symmetric_key_id = f"{username}_user_symmetric_key"

    # Retrieve or generate symmetric key
    try:
        symmetric_key = key_manager.retrieve_symmetric_key(symmetric_key_id)
        print("\nLoaded symmetric key from storage.")
    except ValueError:
        symmetric_key = key_manager.generate_and_store_symmetric_key(symmetric_key_id)
        print("\nGenerated and stored a new symmetric key.")

    # Retrieve or generate asymmetric key pair (RSA or ECC)
    try:
        private_key, public_key = key_manager.retrieve_key_pair(asymmetric_key_id)
        print(f"\nLoaded {public_key_choice} key pair from storage.")
    except ValueError:
        private_key, public_key = key_manager.generate_and_store_key_pair(
            public_key_choice, asymmetric_key_id
        )
        print(f"\nGenerated and stored a new {public_key_choice} key pair.")

    # User operations loop
    while True:
        print("\nAuthenticated.")
        print("\nAvailable operations: 1) Encrypt 2) Decrypt 3) Exit")
        operation_choice = input("Choose an operation: ").strip()

        if operation_choice == "1":
            encrypt_texts(block_cipher_choice, hash_choice, symmetric_key)
        elif operation_choice == "2":
            decrypt_texts(block_cipher_choice, hash_choice, symmetric_key)
        elif operation_choice == "3":
            print("\nExiting the application.")
            # Invalidate the current token
            if token in token_manager.tokens:
                del token_manager.tokens[token]
            break
        else:
            print("Invalid choice. Please try again.")


# Define the encrypt_texts function
def encrypt_texts(block_cipher_choice, hash_choice, symmetric_key):
    # Encrypt using symmetric key
    plaintext_input = input("\nEnter texts to encrypt separated by commas: ").strip()
    plaintexts = [text.strip() for text in plaintext_input.split(",")]
    encrypted_texts = []
    original_hashes = []

    if block_cipher_choice == "AES":
        cipher = AESCipher(symmetric_key)
    else:
        cipher = DESCipher(symmetric_key)

    for plaintext in plaintexts:
        encrypted_text = cipher.encrypt(plaintext)
        encrypted_texts.append(encrypted_text)

        if hash_choice == "SHA-256":
            original_hash = sha256_hash(plaintext.encode())
        else:
            original_hash = md5_hash(plaintext.encode())
        original_hashes.append(original_hash)

    print("\nEncrypted Texts:")
    for i, encrypted_text in enumerate(encrypted_texts):
        print(f"Text {i + 1}: {encrypted_text}")
    print("\nOriginal Hash Values:")
    for i, original_hash in enumerate(original_hashes):
        print(f"Message {i + 1}: {original_hash}")

    # Ask the user if they want to simulate data integrity failure
    fail_indices_input = input(
        "\nSimulate data integrity failure (enter indices to modify hashes, or leave blank): "
    ).strip()

    if fail_indices_input:
        fail_indices = [
            int(index.strip()) - 1 for index in fail_indices_input.split(",")
        ]

        for idx in fail_indices:
            if 0 <= idx < len(original_hashes):
                original_hashes[idx] = "invalid_hash_value"
                print(f"Simulated data integrity failure for message {idx + 1}.")


# Define the decrypt_texts function
def decrypt_texts(block_cipher_choice, hash_choice, symmetric_key):
    encrypted_input = input("\nEnter encrypted texts separated by commas: ").strip()
    encrypted_texts = [text.strip() for text in encrypted_input.split(",")]

    original_hashes_input = input(
        "\nEnter the original hashes separated by commas: "
    ).strip()
    original_hashes = [hash.strip() for hash in original_hashes_input.split(",")]

    decrypted_texts = []
    decrypted_hashes = []

    if block_cipher_choice == "AES":
        cipher = AESCipher(symmetric_key)
    else:
        cipher = DESCipher(symmetric_key)

    for i, encrypted_text in enumerate(encrypted_texts):
        try:
            decrypted_text = cipher.decrypt(encrypted_text)
            decrypted_texts.append(decrypted_text)

            if hash_choice == "SHA-256":
                decrypted_hash = sha256_hash(decrypted_text.encode())
            else:
                decrypted_hash = md5_hash(decrypted_text.encode())
            decrypted_hashes.append(decrypted_hash)
        except ValueError as e:
            print(f"Error decrypting text: {encrypted_text}. Reason: {e}")
            decrypted_texts.append(f"Error: {e}")

    print("\nDecrypted Texts:")
    for i, decrypted_text in enumerate(decrypted_texts):
        print(f"Text {i + 1}: {decrypted_text}")

    print("\nData Integrity Checks:")
    for i in range(len(decrypted_hashes)):
        if original_hashes[i] == decrypted_hashes[i]:
            print(f"Data integrity check passed for message {i + 1}.")
        else:
            print(f"Data integrity check failed for message {i + 1}.")


if __name__ == "__main__":
    main()
