import os
import json
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from generate_certificates import generate_certificates


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
