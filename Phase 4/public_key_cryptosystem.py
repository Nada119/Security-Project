import os
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as padding_module
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# RSA and ECC key pair generation
def generate_rsa_key_pair():
    private_key = None
    public_key = None

    # Function to generate RSA key pair
    def generate_rsa_keys():
        nonlocal private_key, public_key
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

    # Create threads to generate RSA key pair
    thread = threading.Thread(target=generate_rsa_keys)
    thread.start()
    thread.join()

    return private_key, public_key


# Define the generate_ecc_key_pair function with multithreading
def generate_ecc_key_pair():
    private_key = None
    public_key = None

    # Function to generate ECC key pair
    def generate_ecc_keys():
        nonlocal private_key, public_key
        private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        public_key = private_key.public_key()

    # Create threads to generate ECC key pair
    thread = threading.Thread(target=generate_ecc_keys)
    thread.start()
    thread.join()

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
