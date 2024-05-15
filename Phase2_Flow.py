from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode, b64decode
import queue
import hashlib
import threading

# Importing necessary cryptography classes and functions for RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


# AES Cipher class
class AESCipher(threading.Thread):
    def __init__(self, plaintext_queue, ciphertext_queue, key):
        threading.Thread.__init__(self)
        self.plaintext_queue = plaintext_queue
        self.ciphertext_queue = ciphertext_queue
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[: self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size :]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1 :]
        return plain_text[: -ord(last_character)]

    def run(self):
        while True:
            plaintext = self.plaintext_queue.get()
            if plaintext is None:
                break
            encrypted_text = self.encrypt(plaintext)
            self.ciphertext_queue.put(encrypted_text)


# RSA key pair generation
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# RSA encryption and decryption of AES key
def encrypt_aes_key(aes_key, public_key):
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_aes_key


def decrypt_aes_key(encrypted_aes_key, private_key):
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return aes_key


# SHA-256 hash function
def sha256_hash(data):
    sha256_hasher = hashlib.sha256()
    sha256_hasher.update(data)
    return sha256_hasher.hexdigest()


def test_integrated_flow(num_messages=2, message_contents=None, fail_indices=None):
    # Generate RSA key pair
    private_key, public_key = generate_key_pair()

    # Generate AES key
    aes_key = Random.new().read(32)  # AES-256 key

    # Create queues for plaintext and ciphertext messages
    plaintext_queue = queue.Queue()
    ciphertext_queue = queue.Queue()

    # Start AES encryption worker thread
    print("\n*** Starting the encryption process ***")
    worker = AESCipher(plaintext_queue, ciphertext_queue, aes_key)
    worker.start()

    # If message_contents is not provided, use default messages
    if message_contents is None:
        message_contents = ["Message " + str(i) for i in range(1, num_messages + 1)]

    # Calculate the SHA-256 hash of each plaintext message
    hash_values = [sha256_hash(message.encode()) for message in message_contents]

    # Add the plaintext messages to the queue
    for message in message_contents:
        plaintext_queue.put(message)

    # Add None to indicate the end of plaintext messages
    plaintext_queue.put(None)

    # Wait for the worker thread to finish
    worker.join()

    # Retrieve encrypted messages from the ciphertext queue
    encrypted_messages = []
    while not ciphertext_queue.empty():
        encrypted_messages.append(ciphertext_queue.get())

    # Encrypt the AES key using the RSA public key
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

    # Simulate receiving data
    received_encrypted_aes_key = encrypted_aes_key
    received_encrypted_messages = encrypted_messages
    received_hash_values = hash_values

    # Print plaintext messages, encrypted messages, encrypted AES key, and SHA-256 hash values of plaintext messages
    print("\n*** Plaintext Messages ***")
    for idx, message in enumerate(message_contents):
        print(f"Message {idx + 1}: {message}")

    print("\n*** Encrypted Messages ***")
    for idx, encrypted_message in enumerate(encrypted_messages):
        print(f"Encrypted Message {idx + 1}: {encrypted_message}")

    print("\n*** Encrypted AES Key ***")
    print(b64encode(encrypted_aes_key).decode())

    print("\n*** SHA-256 Hash Values of Plaintext Messages ***")
    for idx, hash_value in enumerate(hash_values):
        print(f"Message {idx + 1} Hash: {hash_value}")

    # Decrypt the AES key using the RSA private key
    print("\n*** Starting the decryption process ***")
    decrypted_aes_key = decrypt_aes_key(received_encrypted_aes_key, private_key)

    # Verify the AES key after decryption
    assert aes_key == decrypted_aes_key, "AES key decryption failed!"

    # Decrypt each received encrypted message using AES
    decrypted_messages = []
    aes_cipher = AESCipher(None, None, decrypted_aes_key)
    for encrypted_message in received_encrypted_messages:
        decrypted_messages.append(aes_cipher.decrypt(encrypted_message))

    # Modify specified hash values to simulate data integrity failure
    if fail_indices is not None:
        for idx in fail_indices:
            if idx < len(received_hash_values):
                # Simulate data integrity failure by changing the hash value
                received_hash_values[idx] = "incorrect_hash_value"
                print(f"Simulating failure: Changed hash value for message {idx + 1}")

    # Print decrypted messages and data integrity checks
    # Perform data integrity checks
    print("\n*** Data Integrity Checks ***")
    for idx, decrypted_message in enumerate(decrypted_messages):
        calculated_hash = sha256_hash(decrypted_message.encode())

        try:
            # Compare calculated hash with received hash
            assert (
                calculated_hash == received_hash_values[idx]
            ), f"Data integrity check failed for message {idx + 1}!"
            print(f"Data integrity check passed for message {idx + 1}!")
        except AssertionError:
            # Print error message
            print(f"Data integrity check failed for message {idx + 1}!")

    # Print decrypted messages
    print("\n*** Decrypted Messages ***")
    for idx, decrypted_message in enumerate(decrypted_messages):
        print(f"Decrypted Message {idx + 1}: {decrypted_message}")


# Test the integrated flow
if __name__ == "__main__":
    # Example usage: Test with 2 messages
    # Specifying message contents and indicating that the second message (index 1) should fail the data integrity check
    test_integrated_flow(
        num_messages=2,
        message_contents=["Hello, world!", "Test message for AES encryption."],
        fail_indices=[1],
    )
    # test_integrated_flow(
    #     num_messages=1,
    #     message_contents=[
    #         "A very long message that is significantly longer than the AES block size to test how the system handles messages with multiple blocks."
    #     ],
    #     fail_indices=None,
    # )
    # test_integrated_flow(
    #     num_messages=2,
    #     message_contents=["", ""],
    #     fail_indices=None,
    # )
    # test_integrated_flow(
    #     num_messages=1,
    #     message_contents=["&()"],
    #     fail_indices=None,
    # )
