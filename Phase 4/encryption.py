import threading
from block_chiper import *
from hashing_functions import *


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

    # Function to encrypt plaintext
    def encrypt_text(plaintext):
        encrypted_text = cipher.encrypt(plaintext)
        encrypted_texts.append(encrypted_text)

        if hash_choice == "SHA-256":
            original_hash = sha256_hash(plaintext.encode())
        else:
            original_hash = md5_hash(plaintext.encode())
        original_hashes.append(original_hash)

    threads = []
    for plaintext in plaintexts:
        thread = threading.Thread(target=encrypt_text, args=(plaintext,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

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
