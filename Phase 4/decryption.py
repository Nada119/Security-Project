import threading
from block_chiper import *
from hashing_functions import *


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

    # Function to decrypt text and calculate hash
    def decrypt_and_verify(encrypted_text, original_hash):
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

    threads = []
    for encrypted_text, original_hash in zip(encrypted_texts, original_hashes):
        thread = threading.Thread(
            target=decrypt_and_verify, args=(encrypted_text, original_hash)
        )
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    print("\nDecrypted Texts:")
    for i, decrypted_text in enumerate(decrypted_texts):
        print(f"Text {i + 1}: {decrypted_text}")

    print("\nData Integrity Checks:")
    for i in range(len(decrypted_hashes)):
        if original_hashes[i] == decrypted_hashes[i]:
            print(f"Data integrity check passed for message {i + 1}.")
        else:
            print(f"Data integrity check failed for message {i + 1}.")
