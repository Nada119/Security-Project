from encryption import encrypt_texts
from decryption import decrypt_texts


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
