import os
from authentication import Authentication
from key_management import KeyManagement
from token_management import TokenManager
from user_operations import user_operations


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


if __name__ == "__main__":
    main()
