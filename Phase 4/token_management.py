import time
import secrets


# Token Management
class TokenManager:
    def __init__(self):
        self.token_expiration_time = 0.5 * 60  # 10 minutes in seconds
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


def test_token_manager():
    # Create an instance of TokenManager
    token_manager = TokenManager()

    # Generate a token for a user
    username = "example_user"
    token = token_manager.generate_token(username)
    print("Generated Token:", token)

    # Validate the generated token
    print("Token Validation Result:", token_manager.validate_token(token))

    # Wait for the token to expire
    print("Waiting for token to expire...")
    time.sleep(token_manager.token_expiration_time + 1)

    # Validate the expired token
    print(
        "Token Validation Result after expiration:", token_manager.validate_token(token)
    )


# Run the test function
test_token_manager()
