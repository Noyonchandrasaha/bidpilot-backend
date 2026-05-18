import secrets
import string


def generate_secret_key(length: int = 32) -> str:
    """
    Generate a cryptographically secure secret key.

    Args:
        length (int): Length of the secret key

    Returns:
        str: Secure random secret key
    """

    characters = string.ascii_letters + string.digits + string.punctuation

    return ''.join(
        secrets.choice(characters)
        for _ in range(length)
    )


# Example usage
if __name__ == "__main__":
    print(generate_secret_key())