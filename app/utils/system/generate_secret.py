import secrets
import string


def generate_secret_key(length: int = 32) -> str:
    """
    Generate a cryptographically secure alphanumeric secret key.

    Args:
        length (int): Length of the secret key

    Returns:
        str: Secure random secret key containing uppercase, lowercase, and digits
    """

    if length < 3:
        raise ValueError("Secret key length must be at least 3")

    required_characters = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
    ]
    characters = string.ascii_letters + string.digits
    remaining_characters = [
        secrets.choice(characters)
        for _ in range(length - len(required_characters))
    ]
    secret_key = required_characters + remaining_characters
    secrets.SystemRandom().shuffle(secret_key)

    return "".join(secret_key)


# Example usage
if __name__ == "__main__":
    print(generate_secret_key())