from hashlib import sha256

def login(email, stored_logins, password_to_check):
    """
    Verifies if the password entered matches the stored hash for the provided email.

    Args:
        email (str): The email for which the password is being checked.
        stored_logins (dict): A dictionary mapping emails to their hashed passwords.
        password_to_check (str): The password to verify.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    if email not in stored_logins:
        print(f"Error: {email} is not found in the stored logins.")
        return False

    hashed_password = hash_password(password_to_check)
    if stored_logins[email] == hashed_password:
        return True

    return False


def hash_password(password):
    """
    Hashes a password using the SHA256 algorithm.

    Args:
        password (str): The password to hash.

    Returns:
        str: The SHA256 hash of the password.
    """
    return sha256(password.encode()).hexdigest()


def main():
    """
    Main function for testing the login functionality.
    """
    stored_logins = {
        "example@gmail.com": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", 
        "code_in_placer@cip.org": "973607a4ae7b4cf7d96a100b0fb07e8519cc4f70441d41214a9f811577bb06cc",  
        "student@stanford.edu": "882c6df720fd99f5eebb1581a1cf975625cea8a160283011c0b9512bb56c95fb"  
    }

    # Test cases
    print("Login Results:")
    print(f"example@gmail.com with 'word': {login('example@gmail.com', stored_logins, 'word')}")
    print(f"example@gmail.com with 'password': {login('example@gmail.com', stored_logins, 'password')}")
    print(f"code_in_placer@cip.org with 'Ayesha': {login('code_in_placer@cip.org', stored_logins, 'Ayesha')}")
    print(f"code_in_placer@cip.org with 'Ayesha': {login('code_in_placer@cip.org', stored_logins, 'Ayesha')}")
    print(f"student@stanford.edu with 'password': {login('student@stanford.edu', stored_logins, 'password')}")
    print(f"student@stanford.edu with '123!456?789': {login('student@stanford.edu', stored_logins, '123!456?789')}")

    # Test invalid email
    print(f"unknown@gmail.com with 'password': {login('unknown@gmail.com', stored_logins, 'password')}")

if __name__ == '__main__':
    main()
