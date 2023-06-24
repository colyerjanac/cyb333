import re
from passlib.hash import pbkdf2_sha256


def check_strong_password(password):
    # Check if password length is at least 8 characters, if not it is not a strong enough password
    if len(password) < 8:
        return False

    # Check if password contains uppercase and lowercase characters, if not it is not a strong enough password
    if not re.search("[a-z]", password) or not re.search("[A-Z]", password):
        return False

    # Check if password contains at least one digit, if not it is not a strong enough password
    if not re.search("[0-9]", password):
        return False

    # If all checks pass, password is strong
    return True


def hash_password(password):
    # Generate a secure password hash using PBKDF2 with SHA-256
    return pbkdf2_sha256.hash(password)


def check_password(password, hashed_password):
    # Verify if the entered password matches the stored hashed password
    return pbkdf2_sha256.verify(password, hashed_password)


# Ask user to input a password until it's accepted
while True:
    password = input("Please enter a password: ")
    if check_strong_password(password):
        hashed_password = hash_password(password)
        print("This password is strong.")

        # Store the hashed password in your database or secure storage
        # For demonstration purposes, we'll just pretend it's stored

        entered_password = input("Please re-enter the password for verification: ")
        if check_password(entered_password, hashed_password):
            print("Password verification successful.")
            break
        else:
            print("Password verification failed. Please try again.")
    else:
        print("This password is not strong enough. Please enter a stronger password.")
