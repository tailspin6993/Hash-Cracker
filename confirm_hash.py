import hashlib

password = input("Enter a password to hash: ")

# Hash the password using SHA-256 and print the result
hashed_password = hashlib.sha256(password.encode()).hexdigest()
print("Hashed Password:", hashed_password)
