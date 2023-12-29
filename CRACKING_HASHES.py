import hashlib

def hash_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            plaintext = line.strip()
            hashed = hashlib.sha256(plaintext.encode()).hexdigest()
            if hashed == hash_to_match:
                print(f"CRACKED THE PASSWORD!\nPlaintext: {plaintext}\nHash: {hashed}")
                return

if __name__ == "__main__":
    hash_to_match = input("Enter a hash to attempt to crack: ")
    file_path = "passwords.txt"  # Replace with the path to your text file
    hash_file(file_path)
