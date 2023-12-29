import hashlib
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('digest', help='digest to attempt to crack')
parser.add_argument('-a', '--algorithm', help='algorithm to use, default is SHA256')
parser.add_argument('-s', '--salt', help='salt to use (if any)')

args = parser.parse_args()

ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512
}

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
