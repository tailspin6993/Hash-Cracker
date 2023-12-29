import hashlib
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument('digest', help='digest to attempt to crack')
parser.add_argument('wordlist', help='wordlist to use')
parser.add_argument('-a', '--algorithm', help='algorithm to use, default is SHA256')
parser.add_argument('-s', '--salt', help='salt to use (if any)')

args = parser.parse_args()

ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512
}
DEFAULT_ALGORITHM = ALGORITHMS['sha256']

def read_from_wordlist(wordlist_path):
    with open(wordlist_path, 'r') as f:
        for line in f:
            yield line

def main():
    if args.algorithm is None:
        alg_to_use = DEFAULT_ALGORITHM
    elif args.algorithm.lower() in ALGORITHMS:
        alg_to_use = ALGORITHMS[args.algorithm.lower()]

    if not os.path.exists(args.wordlist):
        print(f'Wordlist {args.wordlist} cannot be found or is unreachable.')
        return

    wordlist = read_from_wordlist(args.wordlist)

if __name__ == "__main__":
    main()
