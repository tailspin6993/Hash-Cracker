# Hash-Cracker
This is a hash bruteforcer that can work with MD5, SHA1, SHA256, and SHA512.

# Basic Usage
Default algorithm is SHA256
`python cracker.py [digest] [wordlist]`

Example:
`python cracker.py e598d0eef6df00a67c17262dbb1a30ef8df99d7a6a95e20d9f24e77da7f05e81 wordlists/default.txt`

# Optional Arguments
- -a/--algorithm : specify algorithm to use

Example"
`python cracker.py a377c08cdd4affd787165bb4b8238efcf1ac1225 wordlists/default.txt -a sha1`