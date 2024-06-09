# Cryptographic Hashing Algorithms in Python
#### Video Demo:  <URL https://youtu.be/NP0R3MBW0-Y>
#
Made by : Bimin Kiran Koju \
Github : https://github.com/biminkoju \
edx username : bimin_7\
My City and Country : Bhaktapur, Nepal\
Date recorded: 2024-6-9 (2024, June 9th)
#

## Description:
This repository contains Python implementations of the following cryptographic hashing algorithms:

- SHA-256
- MD5
- SHA-1

These algorithms are implemented from scratch without using external libraries, providing a basic understanding of how cryptographic hashing functions work. (except for SHA-1)

## How to Use

### Clone the repository to your local machine:

```bash
git clone https://github.com/biminkoju/crypto-hashing-python.git
```

### Navigate to the cloned directory:

```bash
cd crypto-hashing-python
```
### Run the script:
```bash

    python main.py
```
## Usage

Upon running the script, you will be prompted to choose a hashing algorithm and enter the string you want to hash. The available hashing algorithms are:

- SHA-256
- MD5
- SHA-1

Choose the desired algorithm by entering its corresponding number or name. Then, enter the string you want to hash.

The script will display the hashed string using the selected hashing algorithm.
Dependencies

The script does not require any external libraries. It uses standard Python libraries such as hashlib for SHA-1 hashing.
## Algorithm Details
### SHA-256

SHA-256 is a cryptographic hash function that produces a 256-bit (32-byte) hash value. It iteratively processes blocks of data through a series of transformations, resulting in a hash value that is typically represented as a hexadecimal string.

The implementation includes the SHA-256 constants, message padding, message processing, and the SHA-256 compression function.
### MD5

MD5 is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value. It processes the input message in 512-bit (64-byte) blocks and uses various bitwise logical operations and rotations to compute the hash value.

The implementation covers MD5 constants, message padding, message processing, and the MD5 compression function.
### SHA-1

SHA-1 is another cryptographic hash function that produces a 160-bit (20-byte) hash value. It is similar to SHA-256 but uses a different set of constants and operations.

The implementation includes the SHA-1 constants, message padding, message processing, and the SHA-1 compression function.
