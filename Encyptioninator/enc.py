import base64
import binascii
import hashlib
from string import ascii_lowercase, ascii_uppercase

# Base64 Encoding/Decoding
def base64_encrypt(data: str) -> str:
    """Encrypt data using Base64 encoding."""
    encoded_bytes = base64.b64encode(data.encode('utf-8'))
    return encoded_bytes.decode('utf-8')

def base64_decrypt(encoded_data: str) -> str:
    """Decrypt Base64 encoded data."""
    decoded_bytes = base64.b64decode(encoded_data.encode('utf-8'))
    return decoded_bytes.decode('utf-8')

# Hex Encoding/Decoding
def hex_encrypt(data: str) -> str:
    """Encrypt data using Hex encoding."""
    encoded_bytes = binascii.hexlify(data.encode('utf-8'))
    return encoded_bytes.decode('utf-8')

def hex_decrypt(encoded_data: str) -> str:
    """Decrypt Hex encoded data."""
    decoded_bytes = binascii.unhexlify(encoded_data.encode('utf-8'))
    return decoded_bytes.decode('utf-8')

# Caesar Cipher
def caesar_encrypt(data: str, shift: int) -> str:
    """Encrypt data using Caesar Cipher."""
    result = ""
    for char in data:
        if char.isalpha():
            shift_amount = shift % 26
            new_char = chr((ord(char) - ord('a' if char.islower() else 'A') + shift_amount) % 26 + ord('a' if char.islower() else 'A'))
            result += new_char
        else:
            result += char
    return result

def caesar_decrypt(encoded_data: str, shift: int) -> str:
    """Decrypt Caesar Cipher encoded data."""
    return caesar_encrypt(encoded_data, -shift)

# ROT13 Cipher
def rot13_encrypt(data: str) -> str:
    """Encrypt data using ROT13."""
    return caesar_encrypt(data, 13)

def rot13_decrypt(encoded_data: str) -> str:
    """Decrypt ROT13 encoded data."""
    return caesar_encrypt(encoded_data, 13)

# XOR Cipher
def xor_encrypt(data: str, key: str) -> str:
    """Encrypt data using XOR encoding."""
    result = ""
    key_len = len(key)
    for i, char in enumerate(data):
        result += chr(ord(char) ^ ord(key[i % key_len]))
    return result

def xor_decrypt(encoded_data: str, key: str) -> str:
    """Decrypt XOR encoded data."""
    return xor_encrypt(encoded_data, key)

# Vigenère Cipher
def vigenere_encrypt(data: str, key: str) -> str:
    """Encrypt data using Vigenère Cipher."""
    key = key.lower()
    key_len = len(key)
    result = ""
    for i, char in enumerate(data):
        if char.isalpha():
            shift_amount = ord(key[i % key_len]) - ord('a')
            if char.islower():
                result += chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
        else:
            result += char
    return result

def vigenere_decrypt(encoded_data: str, key: str) -> str:
    """Decrypt Vigenère Cipher encoded data."""
    key = key.lower()
    key_len = len(key)
    result = ""
    for i, char in enumerate(encoded_data):
        if char.isalpha():
            shift_amount = ord(key[i % key_len]) - ord('a')
            if char.islower():
                result += chr((ord(char) - ord('a') - shift_amount) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') - shift_amount) % 26 + ord('A'))
        else:
            result += char
    return result

# Atbash Cipher
def atbash_encrypt(data: str) -> str:
    """Encrypt data using Atbash Cipher."""
    result = ""
    for char in data:
        if char.islower():
            result += chr(ord('z') - (ord(char) - ord('a')))
        elif char.isupper():
            result += chr(ord('Z') - (ord(char) - ord('A')))
        else:
            result += char
    return result

def atbash_decrypt(encoded_data: str) -> str:
    """Decrypt Atbash Cipher encoded data."""
    return atbash_encrypt(encoded_data)  # Atbash decryption is the same as encryption

# Morse Code
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
    'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
    'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-', 
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', ' ': '/'
}

REVERSE_MORSE_CODE_DICT = {v: k for k, v in MORSE_CODE_DICT.items()}

def morse_encrypt(data: str) -> str:
    """Encrypt data using Morse Code."""
    result = ''
    for char in data.upper():
        result += MORSE_CODE_DICT.get(char, '') + ' '
    return result.strip()

def morse_decrypt(encoded_data: str) -> str:
    """Decrypt Morse Code encoded data."""
    result = ''
    for code in encoded_data.split(' '):
        result += REVERSE_MORSE_CODE_DICT.get(code, '')
    return result

# Hashing Algorithms
def md5_hash(data: str) -> str:
    """Generate MD5 hash of data."""
    return hashlib.md5(data.encode('utf-8')).hexdigest()

def sha1_hash(data: str) -> str:
    """Generate SHA-1 hash of data."""
    return hashlib.sha1(data.encode('utf-8')).hexdigest()

def sha256_hash(data: str) -> str:
    """Generate SHA-256 hash of data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def sha512_hash(data: str) -> str:
    """Generate SHA-512 hash of data."""
    return hashlib.sha512(data.encode('utf-8')).hexdigest()

# AES Encryption/Decryption
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(data: str) -> bytes:
    """Pad data to be multiple of 16 bytes."""
    pad_length = 16 - len(data) % 16
    return data.encode('utf-8') + bytes([pad_length] * pad_length)

def unpad(data: bytes) -> str:
    """Remove padding from data."""
    return data[:-data[-1]].decode('utf-8')

def aes_encrypt(data: str, key: bytes) -> bytes:
    """Encrypt data using AES."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

def aes_decrypt(encoded_data: bytes, key: bytes) -> str:
    """Decrypt AES encoded data."""
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(encoded_data))

# RSA Encryption/Decryption
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keypair():
    """Generate RSA key pair."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(data: str, public_key: bytes) -> bytes:
    """Encrypt data using RSA."""
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(data.encode('utf-8'))

def rsa_decrypt(encoded_data: bytes, private_key: bytes) -> str:
    """Decrypt RSA encoded data."""
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encoded_data).decode('utf-8')

# Additional encryption algorithms can be added here
