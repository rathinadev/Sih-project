from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import redis
import time

# Initialize Redis
redis_client_aes = redis.StrictRedis(host='localhost', port=6379, db=1)
redis_client_rsa = redis.StrictRedis(host='localhost', port=6379, db=2)


# AES Key Generation Function
import random

# AES Key Generation Function (Unique ID for each key)
def generate_aes_key():
    key = os.urandom(32)  # 256-bit key
    key_id = f'aes_key_{int(time.time())}_{random.randint(1000, 9999)}'  # Unique ID
    redis_client_aes.set(key_id, key)  # Store in Redis
    redis_client_aes.expire(key_id, 12 * 3600)  # Set expiry (12 hours)
    return key_id, key

# RSA Key Generation (Storing multiple sets with distinct names)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048  # Use 4096 for stronger security
    )
    public_key = private_key.public_key()

    # Serialize keys
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Generate unique key names
    key_suffix = random.randint(1000, 9999)
    private_key_id = f'rsa_private_key_{key_suffix}'
    public_key_id = f'rsa_public_key_{key_suffix}'

    # Store keys in Redis under unique names
    redis_client_rsa.set(private_key_id, private_key_pem)
    redis_client_rsa.set(public_key_id, public_key_pem)

    return private_key_id, public_key_id


def check_and_generate_aes_keys(min_keys=5):
    # Get all keys in db=1 (AES keys database)
    aes_keys = redis_client_aes.keys('aes_key_*')  # Get all keys that start with 'aes_key_'
    aes_keys_count = len(aes_keys)  # Count the number of AES keys
    if aes_keys_count < min_keys:
        print(f"Found {aes_keys_count} AES keys. Generating {min_keys - aes_keys_count} more AES keys...")
        # Generate missing AES keys
        for _ in range(min_keys - aes_keys_count):
            time.sleep(10)
            generate_aes_key()
    else:
        print(f"Already have {aes_keys_count} AES keys. No need to generate more.")

def check_and_generate_rsa_keys(min_keys=3):
    # Get all keys in db=2 (RSA keys database)
    rsa_keys = redis_client_rsa.keys('rsa_private_key_*')  # Get all keys that start with 'rsa_private_key_'
    rsa_keys_count = len(rsa_keys)  # Count the number of RSA private keys
    if rsa_keys_count < min_keys:
        print(f"Found {rsa_keys_count} RSA keys. Generating {min_keys - rsa_keys_count} more RSA keys...")
        # Generate missing RSA keys
        for _ in range(min_keys - rsa_keys_count):
            time.sleep(10)
            generate_rsa_keys()
    else:
        print(f"Already have {rsa_keys_count} RSA keys. No need to generate more.")





