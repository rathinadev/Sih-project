from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import encrypt1
import os
import redis
import time
import random

# Initialize Redis
redis_client_aes = redis.StrictRedis(host='localhost', port=6379, db=1)
redis_client_rsa = redis.StrictRedis(host='localhost', port=6379, db=2)


# Check and generate AES keys if needed
def check_and_generate_aes_keys(min_keys=5):
    # Get all keys in db=1 (AES keys database)
    aes_keys = redis_client_aes.keys('aes_key_*')  # Get all keys that start with 'aes_key_'
    aes_keys_count = len(aes_keys)  # Count the number of AES keys
    if aes_keys_count < min_keys:
        print(f"Found {aes_keys_count} AES keys. Generating {min_keys - aes_keys_count} more AES keys...")
        # Generate missing AES keys
        for _ in range(min_keys - aes_keys_count):
            time.sleep(1)
            # Delay the import to avoid circular import error
            encrypt1.encrypt_and_store_model_json()
    else:
        print(f"Already have {aes_keys_count} AES keys. No need to generate more.")

# Check and generate RSA keys if needed
def check_and_generate_rsa_keys(min_keys=3):
    # Get all keys in db=2 (RSA keys database)
    rsa_keys = redis_client_rsa.keys('rsa_private_key_*')  # Get all keys that start with 'rsa_private_key_'
    rsa_keys_count = len(rsa_keys)  # Count the number of RSA private keys
    if rsa_keys_count < min_keys:
        print(f"Found {rsa_keys_count} RSA keys. Generating {min_keys - rsa_keys_count} more RSA keys...")
        # Generate missing RSA keys
        for _ in range(min_keys - rsa_keys_count):
            time.sleep(1)
            encrypt1.generate_rsa_keys()
    else:
        print(f"Already have {rsa_keys_count} RSA keys. No need to generate more.")

def monitor_redis_keys():
    
        # Check and generate AES keys if needed
        check_and_generate_aes_keys(min_keys=5)

        # Check and generate RSA keys if needed
        check_and_generate_rsa_keys(min_keys=3)

        # Sleep for a specified period (e.g., 1 minute) before checking again
       

# Start monitoring the Redis keys
if __name__ == "__main__":
    
    monitor_redis_keys()





