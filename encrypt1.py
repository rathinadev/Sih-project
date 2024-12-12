import os
import redis
import time
import random
from cryptography.hazmat.backends import default_backend

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Initialize Redis clients for AES keys and models
redis_client_aes = redis.StrictRedis(host='localhost', port=6379, db=1)  # db 1 for AES keys
redis_client_rsa = redis.StrictRedis(host='localhost', port=6379, db=2)  # db 2 for RSA keys
redis_client_model = redis.StrictRedis(host='localhost', port=6379, db=3)  # db 3 for model path storage


def rsa_encrypt(aes_key, rsa_public_key):
    """
    Encrypt the AES key using the provided RSA public key.

    :param aes_key: The AES key to encrypt.
    :param rsa_public_key: The RSA public key as a PEM-formatted string.
    :return: The RSA-encrypted AES key in base64 format.
    """
    try:
        # Load the RSA public key
        public_key = serialization.load_pem_public_key(rsa_public_key.encode())

        # Encrypt the AES key
        encrypted_key = public_key.encrypt(
            aes_key.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(encrypted_key).decode()  # Convert to base64 string for transmission

    except Exception as e:
        raise Exception(f"Error encrypting AES key: {e}")


# AES Key Generation Function
def generate_aes_key():
    key = os.urandom(32)  # 256-bit key
    return key

# RSA Key Generation
def generate_rsa_keys():
    # Generate keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Serialize keys
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8').strip()  # Decode bytes to string

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8').strip()  # Decode bytes to string

    # Generate unique key names
    key_suffix = random.randint(1000, 9999)
    private_key_id = f'rsa_private_key_{key_suffix}'
    public_key_id = f'rsa_public_key_{key_suffix}'

    # Store keys in Redis (base64 encoded)
    redis_client_rsa.set(private_key_id, base64.b64encode(private_key_pem.encode()).decode())
    redis_client_rsa.set(public_key_id, base64.b64encode(public_key_pem.encode()).decode())

    return private_key_id, public_key_id

# AES Encryption function using AES-GCM mode
def encrypt_data_with_aes(aes_key, data):
    # Ensure the data is in bytes, as it might have been passed as a string or bytes
    if isinstance(data, str):
        data = data.encode()  # Only encode if it's a string
    
    iv = os.urandom(12)  # Generate random 12-byte IV (AES-GCM standard)

    # Create an AES-GCM cipher
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the data
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Get the authentication tag
    tag = encryptor.tag
    
    # Return the IV, encrypted data, and authentication tag (in that order)
    return iv + encrypted_data + tag  # IV + encrypted data + tag

# Decrypt the data using AES
def decrypt_data_with_aes(aes_key, encrypted_data):
    # Extract the IV (First 12 bytes for GCM, commonly)
    iv = encrypted_data[:12]  # AES-GCM typically uses a 12-byte IV
    tag = encrypted_data[-16:]  # Authentication tag (last 16 bytes)
    
    # The actual encrypted data (the portion in between the IV and tag)
    ciphertext = encrypted_data[12:-16]
    
    # Initialize the AES-GCM cipher with the IV and authentication tag
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data  # Return decrypted data as bytes

# Encrypt and store model and JSON file in the encryptedfiles directory

def encrypt_and_store_model_json(model_file_path="models/tiny_face_detector_model-shard1"):
    # Generate a unique timestamp-based filename for the encrypted model
    timestamp = int(time.time())
    encrypted_file_path = f"models/encryptedfiles/encrypted_model_{timestamp}.bin"
    
    # Generate AES key
    aes_key = generate_aes_key()
    
    # Encrypt the model file
    with open(model_file_path, 'rb') as model_file:
        model_data = model_file.read()  # Read model file as binary data
        
        encrypted_model = encrypt_data_with_aes(aes_key, model_data)

        # Save the encrypted model file to disk
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_model)
    
    # Store the AES key in Redis (base64 encoded)
    redis_key = f'aes_key_{timestamp}_{random.randint(1000, 9999)}'  # Unique ID based on timestamp and random number
    
    # Encode the AES key to base64 for storage
    aes_key_base64 = base64.b64encode(aes_key).decode('utf-8')
    
    # Store the AES key in db=1 and the model path in db=3
    redis_client_aes.set(redis_key, aes_key_base64)  # Store AES key in db=1
    redis_client_model.set(f"{redis_key}_path", encrypted_file_path)  # Store model path in db=3
    redis_client_aes.expire(redis_key, 12 * 3600)  # Set expiry for AES key (12 hours)

    print(f"Encrypted model stored at {encrypted_file_path}")
    print(f"AES Key (Base64): {aes_key_base64}")
    print(f"AES Key Length: {len(base64.b64decode(aes_key_base64))} bytes")

    return redis_key  # Return the unique Redis key for reference   
# Decrypt the model and JSON from Redis using the key and save to disk
def decrypt_from_redis_and_save(redis_key, decrypted_model_path):
    aes_key_base64 = redis_client_aes.get(redis_key)  # Retrieve AES key from db=1

    if aes_key_base64:
        aes_key = base64.b64decode(aes_key_base64)  # Decode from base64

        # Read the encrypted model file
        encrypted_model_file_path = f"models/encryptedfiles/{redis_key.split('_')[2]}.bin"  # Assuming the filename has timestamp
        with open(encrypted_model_file_path, 'rb') as encrypted_model_file:
            encrypted_model_data = encrypted_model_file.read()

        decrypted_model = decrypt_data_with_aes(aes_key, encrypted_model_data)

        # Save the decrypted model to disk
        with open(decrypted_model_path, 'wb') as model_output:
            model_output.write(decrypted_model)
        print(f"Decrypted model saved to: {decrypted_model_path}")
    else:
        print(f"No AES key found in Redis for key: {redis_key}")

# Main test function
def test_encryption_decryption():
    # Paths to model files
    model_file_path = "models/tiny_face_detector_model-shard1"
    
    # Encrypt and store model and JSON files
    redis_key = encrypt_and_store_model_json(model_file_path)

    # Decrypt model from Redis and save to disk
    decrypt_from_redis_and_save(redis_key, 'models/decrypted_model-shard1')

if __name__ == "__main__":

    test_encryption_decryption()
