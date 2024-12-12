import os
import redis
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Initialize Redis
redis_client_model = redis.StrictRedis(host='localhost', port=6379, db=3)

# AES Encryption function
def encrypt_data_with_aes(aes_key, data):
    iv = os.urandom(16)  # Generate random 16-byte IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data  # Prepend the IV for use during decryption

# AES Decryption function
def decrypt_data_with_aes(aes_key, encrypted_data):
    iv = encrypted_data[:16]  # Extract the IV from the encrypted data
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted_data  # Return decrypted data as bytes

# Function to generate AES key (256-bit)
def generate_aes_key():
    return os.urandom(32)  # 256-bit AES key

# Encrypt and store model and JSON file in Redis
def encrypt_and_store_model_json(aes_key, model_file_path, json_file_path, redis_model_key, redis_json_key):
    # Encrypt the model file
    with open(model_file_path, 'rb') as model_file:
        model_data = model_file.read()  # Read model file as binary data
        encrypted_model = encrypt_data_with_aes(aes_key, model_data)
        redis_client_model.set(redis_model_key, encrypted_model)
        redis_client_model.expire(redis_model_key, 12 * 3600)  # Set expiry for 12 hours

    # Encrypt the JSON file
    with open(json_file_path, 'rb') as json_file:
        json_data = json_file.read()  # Read JSON file as binary data
        encrypted_json = encrypt_data_with_aes(aes_key, json_data)
        redis_client_model.set(redis_json_key, encrypted_json)
        redis_client_model.expire(redis_json_key, 12 * 3600)  # Set expiry for 12 hours

    print(f"Encrypted and stored model and json in Redis keys: {redis_model_key}, {redis_json_key}")

# Decrypt the model and JSON from Redis and save to disk
def decrypt_from_redis_and_save(aes_key, redis_model_key, redis_json_key, decrypted_model_path, decrypted_json_path):
    encrypted_model_data = redis_client_model.get(redis_model_key)
    encrypted_json_data = redis_client_model.get(redis_json_key)
    
    if encrypted_model_data:
        decrypted_model = decrypt_data_with_aes(aes_key, encrypted_model_data)
        with open(decrypted_model_path, 'wb') as model_output:
            model_output.write(decrypted_model)
        print(f"Decrypted model saved to: {decrypted_model_path}")
    else:
        print(f"No model data found in Redis for key: {redis_model_key}")

    if encrypted_json_data:
        decrypted_json = decrypt_data_with_aes(aes_key, encrypted_json_data)
        with open(decrypted_json_path, 'wb') as json_output:
            json_output.write(decrypted_json)
        print(f"Decrypted JSON saved to: {decrypted_json_path}")
    else:
        print(f"No JSON data found in Redis for key: {redis_json_key}")

# Main test function
def test_encryption_decryption():
    # Paths to model files
    model_file_path = "tiny_face_detector_model-shard1"
    json_file_path = "tiny_face_detector_model-weights_manifest.json"
    
    # AES Key Generation
    aes_key = generate_aes_key()

    # Encrypt and store model and json files in Redis
    encrypt_and_store_model_json(aes_key, model_file_path, json_file_path, 'encrypted_model', 'encrypted_json')

    # Decrypt model and json from Redis and save to disk
    decrypt_from_redis_and_save(aes_key, 'encrypted_model', 'encrypted_json', 'decrypted_model-shard1', 'decrypted_model-weights_manifest.json')


