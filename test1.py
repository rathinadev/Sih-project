import hashlib
import redis
import base64
from Crypto.Cipher import AES

def compute_file_hash(data):
    """
    Compute SHA-256 hash of data.
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data)
    return sha256_hash.hexdigest()

# Fetch AES key from Redis and decode it from base64
def get_aes_key_from_redis(redis_key):
    redis_client = redis.StrictRedis(host='localhost', port=6379, db=1, decode_responses=False)
    aes_key_base64 = redis_client.get(redis_key)

    if aes_key_base64 is None:
        print(f"AES key not found in Redis for key: {redis_key}")
        return None

    # Decode the base64-encoded AES key into raw bytes
    aes_key = base64.b64decode(aes_key_base64)

    return aes_key

# Decrypt the model data using the AES key
def decrypt_aes_data(encrypted_data, aes_key):
    try:
        # Extract IV, ciphertext, and tag
        iv = encrypted_data[:12]  # AES-GCM IV is the first 12 bytes
        tag = encrypted_data[-16:]  # AES-GCM tag is the last 16 bytes
        ciphertext = encrypted_data[12:-16]  # Ciphertext is the middle part

        # Initialize AES cipher with the key and IV
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)

        # Decrypt the ciphertext and check authenticity with the tag
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        # Return the decrypted data
        return decrypted_data

    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

def split_and_decrypt_model_data(redis_key):
    try:
        # Connect to Redis and retrieve the encrypted model data
        redis_client_model = redis.StrictRedis(host='localhost', port=6379, db=3, decode_responses=False)
        encrypted_data = redis_client_model.get(redis_key)

        if not encrypted_data:
            print(f"No data found in Redis for key: {redis_key}")
            return

        # Decode the Base64 encoded encrypted data into bytes
        encrypted_data_bytes = base64.b64decode(encrypted_data)

        # Fetch the AES key from Redis
        aes_key = get_aes_key_from_redis('aes_key_1733629480_4164')
        if aes_key is None:
            return

        # Ensure the AES key is the correct length (32 bytes for AES-256)
        if len(aes_key) != 32:
            print(f"Invalid AES key length: {len(aes_key)} bytes.")
            return

        # Decrypt the model data
        decrypted_data = decrypt_aes_data(encrypted_data_bytes, aes_key)

        if decrypted_data:
            # Compute the SHA-256 hash of the decrypted model data
            model_hash = compute_file_hash(decrypted_data)
            print(f"SHA-256 Hash of the Decrypted Model: {model_hash}")
        else:
            print("Decryption failed.")

    except Exception as e:
        print(f"Error occurred: {e}")

# Example usage
if __name__ == "__main__":
    # Use the appropriate Redis key for your encrypted model data
    redis_key = "aes_key_1733629480_4164"

    # Call the function to decrypt and print the hash of the model data
    split_and_decrypt_model_data(redis_key)
