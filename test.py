import hashlib
import redis
import base64
import encrypt1

def compute_file_hash(file_path):
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()

    # Open the file in binary mode
    with open(file_path, "rb") as f:
        # Read the file in chunks to avoid memory overload
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    # Return the hexadecimal hash
    return sha256_hash.hexdigest()

# Path to your file
file_path = "models/tiny_face_detector_model-shard1"

# Compute the hash of the file
file_hash = compute_file_hash(file_path)

print(f"SHA-256 Hash of {file_path}: {file_hash}")

# Test decryption function
encrypt1.decrypt_from_redis_and_save('aes_key_1733643084_2757','models/hi')

def get_aes_key_from_redis():
    """
    Fetch the AES key from Redis, decode from base64, and return it.
    """
    # Connect to the Redis server
    redis_client = redis.StrictRedis(host='localhost', port=6379, db=1, decode_responses=False)

    # Fetch the AES key from Redis
    aes_key_base64 = redis_client.get('aes_key_1733629480_4164')

    if aes_key_base64 is None:
        print("AES key not found in Redis.")
        return None

    # Decode the base64-encoded AES key
    print(aes_key_base64)
    aes_key = base64.b64decode(aes_key_base64)

    return aes_key

# Call the function to fetch the AES key
aes_key = get_aes_key_from_redis()
print(f"AES Key (Decoded): {aes_key.hex()}")

def split_and_print_model_data(redis_key, output_file="model_data_output.txt"):
    """
    Retrieve encrypted model data from Redis, split into IV, ciphertext, and tag,
    and write their hexadecimal values to a file.
    """
    try:
        # Connect to Redis
        redis_client_model = redis.StrictRedis(host='localhost', port=6379, db=3, decode_responses=False)

        # Fetch the encrypted model data (assuming base64-encoded in Redis)
        encrypted_data_base64 = redis_client_model.get(redis_key)
        if not encrypted_data_base64:
            print(f"No data found in Redis for key: {redis_key}")
            return

        # Decode the base64-encoded encrypted data
        encrypted_data = base64.b64decode(encrypted_data_base64)

        # Split the data into IV, ciphertext, and tag (based on AES-GCM standard)
        iv = encrypted_data[:12]  # First 12 bytes (AES-GCM standard IV size)
        tag = encrypted_data[-16:]  # Last 16 bytes (AES-GCM tag size)
        ciphertext = encrypted_data[12:-16]  # The rest is ciphertext

        # Open the file for writing
        with open(output_file, 'w') as f:
            # Write the hexadecimal values to the file
            f.write(f"IV (Hex): {iv.hex()}\n")
            f.write(f"Ciphertext (Hex): {ciphertext.hex()}\n")
            f.write(f"Tag (Hex): {tag.hex()}\n")
            f.write(f"IV Length: {len(iv)}\n")
            f.write(f"Ciphertext Length: {len(ciphertext)}\n")
            f.write(f"Tag Length: {len(tag)}\n")
            f.write("\n")

        print(f"Output written to {output_file}")

    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    # Replace 'aes_key_1733604807_9290' with the Redis key where your encrypted model data is stored
    redis_key = "aes_key_1733643084_2757"

    # Call the function to split and print the model data
    split_and_print_model_data(redis_key)
