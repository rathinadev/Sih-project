import random
import redis
import logging
import base64

# Initialize Redis clients
redis_client_model = redis.StrictRedis(host='localhost', port=6379, db=3)  # db 3 for models
redis_client_aes = redis.StrictRedis(host='localhost', port=6379, db=1)  # db 1 for AES keys
redis_client_rsa = redis.StrictRedis(host='localhost', port=6379, db=2)  # db 2 for RSA keys

# Function to fetch a random Redis key for AES key
def get_random_redis_key():
    keys = redis_client_aes.keys("aes_key_*")  # Fetch all keys matching the AES key pattern
    if not keys:
        return None
    return random.choice(keys)  # Randomly pick one key

def get_redis_key(key):
    """
    Retrieve the AES key from Redis and decode from base64.
    """
    try:
        # Fetch binary data from Redis and decode to string
        key_data = redis_client_aes.get(key)
        if key_data:
            return base64.b64decode(key_data)
        return None
    except Exception as e:
        raise Exception(f"Error fetching key from Redis: {e}")


# Function to fetch AES key and encrypted model using a Redis key
def get_aes_key_and_model(redis_key):
    aes_key = redis_client_aes.get(redis_key)
    encrypted_model = redis_client_model.get(redis_key)

    if not aes_key or not encrypted_model:
        return None, None

    # Decode the values as base64 and return them
    return base64.b64decode(aes_key), base64.b64decode(encrypted_model)


# Function to fetch a random RSA private key and its corresponding public key from Redis
def get_random_rsa_keys():
    # Get all private RSA keys from Redis
    keys = redis_client_rsa.keys("rsa_private_key_*")
    if not keys:
        logging.error("No private RSA keys found in Redis.")
        return None, None

    # Decode Redis keys to strings
    keys = [key.decode('utf-8') for key in keys]
    logging.debug(f"Available private keys: {keys}")

    # Select a random private key
    private_key_id = random.choice(keys)
    public_key_id = private_key_id.replace("private", "public")

    # Fetch the PEMs for the selected keys
    private_key_pem = redis_client_rsa.get(private_key_id)
    public_key_pem = redis_client_rsa.get(public_key_id)

    if not private_key_pem or not public_key_pem:
        logging.error(f"Failed to retrieve keys: {private_key_id}, {public_key_id}")
        return None, None

    # Decode PEMs (assuming they are base64-encoded)
    private_key_pem = base64.b64decode(private_key_pem).decode('utf-8').strip()
    public_key_pem = base64.b64decode(public_key_pem).decode('utf-8').strip()

    # Validate the PEM format
    if not (
        private_key_pem.startswith("-----BEGIN PRIVATE KEY-----") and
        private_key_pem.endswith("-----END PRIVATE KEY-----") and
        public_key_pem.startswith("-----BEGIN PUBLIC KEY-----") and
        public_key_pem.endswith("-----END PUBLIC KEY-----")
    ):
        logging.error("Retrieved keys are not in valid PEM format.")
        return None, None

    logging.info("Successfully retrieved a random RSA key pair.")
    return private_key_pem, public_key_pem

# Function to get a random AES key and model and a random RSA key pair
def get_random_aes_key_and_model():
    # Fetch a random AES key from Redis
    aes_key_redis_key = get_random_redis_key()
    if not aes_key_redis_key:
        logging.error("No AES key found in Redis.")
        return None, None, None

    # Fetch AES key and encrypted model data
    aes_key, model_data = get_aes_key_and_model(aes_key_redis_key)
    if not aes_key or not model_data:
        logging.error("Failed to fetch AES key or model data.")
        return None, None, None

    # Fetch random RSA private and public keys
    private_key_pem, public_key_pem = get_random_rsa_keys()
    if not private_key_pem or not public_key_pem:
        logging.error("Failed to fetch RSA key pair.")
        return None, None, None

    return aes_key, model_data, public_key_pem

# Example of how to store a model and key as base64
def store_aes_key_and_model(redis_key, aes_key, model_data):
    # Encode AES key and model data to base64
    encoded_aes_key = base64.b64encode(aes_key)
    encoded_model_data = base64.b64encode(model_data)

    # Store the base64-encoded data in Redis
    redis_client_aes.set(redis_key, encoded_aes_key)
    redis_client_model.set(redis_key, encoded_model_data)

# Example of how to store RSA keys as base64
def store_rsa_keys(private_key_pem, public_key_pem):
    # Encode RSA keys to base64
    encoded_private_key = base64.b64encode(private_key_pem.encode('utf-8'))
    encoded_public_key = base64.b64encode(public_key_pem.encode('utf-8'))

    # Store the base64-encoded keys in Redis
    redis_client_rsa.set(f"rsa_private_key_{random.randint(1, 1000)}", encoded_private_key)
    redis_client_rsa.set(f"rsa_public_key_{random.randint(1, 1000)}", encoded_public_key)
