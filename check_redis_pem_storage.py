import redis
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

# Connect to Redis
redis_client = redis.StrictRedis(host='localhost', port=6379, db=2)

def check_rsa_key_format(redis_key, key_data):
    """Check if the given key data is a valid RSA key in PEM format."""
    try:
        # Try to load as private key
        try:
            private_key = serialization.load_pem_private_key(
                key_data.encode(), password=None, backend=default_backend())
            logger.info(f"{redis_key} loaded successfully as a private key.")
            return True
        except ValueError:
            # Not a private key, try to load as public key
            try:
                public_key = serialization.load_pem_public_key(
                    key_data.encode(), backend=default_backend())
                logger.info(f"{redis_key} loaded successfully as a public key.")
                return True
            except ValueError:
                logger.warning(f"{redis_key} is not in valid PEM format.")
                return False
    except Exception as e:
        logger.error(f"Error loading key {redis_key}: {e}")
        return False

def check_all_rsa_keys():
    """Fetch and check all RSA keys from Redis."""
    # Get all keys from Redis (adjust the pattern if needed)
    keys = redis_client.keys('*rsa*')
    
    for redis_key in keys:
        # Retrieve the key from Redis
        key_data = redis_client.get(redis_key).decode('utf-8')
        
        # Check if the key is valid
        if check_rsa_key_format(redis_key.decode('utf-8'), key_data):
            logger.info(f"Key {redis_key.decode('utf-8')} is valid.")
        else:
            logger.warning(f"Key {redis_key.decode('utf-8')} is invalid.")

if __name__ == '__main__':
    check_all_rsa_keys()
