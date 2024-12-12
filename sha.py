import hashlib
import redis

# Connect to Redis database
redis_client_sha = redis.StrictRedis(host='localhost', port=6379, db=4)

def generate_sha256(model):
    
    sha256hash = hashlib.sha256(model).hexdigest()
    return sha256hash

def compare_hash(redis_key, model):
   
    try:
        # Retrieve the model data from Redis using the key
        redis_model = redis_client_sha.get(redis_key)
        
        if not redis_model:
            print(f"Key '{redis_key}' does not exist in the Redis database.")
            return None
        
        # Generate SHA-256 hashes
        redis_hash = generate_sha256(redis_model)
        model_hash = generate_sha256(model)

        # Compare the hashes
        if redis_hash == model_hash:
            print("Hashes match!")
            return True
        else:
            print("Hashes do not match.")
            return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
