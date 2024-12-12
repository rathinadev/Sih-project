import redis

# Connect to Redis
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

# List of database indices to check
db_indices = [1, 2, 3, 4,5]

def process_database(db_index):
    redis_client.execute_command('SELECT', db_index)  # Switch to the specified db
    keys = redis_client.keys('*')  # Get all keys in the selected db

    if db_index in [ 1,3,5]:  # For DBs 1, 2, and 4: Print keys and values
        print(f"Keys and Values in DB {db_index}:")
        if keys:
            for key in keys:
                key_str = key.decode()  # Decode the key from bytes to string
                value = redis_client.get(key)  # Get the value for the key
                try:
                    # Attempt to decode the value as UTF-8
                    value_str = value.decode('utf-8') if value else "None"
                except UnicodeDecodeError:
                    # Fall back to displaying raw bytes if decoding fails
                    value_str = repr(value)
                print(f"  Key: {key_str}, Value: {value_str}")
        else:
            print("  No keys found.")
    elif  db_index in [1,2,3]:  # For DB 3: Print keys only
        print(f"Keys in DB {db_index}:")
        if keys:
            for key in keys:
                key_str = key.decode()  # Decode the key from bytes to string
                print(f"  Key: {key_str}")
        else:
            print("  No keys found.")
    print()

# Process each database index
for db_index in db_indices:
    process_database(db_index)
