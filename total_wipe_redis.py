import subprocess

# Full path to redis-cli.exe (Update the path as per your system)
redis_cli_path = "C:/Users/ramya/Downloads/Redis-x64-5.0.14.1/redis-cli.exe"

# Commands to run in redis-cli
commands = [
    "select 1", "flushdb",   # Clear DB 1
    "select 2", "flushdb",   # Clear DB 2
    "select 3", "flushdb",   # Clear DB 3
    "select 4", "flushdb",   # Clear DB 4
    "select 5", "flushdb",   # Clear DB 5
]

try:
    # Start redis-cli process
    redis_cli = subprocess.Popen(
        [redis_cli_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,  # Ensure text mode for input/output
    )

    # Send the flush commands to clear DBs
    command_string = "\n".join(commands) + "\n"
    stdout, stderr = redis_cli.communicate(input=command_string)

    # Output results
    print("STDOUT:")
    print(stdout)
    if stderr:
        print("STDERR:")
        print(stderr)

except FileNotFoundError:
    print(f"Error: redis-cli not found at {redis_cli_path}. Ensure the path is correct.")
except Exception as e:
    print(f"An error occurred: {e}")
