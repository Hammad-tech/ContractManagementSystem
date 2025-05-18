import secrets
 
# Generate a secure random string for session secret
session_secret = secrets.token_hex(32)
print(f"Generated Session Secret: {session_secret}")
print("\nAdd this to your .env file as:")
print(f"SESSION_SECRET={session_secret}") 