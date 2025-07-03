import secrets

# Generate a 32-byte hex key
secret_key = secrets.token_hex(32)
# salt = secrets.token_hex(16)

print("SECRET_KEY =", secret_key)
# print("SECURITY_PASSWORD_SALT =", salt)
