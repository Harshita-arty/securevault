import json
import bcrypt
import os
import getpass

USERS_FILE = "users.json"

# Create users.json if not exists
def init_user_db():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)

# Save user to DB
def save_user(username, password):
    with open(USERS_FILE, "r+") as file:
        users = json.load(file)
        if username in users:
            return False  # Username already exists

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        users[username] = hashed_pw.decode()

        file.seek(0)
        json.dump(users, file, indent=4)
        return True

# Validate user login
def verify_user(username, password):
    with open(USERS_FILE, "r") as file:
        users = json.load(file)
        if username not in users:
            return False
        hashed_pw = users[username].encode()
        return bcrypt.checkpw(password.encode(), hashed_pw)

# User Interface
def main():
    init_user_db()
    print("🔐 SecureVault Login System")
    print("1. Register")
    print("2. Login")
    choice = input("Choose (1/2): ")

    username = input("Username: ")
    password = getpass.getpass("Password (hidden): ")

    if choice == "1":
        if save_user(username, password):
            print("✅ Registered successfully.")
        else:
            print("❌ Username already exists.")
    elif choice == "2":
        if verify_user(username, password):
            print("✅ Login successful!")
        else:
            print("❌ Invalid username or password.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()