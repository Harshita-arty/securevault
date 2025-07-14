import os
import json
import getpass
import bcrypt
import datetime
from cryptography.fernet import Fernet

USERS_FILE = "users.json"
VAULT_DIR = "vault"
LOG_FILE = "logs.txt"

def log_event(username, action, filename=None):
    time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log:
        entry = f"[{time}] User: {username} | Action: {action}"
        if filename:
            entry += f" | File: {filename}"
        log.write(entry + "\n")

def init_user_db():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)

def save_user(username, password):
    with open(USERS_FILE, "r+") as file:
        users = json.load(file)
        if username in users:
            return False
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        users[username] = hashed_pw.decode()
        file.seek(0)
        json.dump(users, file, indent=4)
        os.makedirs(f"{VAULT_DIR}/{username}", exist_ok=True)
        with open(f"{VAULT_DIR}/{username}/secret.key", "wb") as key_file:
            key_file.write(Fernet.generate_key())
        return True

def verify_user(username, password):
    with open(USERS_FILE, "r") as file:
        users = json.load(file)
        if username not in users:
            return False
        hashed_pw = users[username].encode()
        return bcrypt.checkpw(password.encode(), hashed_pw)

def load_user_key(username):
    key_path = f"{VAULT_DIR}/{username}/secret.key"
    return open(key_path, "rb").read()

def encrypt_file(username, filename):
    try:
        key = load_user_key(username)
        f = Fernet(key)
        with open(filename, "rb") as file:
            data = file.read()
        encrypted = f.encrypt(data)
        encrypted_path = f"{VAULT_DIR}/{username}/{os.path.basename(filename)}.enc"
        with open(encrypted_path, "wb") as file:
            file.write(encrypted)
        print(f"🔐 File encrypted and saved as: {encrypted_path}")
    except Exception as e:
        print(f"❌ Encryption failed: {str(e)}")

def decrypt_file(username, enc_file):
    try:
        key = load_user_key(username)
        f = Fernet(key)
        with open(enc_file, "rb") as file:
            encrypted_data = file.read()
        decrypted = f.decrypt(encrypted_data)
        original_name = os.path.basename(enc_file).replace(".enc", "")
        decrypted_path = f"{VAULT_DIR}/{username}/{original_name}_decrypted"
        with open(decrypted_path, "wb") as file:
            file.write(decrypted)
        print(f"✅ Decrypted file saved as: {decrypted_path}")
    except Exception as e:
        print(f"❌ Decryption failed: {str(e)}")

def main():
    init_user_db()
    os.makedirs(VAULT_DIR, exist_ok=True)

    print("\n🔐 Welcome to SecureVault 🔐")
    while True:
        print("\n1️⃣ Register")
        print("2️⃣ Login")
        print("3️⃣ Exit")
        choice = input("Choose (1/2/3): ").strip()

        if choice == "1":
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            if save_user(username, password):
                print("✅ Registration complete.")
            else:
                print("❌ Username already exists.")
        elif choice == "2":
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            if verify_user(username, password):
                log_event(username, "LOGIN")
                print(f"✅ Welcome {username}!")
                user_menu(username)
            else:
                print("❌ Invalid username or password.")
        elif choice == "3":
            print("👋 Exiting SecureVault. Goodbye!")
            break
        else:
            print("❌ Invalid option. Please choose 1, 2, or 3.")

def user_menu(username):
    while True:
        print(f"\n🗄️ {username}'s Vault Menu")
        print("1️⃣ Encrypt a file (Input from 'files/' folder)")
        print("2️⃣ Decrypt a file (Input from your 'vault/' folder)")
        print("3️⃣ View logs")
        print("4️⃣ Logout")
        choice = input("Choose (1/2/3/4): ").strip()

        if choice == "1":
            filename = input("Enter path to file (e.g., files/hello.txt): ").strip()
            if os.path.exists(filename):
                encrypt_file(username, filename)
                log_event(username, "ENCRYPT", os.path.basename(filename))
            else:
                print("❌ File not found. Make sure it's in the 'files/' folder.")
        elif choice == "2":
            filename = input(f"Enter path to your encrypted file (e.g., vault/{username}/file.txt.enc): ").strip()
            if os.path.exists(filename):
                decrypt_file(username, filename)
                log_event(username, "DECRYPT", os.path.basename(filename))
            else:
                print("❌ Encrypted file not found in your vault.")
        elif choice == "3":
            try:
                with open(LOG_FILE, "r") as log:
                    print("\n📝 Audit Logs:")
                    for line in log.readlines():
                        if username in line:
                            print(line.strip())
            except FileNotFoundError:
                print("No logs found yet.")
        elif choice == "4":
            print("👋 Logging out...")
            break
        else:
            print("❌ Invalid option. Please choose 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()