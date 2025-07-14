from cryptography.fernet import Fernet

# Step 1: Generate a key and save it to a file
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Step 2: Load the previously generated key
def load_key():
    return open("secret.key", "rb").read()

# Step 3: Encrypt a file
def encrypt_file(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename + ".enc", "wb") as file:
        file.write(encrypted_data)
    print(f"{filename} encrypted as {filename}.enc")

# Step 4: Decrypt a file
def decrypt_file(encrypted_filename, key):
    f = Fernet(key)
    with open(encrypted_filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    original_filename = encrypted_filename.replace(".enc", "")
    with open(original_filename + "_decrypted", "wb") as file:
        file.write(decrypted_data)
    print(f"{encrypted_filename} decrypted as {original_filename}_decrypted")

# Run it
if __name__ == "__main__":
    import os

    if not os.path.exists("secret.key"):
        generate_key()

    key = load_key()

    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Choose (1/2): ")

    if choice == "1":
        filename = input("Enter filename to encrypt (e.g., myfile.txt): ")
        encrypt_file(filename, key)

    elif choice == "2":
        filename = input("Enter filename to decrypt (e.g., myfile.txt.enc): ")
        decrypt_file(filename, key)

    else:
        print("Invalid choice")