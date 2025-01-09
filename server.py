import socket
import multiprocessing
import hashlib
import os
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Diffie-Hellman parameters
P = 23  # A prime number (public)
G = 5   # A primitive root modulo P (public)

CREDENTIALS_FILE = 'creds.txt'

def load_credentials():
    if not os.path.exists(CREDENTIALS_FILE):
        return {}
    
    user_db = {}
    with open(CREDENTIALS_FILE, 'r') as file:
        for line in file:
            username, salt, password_hash, email = line.strip().split(':')
            user_db[username] = (salt, password_hash)
    return user_db

def save_credentials(username, salt, password_hash, email):
    with open(CREDENTIALS_FILE, 'a') as file:
        file.write(f"{username}:{salt}:{password_hash}:{email}\n")

def generate_salt(length=16):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def hash_password(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()

user_db = load_credentials()
uname = ""

def encrypt_message(shared_key, message):
    cipher = AES.new(shared_key, AES.MODE_CBC)
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + encrypted_message

def decrypt_message(shared_key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message[AES.block_size:]), AES.block_size)
    return decrypted_message.decode()

def main():
    print("\n\t>>>>>>>>>> XYZ University Chat Server <<<<<<<<<<\n\n")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('', 8080)
    server_socket.bind(server_address)
    server_socket.listen(5)

    while True:
        client_socket, client_address = server_socket.accept()
        process = multiprocessing.Process(target=handle_client, args=(client_socket,))
        process.start()
        client_socket.close()

def handle_client(client_socket):
    private_key = random.randint(1, P - 2)  # Server's private key
    public_key = pow(G, private_key, P)     # Server's public key

    client_socket.send(str(public_key).encode('utf-8'))
    client_public_key = int(client_socket.recv(256).decode('utf-8'))

    shared_secret = pow(client_public_key, private_key, P)
    combined_secret = str(shared_secret) + uname
    shared_key = hashlib.sha256(combined_secret.encode()).digest()
    #shared_key = hashlib.sha256(str(shared_secret).encode()).digest()
    #print("Shared secret computed on server:", combined_secret)

    client_socket.send(encrypt_message(shared_key, "Type 'register' to create a new account or 'login' to sign in: "))
    action = decrypt_message(shared_key, client_socket.recv(256)).strip()

    if action == 'register':
        register_user(client_socket, shared_key)
        action = decrypt_message(shared_key, client_socket.recv(256)).strip()

    if action == 'login':
        if not authenticate_user(client_socket, shared_key):
            client_socket.send(encrypt_message(shared_key, "Authentication failed. Disconnecting."))
            client_socket.close()
            return
    else:
        client_socket.send(encrypt_message(shared_key, "Invalid action. Disconnecting."))
        client_socket.close()
        return

    while True:
        buf = decrypt_message(shared_key, client_socket.recv(256))
        if buf == "exit":
            print("Client disconnected.")
            break

        print("Client:", buf)
        response = "Message received."
        client_socket.send(encrypt_message(shared_key, "Server: " + response))

    client_socket.close()

def register_user(client_socket, shared_key):
    client_socket.send(encrypt_message(shared_key, "Enter a unique username: "))
    username = decrypt_message(shared_key, client_socket.recv(256)).strip()

    if username in user_db:
        client_socket.send(encrypt_message(shared_key, "Username already exists. Enter to try again.\n"))
        return register_user(client_socket, shared_key)
    
    client_socket.send(encrypt_message(shared_key, "Enter a valid email: "))
    email = decrypt_message(shared_key, client_socket.recv(256)).strip()

    client_socket.send(encrypt_message(shared_key, "Enter your password: "))
    password = decrypt_message(shared_key, client_socket.recv(256)).strip()

    salt = generate_salt()
    password_hash = hash_password(password, salt)
    user_db[username] = (salt, password_hash)
    save_credentials(username, salt, password_hash, email)

    client_socket.send(encrypt_message(shared_key, "Registration successful! Type 'login' to continue.\n"))
    

def authenticate_user(client_socket, shared_key):
    client_socket.send(encrypt_message(shared_key, "Enter your username: "))
    username = decrypt_message(shared_key, client_socket.recv(256)).strip()

    client_socket.send(encrypt_message(shared_key, "Enter your password: "))
    password = decrypt_message(shared_key, client_socket.recv(256)).strip()

    if username in user_db:
        salt, stored_hash = user_db[username]
        password_hash = hash_password(password, salt)

        if password_hash == stored_hash:
            client_socket.send(encrypt_message(shared_key, "Login successful! Type 'exit' to disconnect.\n"))
            return True

    return False

if __name__ == "__main__":
    main()
