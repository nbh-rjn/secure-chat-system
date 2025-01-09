import socket
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Diffie-Hellman parameters (must match server)
P = 23  # Same prime number
G = 5   # Same primitive root
uname = ""

def create_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8080)
    sock.connect(server_address)
    return sock

def encrypt_message(shared_key, message):
    cipher = AES.new(shared_key, AES.MODE_CBC)
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + encrypted_message  # Send IV with encrypted message

def decrypt_message(shared_key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message[AES.block_size:]), AES.block_size)
    return decrypted_message.decode()

def main():
    print("\n\t>>>>>>>>>> XYZ University Chat Client <<<<<<<<<<\n\n")
    sock = create_socket()

    # Diffie-Hellman Key Exchange
    private_key = random.randint(1, P - 2)  # Client's private key
    public_key = pow(G, private_key, P)     # Client's public key

    # Receive server's public key
    server_public_key = int(sock.recv(256).decode('utf-8'))
    # Send client's public key
    sock.send(str(public_key).encode('utf-8'))

    # Compute shared secret and generate AES key
    shared_secret = pow(server_public_key, private_key, P)
    combined_secret = str(shared_secret) + uname
    shared_key = hashlib.sha256(combined_secret.encode()).digest()
    #shared_key = hashlib.sha256(str(shared_secret).encode()).digest()
    #print("Shared secret computed on client:", combined_secret)

    # Proceed with authentication or registration
    print(decrypt_message(shared_key, sock.recv(256)))

    action = ''
    while action != 'register' and action != 'login':
        action = input("You: ")

    sock.send(encrypt_message(shared_key, action))
    print(decrypt_message(shared_key, sock.recv(256)))

    # Start chat session
    while True:
        message = input("You: ")
        sock.send(encrypt_message(shared_key, message))

        if message == "exit":
            print("You disconnected from the chat.")
            break

        response = decrypt_message(shared_key, sock.recv(256))
        print(response)

        if "Authentication failed. Disconnecting." in response:
            break

    sock.close()

if __name__ == "__main__":
    main()
