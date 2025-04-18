import socket
import threading
import hashlib
import os
from rsa import generate_key_pair, encode, decode, PublicKey, PrivateKey


class Server:
    def __init__(self, port: int) -> None:
        self.host = "127.0.0.1"
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.client_public_keys = {}
        self.secret_keys = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = generate_key_pair()

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f"new person has joined: {username}")
            self.username_lookup[c] = username
            self.clients.append(c)

            public_key_bytes = f"{self.public_key.n}|{self.public_key.e}".encode()
            c.send(public_key_bytes)

            client_public_key_bytes = c.recv(1024).decode()
            n_str, e_str = client_public_key_bytes.split("|")
            client_public_key = PublicKey(int(n_str), int(e_str))
            self.client_public_keys[c] = client_public_key

            secret_key = os.urandom(16)
            self.secret_keys[c] = secret_key

            secret_int = int.from_bytes(secret_key, 'big')
            encrypted_secret = encode(secret_int, client_public_key)

            encrypted_bytes = encrypted_secret.to_bytes((encrypted_secret.bit_length()+7)//8, 'big')
            c.send(encrypted_bytes)

            threading.Thread(
                target=self.handle_client,
                args=(
                    c,
                    addr,
                ),
            ).start()

    def broadcast(self, msg: str):
        for client in self.clients:
            final_message = self.create_message(msg)
            client.send(final_message)

    def handle_client(self, c: socket.socket, addr):
        while True:
            msg = c.recv(1024)

            for client in self.clients:
                if client != c:
                    client.send(msg)

    def create_message(self, message):
        hash = self.get_hash(message)
        return hash + message.encode()

    def get_hash(self, message):
        return hashlib.sha256(message.encode()).digest()


if __name__ == "__main__":
    s = Server(9001)
    s.start()

