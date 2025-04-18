import socket
import threading
import hashlib
from rsa import generate_key_pair, encode, decode, PublicKey, MessageLengthError

class Server:
    def __init__(self, port: int) -> None:
        self.host = "127.0.0.1"
        self.port = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []
        self.usernames = {}
        self.public_keys = {}
        self.private_key, self.public_key = generate_key_pair()

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)
        print(f"listening port {self.port}")

        while True:
            c, addr = self.s.accept()
            threading.Thread(target=self.handle_client, args=(c,)).start()

    def handle_client(self, c: socket.socket):
        username = c.recv(1024).decode()
        self.usernames[c] = username
        self.clients.append(c)
        print(f"{username} connected")

        server_pub = f"{self.public_key.n}|{self.public_key.e}".encode()
        c.send(server_pub)

        client_pub = c.recv(1024).decode()
        n_str, e_str = client_pub.split("|")
        client_public_key = PublicKey(n=int(n_str), e=int(e_str))
        self.public_keys[c] = client_public_key

        while True:

            data = c.recv(8192)
            if not data:
                break

            hash = data[:32]
            encrypted = data[32:]

            decrypted_int = decode(int.from_bytes(encrypted, 'big'), self.private_key)
            decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
            decrypted_message = decrypted_bytes.decode()

            if hashlib.sha256(decrypted_message.encode()).digest() != hash:
                print(f"failed integrity check")
                continue

            print(f"[{username}]: {decrypted_message}")
            self.broadcast(decrypted_message)

        self.clients.remove(c)
        del self.usernames[c]
        del self.public_keys[c]
        c.close()

    def broadcast(self, message: str):
        for client in self.clients:
            try:
                pubkey = self.public_keys[client]
                message_bytes = message.encode()
                hash = hashlib.sha256(message_bytes).digest()
                message_int = int.from_bytes(message_bytes, 'big')
                encrypted_int = encode(message_int, pubkey)
                encrypted_bytes = encrypted_int.to_bytes((encrypted_int.bit_length() + 7) // 8, 'big')
                message_final = hash + encrypted_bytes
                client.send(message_final)
            except Exception:
                print(f"failed to send message")

if __name__ == "__main__":
    Server(9001).start()