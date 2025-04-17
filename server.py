import socket
import threading
import hashlib


class Server:
    def __init__(self, port: int) -> None:
        self.host = "127.0.0.1"
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate keys ...

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f"new person has joined: {username}")
            self.username_lookup[c] = username
            self.clients.append(c)

            # send public key to the client

            # ...

            # encrypt the secret with the clients public key

            # ...

            # send the encrypted secret to a client

            # ...

            threading.Thread(
                target=self.handle_client,
                args=(
                    c,
                    addr,
                ),
            ).start()

    def broadcast(self, msg: str):
        for client in self.clients:
            # encrypt the message
            # це зробимо після rsa

            client.send(msg.encode())

    def handle_client(self, c: socket.socket, addr):
        while True:
            msg = c.recv(1024)

            for client in self.clients:
                if client != c:
                    final_message = self.create_message(msg.decode())
                    client.send(final_message)

    def create_message(self, message):
        hash = self.get_hash(message)

        bytes = message.encode()
        final_message = hash + bytes
        return final_message

    def get_hash(self, message):
        return hashlib.sha256(message.encode()).digest()


if __name__ == "__main__":
    s = Server(9001)
    s.start()

