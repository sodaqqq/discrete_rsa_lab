import socket
import threading
import hashlib
from rsa import generate_key_pair, encode, decode, PublicKey, MessageLengthError

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.server_ip, self.port))
        self.s.send(self.username.encode())

        pub = self.s.recv(1024).decode()
        n_str, e_str = pub.split("|")
        self.server_pub = PublicKey(int(n_str), int(e_str))
        self.priv_key, self.pub_key = generate_key_pair()
        pub_to_send = f"{self.pub_key.n}|{self.pub_key.e}".encode()
        self.s.send(pub_to_send)

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        while True:
            data = self.s.recv(8192)
            if not data:
                break

            hash = data[:32]
            encrypted = data[32:]
            decrypted_int = decode(int.from_bytes(encrypted, 'big'), self.priv_key)
            decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
            message = decrypted_bytes.decode()

            if hashlib.sha256(message.encode()).digest() == hash:
                print(message)
            else:
                print("integrity check failed :(")


    def write_handler(self):
        while True:
            message = input()

            try:
                message_bytes = message.encode()
                message_hash = hashlib.sha256(message_bytes).digest()
                message_int = int.from_bytes(message_bytes, 'big')
                encrypted_int = encode(message_int, self.server_pub)
                encrypted_bytes = encrypted_int.to_bytes((encrypted_int.bit_length() + 7) // 8, 'big')
                message_final = message_hash + encrypted_bytes
                self.s.send(message_final)
            except MessageLengthError:
                print("message too long for RSA")

if __name__ == "__main__":
    Client("127.0.0.1", 9001, "b_g").init_connection()
