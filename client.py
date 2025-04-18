import socket
import threading
import hashlib
from rsa import generate_key_pair, encode, decode, PublicKey, PrivateKey, MessageLengthError


class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.secret_key = None

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs
        self.private_key, self.public_key = generate_key_pair()

        # exchange public keys
        public_key_bytes = str(self.public_key.n).encode() + b'|' + str(self.public_key.e).encode()
        self.s.send(public_key_bytes)

        # receive the encrypted secret key
        server_public_key_data = self.s.recv(1024).decode()
        n_str, e_str = server_public_key_data.split('|')
        self.server_public_key = PublicKey(n=int(n_str), e=int(e_str))

        encrypted_secret = self.s.recv(1024)
        encrypted_secret_int = int.from_bytes(encrypted_secret, 'big')
        decrypted_secret_int = decode(encrypted_secret_int, self.private_key)
        self.secret_key = decrypted_secret_int.to_bytes((decrypted_secret_int.bit_length()+7)//8, 'big')

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self): 
        while True:
            message = self.s.recv(1024)

            if len(message) < 32:
                raise Exception('given message is to short')

            message_hash = message[:32]
            encrypted_message_bytes = message[32:]

            encrypted_message_int = int.from_bytes(encrypted_message_bytes, 'big')

            try:
                decrypted_message_int = decode(encrypted_message_int, self.private_key)
                decrypted_bytes = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8, 'big')
                decrypted_message = decrypted_bytes.decode()
            except Exception as e:
                print("failed to decode message:", e)
                continue
            
            hash = hashlib.sha256(decrypted_message.encode()).digest()

            if hash == message_hash:
                print(f"{decrypted_message}")
            else:
                print("message was damaged")

    def write_handler(self):
        while True:
            message = input()

            message_hash = self.get_hash(message)
            message_bytes = message.encode()
            message_int = int.from_bytes(message_bytes, 'big')

            try:
                encrypted_int = encode(message_int, self.server_public_key)
            except MessageLengthError:
                print("message too long for encryption")
                continue

            encrypted_bytes = encrypted_int.to_bytes((encrypted_int.bit_length() + 7) // 8, 'big')
            final_message = message_hash + encrypted_bytes

            self.s.send(final_message)
    
    def get_hash(self, message):
        return hashlib.sha256(message.encode()).digest()

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()