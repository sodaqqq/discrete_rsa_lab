import socket
import threading
import hashlib

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs

        # exchange public keys

        # receive the encrypted secret key

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self): 
        while True:
            message = self.s.recv(1024)

            if len(message) < 32:
                raise Exception('given message is to short')
                continue

            hash = message[:32]
            encrypted_message = message[32:]

            # decrypt message with the secrete key
            # ... 
            # стас тут твоє
            # decrypted_message = rsa_decrypt(encrypted_message, secret_key)

            decrypted_message = encrypted_message.decode() # тимчасово
            calculated_hash = hashlib.sha256(decrypted_message.encode()).digest()

            if calculated_hash == hash:
                print(f"{decrypted_message}")
            else:
                print("message was damaged")

    def write_handler(self):
        while True:
            message = input()

            hash = self.get_hash(message)
            # encrypted_message = rsa_encrypt(message, secret_key)
            # стас тут твоє шифрування
            bytes = message.encode()
            final_message = hash + bytes
            self.s.send(final_message)
    
    def get_hash(self, message):
        return hashlib.sha256(message.encode()).digest()

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()