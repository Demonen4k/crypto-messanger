import os
import time
import socket
import threading
from Crypto.Cipher import AES
from Crypto import Random
import base64
import binascii
import rsa
import atexit
import sys



BUFSIZE = 1024
#HOST = '25.43.140.124'
HOST = '127.0.0.1'
PORT = 4444
ADDR = HOST, PORT
connected = 2

def generate_rsa():
    global privkey_pem, pubkey_pem
    (pubkey, privkey) = rsa.newkeys(2048)

    pubkey_pem = pubkey.save_pkcs1()
    privkey_pem = privkey.save_pkcs1()

    with open('my_keys/private.bin', 'wb') as f:
        f.write(privkey_pem)
    with open('my_keys/public.pem', 'wb') as f:
        f.write(pubkey_pem)



def encrypt_key(key):
    with open('stranger_id/public_id.pem', 'rb') as f:
        public_id_pem = f.read()

    pubkey = rsa.PublicKey.load_pkcs1(public_id_pem, 'PEM')

    ciphertext = rsa.encrypt(key, pubkey)
    return ciphertext


def decrypt_key(cipherkey):
    with open('my_keys/private.bin', 'rb') as f:
        privkey_pem = f.read()
    privkey = rsa.PrivateKey.load_pkcs1(privkey_pem, 'PEM')

    key = rsa.decrypt(cipherkey, privkey)
    return key


def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


def encrypt(message, key):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)


def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")


def encrypt_file(key):
    with open('sender_files/data.txt', 'rb') as fo:
        data = fo.read()

    data = base64.b64encode(data)

    enc = encrypt(data, key)

    with open("sender_files/encrypted_data.txt.enc", 'wb') as fo:
        fo.write(enc)


def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    dec = base64.b64decode(dec)
    with open(file_name[:-4] + ".dec", 'wb') as fo:
        fo.write(dec)


class myThread:
    def __init__(self):
        
        global tcp_client, nick
        con = ''
        tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                tcp_client.connect(ADDR)
                break
            except ConnectionRefusedError:
                print('Сервер не запущен')
                time.sleep(5)

        if not os.path.isfile('config.txt'):
            nick = input("Введите имя пользователя: ")
            with open('config.txt', 'w') as f:
                f.write(nick)
        else:
            with open('config.txt', 'r') as f:
                nick = f.read()
        nick = nick.encode('utf-8')
        tcp_client.send(nick)
        self.taken_data = tcp_client.recv(BUFSIZE)
        print("\nSYS:", self.taken_data.decode('utf-8'))
        time.sleep(1)
        while True:
            self.taken_data = tcp_client.recv(BUFSIZE)
            con = self.taken_data.decode('utf-8')
            try:
                if con == 'SYS: second user is connected/':
                    with open('my_keys/public.pem', 'rb') as f:
                        my_id = f.read(BUFSIZE)
                        tcp_client.send(my_id)
                    break
            except:
                print('Второй пользователь не подключен')
                break
                    
                
        threading.Thread(target=self.message_monitoring, args=(tcp_client,)).start()
        
    def message_monitoring(self, server_socket):
        self.server_socket = server_socket
        global public_id_pem
        self.taken_data = server_socket.recv(BUFSIZE)
        public_id = self.taken_data
        with open('stranger_id/public_id.pem', 'wb') as f:
            f.write(public_id)
        threading.Thread(target=self.send_message).start()
        while True:
            time.sleep(3)
            try:
                with open('received_files/message.txt.enc', 'wb') as f:
                    self.taken_data = self.server_socket.recv(BUFSIZE)
                    f.write(self.taken_data)
                with open('received_files/message.txt.enc', 'rb') as f:
                    file = f.read()
                    message = file.split(b'<!d:d!>')
                    key_encrypted = message[0]
                    nick = message[1]
                    message_encrypted = message[2]

                with open('received_files/message.txt.enc', 'wb') as f:
                    f.write(message_encrypted)

                key = decrypt_key(key_encrypted)

                decrypt_file('received_files/message.txt.enc', key)
                with open('received_files/message.txt.dec', 'r') as f:
                    print(f'\n{nick.decode("utf-8")}: {f.read()}')
                    
                threading.Thread(target=self.send_message).start()
                
            except:
                if self.taken_data.decode('utf-8') == 'SYS: second user is disconnected/':
                    global connected
                    connected -= 1
                    if connected == 1:
                        close_connection()
                        main()
                
                    
           

    def send_message(self):
        while True:
            data = input('-> ')
            with open('sender_files/data.txt', 'w') as f:
                f.write(data)
            key = binascii.hexlify(os.urandom(16))
            try:
                encrypt_file(key)
            except:
                print('SYS: Сообщение не зашифровано')

            enc_key = encrypt_key(key)

            with open('sender_files/full_message.enc', 'wb') as sender_file:
                with open('sender_files/encrypted_data.txt.enc', 'rb') as enc_text:
                    enc_text = enc_text.read()
                sender_file.write(enc_key)
                sender_file.write(b'<!d:d!>')
                sender_file.write(nick)
                sender_file.write(b'<!d:d!>')
                sender_file.write(enc_text)

            try:
                with open('sender_files/full_message.enc', 'rb') as f:
                    send_data = ''
                    while send_data != b'':
                        send_data = f.read(BUFSIZE)
                        tcp_client.send(send_data)

            except ConnectionRefusedError:
                print('SYS: Произошла непредвиденная ошибка при отправке, попробуйте снова')
            except FileNotFoundError:
                print('SYS: Файл не существует')


def close_connection():
    tcp_client.send(b'exit')
    tcp_client.close()
    

def main():
    if not os.path.isfile('my_keys/private.bin'):
        print(generate_rsa())

    connect = myThread()
    
    atexit.register(close_connection)       

if __name__ == "__main__":
    main()
