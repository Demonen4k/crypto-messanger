import time
import socket
import threading

connected = 0

class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.all_client = []

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.ip, self.port))
        self.server.listen(0)
        threading.Thread(target=self.connect_handler).start()
        print('Сервер запущен')

    def connect_handler(self):
        global nick, connected
        while True:
            client, address = self.server.accept()
            if client not in self.all_client:
                nick = client.recv(1024)
                nick = nick.decode('utf-8')
                self.all_client.append(client)
                connected += 1
                threading.Thread(target=self.message_handler, args=(client,)).start()
                print(f'[{nick}] подключился')
                client.send('Вы онлайн'.encode('utf-8'))
                time.sleep(2)
            if connected == 2:
                print('Оба пользователя в сети')
                for con in self.all_client:
                    con.send('SYS: second user is connected/'.encode('utf-8'))
            time.sleep(1)

    def message_handler(self, client_socket):
        global connected
        while True:
            message = client_socket.recv(1024)

            if message == b'exit':
                self.all_client.remove(client_socket)
                print('Пользователь отключился')
                connected -= 1
                for disc in self.all_client:
                    if disc != client_socket:
                        disc.send('SYS: second user is disconnected/'.encode('utf-8'))
                break
                

            for client in self.all_client:
                if client != client_socket:
                    client.send(message)
                else:
                    print(f'{client} отправил сообщение: ', message)
            time.sleep(1.5)
            
myserver = Server('127.0.0.1', 4444)
#myserver = Server('25.43.140.124', 4444)
