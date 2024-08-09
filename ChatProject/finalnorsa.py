import socket
import threading

import rsa

choice = input("Would you like to host (1) or connect (2)")

if choice == "1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("10.106.100.147", 9999))
    server.listen()


    client, _ = server.accept()
elif choice == "2":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("10.106.100.147", 9999))
else:
    exit()

def sending_messages(c):
    while True:
        message = input("")
        c.send(message.encode())
        print("You: " + message)

def receiving_messages(c):
    while True:
        print("Partner: " + c.recv(1024).decode())

threading.Thread(target=sending_messages, args=(client,)).start()

threading.Thread(target=receiving_messages, args=(client,)).start()