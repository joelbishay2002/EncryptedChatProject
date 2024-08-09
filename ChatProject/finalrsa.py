import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_message(public_key, message):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher_rsa.encrypt(message.encode())
    return encrypted_message

def decrypt_message(private_key, encrypted_message):
    key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    message = cipher_rsa.decrypt(encrypted_message)
    return message.decode()

def receiving_messages(c, text_area, private_key):
    while True:
        try:
            encrypted_message = c.recv(2048)
            message = decrypt_message(private_key, encrypted_message)
            text_area.configure(state='normal')
            text_area.insert(tk.END, "Partner: " + message + "\n")
            text_area.configure(state='disabled')
        except OSError:  # Possibly client has left the chat.
            break

def sending_messages(c, entry_widget, text_area, public_key):
    message = entry_widget.get()
    encrypted_message = encrypt_message(public_key, message)
    c.send(encrypted_message)
    text_area.configure(state='normal')
    text_area.insert(tk.END, "You: " + message + "\n")
    text_area.configure(state='disabled')
    entry_widget.delete(0, tk.END)

def start_client():
    choice = input("Would you like to host (1) or connect (2)? ")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    if choice == "1":
        private_key, public_key = generate_keys()
        client.bind(("localhost", 9999))
        client.listen(1)
        c, addr = client.accept()
        print("Connection accepted from ", addr)
        partner_public_key = c.recv(2048)  # Receive the partner's public key
        c.send(public_key)  # Send your public key
    elif choice == "2":
        private_key, public_key = generate_keys()
        host = input("Enter host IP: ")
        client.connect((host, 9999))
        c = client
        c.send(public_key)  # Send your public key
        partner_public_key = c.recv(2048)  # Receive the partner's public key
    else:
        return

    # Set up the GUI
    window = tk.Tk()
    window.title("Chat")
    
    text_area = scrolledtext.ScrolledText(window, state='disabled')
    text_area.grid(row=0, column=0, columnspan=2)
    
    message_entry = tk.Entry(window, width=50)
    message_entry.grid(row=1, column=0)
    
    send_button = tk.Button(window, text="Send", command=lambda: sending_messages(c, message_entry, text_area, partner_public_key))
    send_button.grid(row=1, column=1)
    
    thread = Thread(target=receiving_messages, args=(c, text_area, private_key))
    thread.start()
    
    window.mainloop()

if __name__ == "__main__":
    start_client()
