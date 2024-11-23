import socket

import threading
import curses
from curses import wrapper
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class Encrypt:
    def __init__(self):
        # create the key objects for the user
        self.myPrivateKey, self.myPubKey = self.genKeys()
        self.receiver_public_key = None

    # generate a public and private key for the user
    def genKeys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    # encrypt the message with the receiver's public key
    def asymmetric_encrypt(self, plaintext):
        return self.receiver_public_key.encrypt(
            bytes(plaintext, 'utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # decrypt the message with the sender's private key
    def asymmetric_decrypt(self, ciphertext):
        return self.myPrivateKey.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode('utf-8')

    # convert from key object to bytes
    def serialize(self, key):
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

    # convert from bytes to key object
    def deserialize(self, key_bytes):
        return serialization.load_pem_public_key(key_bytes)


class Window:
    winHeight = 0
    winWidth = 0
    outputWindow = None
    inputWindow = None
    outputRow = 0

    def __init__(self):
        self.window = wrapper(self.makeWindow)

    # make the input and output boxed on the window
    def makeWindow(self, stdscr):
        stdscr.clear()
        self.winHeight, self.winWidth = stdscr.getmaxyx()
        self.outputWindow = curses.newwin(self.winHeight - 5, self.winWidth, 0, 0)
        self.inputWindow = curses.newwin(3, self.winWidth, self.winHeight - 4, 0)

    # prints to the output box
    def printToOutput(self, sender, message):
        self.outputWindow.addstr(self.outputRow, 0, f'{sender}: {message}\n')
        self.outputWindow.refresh()
        self.outputRow += 1

    # print the user input in the input box
    def printRealTime(self, marker='> '):
        message = []
        while True:
            self.inputWindow.addstr(0, 0, marker)
            self.inputWindow.refresh()
            while True:
                key = self.inputWindow.getch()
                if key == ord('\n'):
                    self.inputWindow.clear()
                    self.inputWindow.refresh()
                    return ''.join(message)
                elif key == curses.KEY_BACKSPACE or key == 127:
                    if message:
                        message.pop()
                        y, x = self.inputWindow.getyx()
                        self.inputWindow.addch(y, x-1, ' ')
                        self.inputWindow.move(y, x-1)
                else:
                    message.append(chr(key))
                    self.inputWindow.addch(key)


class Client:
    # create a
    host = socket.gethostbyname(socket.gethostname())
    receiverAddress = ''
    e = Encrypt()

    def __init__(self):
        serverOrUser = int(window.printRealTime('Would you like to run as a server (1) or as a user (2): '))
        if serverOrUser == 1:
            self.openServer()
        else:
            self.searchForUser()

    def sendMessage(self, connection):
        while True:
            message = window.printRealTime('(You) > ')
            if message == 'exit':
                window.printToOutput('', 'Connection terminated.')
                connection.send(message.encode('utf-8'))
                connection.close()
            window.printToOutput(f'{self.host} (You)', message)
            # add encryption method call here
            message = self.e.asymmetric_encrypt(message)
            connection.send(message)

    def receiveMessage(self, connection):
        while True:
            try:
                # receive the message
                message = connection.recv(1042)
                # decrypt the message
                message = self.e.asymmetric_decrypt(message)
                if not message:
                    break
                if message == 'exit':
                    window.printToOutput('', 'Connection terminated.')
                    connection.close()
                    exit(1)

                # send message to window
                window.printToOutput(self.receiverAddress, message)
            except ():
                window.printToOutput(self.host, 'Connection closed.')
                connection.close()

    def exchangeKeys(self, connection):
        connection.send(self.e.serialize(self.e.myPubKey))
        self.e.receiver_public_key = self.e.deserialize(connection.recv(1042))

    def openServer(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', 6006))
        server.listen(1)
        print('Server started, waiting for connection...')

        while True:
            # accept incoming connections
            connection, addr = server.accept()
            self.receiverAddress = addr[0]
            # exchange keys here
            self.exchangeKeys(connection)
            # clear windows first
            window.outputWindow.clear()
            window.inputWindow.clear()
            window.outputWindow.refresh()
            window.inputWindow.refresh()
            # start connection thread between two clients
            threading.Thread(target=self.sendMessage, args=(connection,)).start()
            threading.Thread(target=self.receiveMessage, args=(connection,)).start()

    def searchForUser(self):
        host = window.printRealTime('Enter the IP address you would like to connect to: ')
        myClientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        myClientSocket.connect((host, 6006))
        self.receiverAddress = host
        # exchange keys here
        self.exchangeKeys(myClientSocket)
        # clear windows first
        window.outputWindow.clear()
        window.inputWindow.clear()
        window.outputWindow.refresh()
        window.inputWindow.refresh()
        # once connection is established, start send/receive threads
        threading.Thread(target=self.sendMessage, args=(myClientSocket,)).start()
        threading.Thread(target=self.receiveMessage, args=(myClientSocket,)).start()


window = Window()
def main():
    Client()


if __name__ == '__main__':
    main()

