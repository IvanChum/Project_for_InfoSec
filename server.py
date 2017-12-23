import socketserver
from kuznyechik import Kuznyechik
import binascii
import re
import json
import os
import hashlib
from getpass import getpass
from dfh import DiffieHellman


def partition(lst, siz):
    """
    Split list into chunks of equal length the size of the siz
    :param lst: string should be split into parts
    :param siz: size by which the string is broken.
    :return: list containing the string parts
    """
    return [lst[i:i+siz] for i in range(0, len(lst), siz)]


def add_user():
    """
    Add new user to database.
    :return:
    """
    print("---------Add new user---------")
    directory = os.getcwd()  # current directory
    # check that directory exists
    if os.path.exists(directory + '/data.json'):
        with open(directory + '/data.json') as input_file:
            data = json.load(input_file)  # read file and import from json object to dictionary
        username = input("Enter username:\n")
        hex_username = binascii.hexlify(username.encode()).zfill(32)
        hash_username = hashlib.md5(binascii.unhexlify(hex_username)).hexdigest()
        password = str(getpass())
        hex_password = binascii.hexlify(password.encode()).zfill(32)
        hash_password = hashlib.md5(binascii.unhexlify(hex_password)).hexdigest()
        data.update({hash_username: hash_password})  # add new username and password
    # if database doesn't exists
    else:
        username = input("Enter username:\n")
        hex_username = binascii.hexlify(username.encode()).zfill(32)
        hash_username = hashlib.md5(binascii.unhexlify(hex_username)).hexdigest()
        password = str(getpass())
        hex_password = binascii.hexlify(password.encode()).zfill(32)
        hash_password = hashlib.md5(binascii.unhexlify(hex_password)).hexdigest()
        data = {hash_username: hash_password}  # add new username and password
    # write new data to database
    with open(directory + '/data.json', "w", encoding="utf-8") as output_file:
        json.dump(data, output_file, ensure_ascii=False)  # import from dictionary to json object and write to file
    print("Successful add new user!")


def del_user():
    """
    Delete user from database.
    :return:
    """
    print("---------Delete user---------")
    # check that directory exists
    directory = os.getcwd()
    if os.path.exists(directory + '/data.json'):
        with open(directory + '/data.json') as input_file:
            data = json.load(input_file)  # read file and import from json object to dictionary
        username = input("Enter username, that you want to remove:\n")
        hex_username = binascii.hexlify(username.encode()).zfill(32)
        hash_username = hashlib.md5(binascii.unhexlify(hex_username)).hexdigest()
        # try to delete user
        try:
            data.pop(hash_username)
        # if user doesn't exist
        except KeyError:
            print("Username doesn't exists.")
            return
        # write new data to database
        with open(directory + '/data.json', "w", encoding="utf-8") as output_file:
            json.dump(data, output_file, ensure_ascii=False)  # import from dictionary to json object and write to file
        print("Successful delete user!")
    else:
        print("Database doesn't exist.")


def check_data():
    """
    Check that database exists.
    :return:
    True if database exists and isn't empty
    False otherwise.
    """
    directory = os.getcwd()
    if os.path.exists(directory + '/data.json'):
        with open(directory + '/data.json') as input_file:
            data = json.load(input_file)
        if data.keys():
            return True
        else:
            print("Empty database.")
            return False
    else:
        print("Database doesn't exist.")
        return False


def start_server():
    """
    Start server.
    :return:
    """
    while True:
        # Check that user input correct address
        try:
            host, port = input("Enter host address: IP Port\n").split(" ")
        except ValueError:
            print("Error! You should enter only IP and Port")
            continue
        # interrupt the program with Ctrl-C
        except KeyboardInterrupt:
            print("Close Server.")
            exit(-1)
        # Check type of IP and port
        try:
            if host.isdigit():  # if host is IP address (digit)
                ip = int(host)  # str -> integer
            else:
                ip = host  # else leave data in string
            if not port.isdigit():  # check that port is digit
                # if it isn't digit raise exception
                raise NameError
            break  # if address is correct then leave loop and go to next section
        except NameError:
            print("Wrong IP or Port.")
    print("Server start")
    print("Waiting for connection...")

    # Create the server, binding to localhost on port which user chooses
    with socketserver.TCPServer((ip, int(port)), MyTCPHandler) as server:
        try:
            # Activate the server; this will keep running until you
            # interrupt the program with Ctrl-C
            server.serve_forever()
        except KeyboardInterrupt:
            print("Shutdown server.")
            server.shutdown()


def check_key():
    """
    Check that file with private key exists.
    :return:
    True if file exists and isn't empty.
    False otherwise.
    """
    directory = os.getcwd()
    if os.path.exists(directory + "/private_key.txt") and os.path.exists(directory + "/public_key.txt"):
        with open(directory + "/private_key.txt") as key_file:
            private_key = key_file.read()
        with open(directory + "/public_key.txt") as key_file:
            public_key = key_file.read()
        if private_key and public_key:
            return True
        else:
            print("Empty file.")
            return False
    else:
        print("File with key doesn't exist.")
        return False


class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    Handler class.
    """
    def receive_mes(self, key):
        """
        Receive encrypted message from client and decrypt them.
        :param key: secret key.
        :return: decrypted message.
        """
        data = self.request.recv(2048)  # receive message from Client
        if not data:
            print("Close connection.")
            print("Waiting for new connection...")
            return None
        text = ""  # buffer for message
        size = int.from_bytes(data, byteorder="big")  # convert amount blocks from bytes to integer
        # For each block decrypt and add to buffer
        for i in range(size):
            data = self.request.recv(2048)  # receive block from client
            text_hex = Kuznyechik(key).decrypt(data)  # decrypt block
            text_str = str(binascii.unhexlify(text_hex), "utf-8")  # convert block from bytes to string
            text += text_str  # add block in buffer
        return text

    def send_mes(self, key, mes):
        """
        Send encrypted message to client.
        :param key: secret key.
        :param mes: message to send.
        :return: 
        """
        big_text = partition(mes, 16)  # split the message into blocks of 256 bits
        self.request.send(len(big_text).to_bytes(len(big_text).bit_length(), byteorder="big"))  # send amount of blocks to Client
        # For each message encrypt and then send them to Client
        for i in big_text:
            text_byte = bytes(i, "utf-8")
            text_hex = binascii.hexlify(text_byte).zfill(32)
            crypto_text = Kuznyechik(key).encrypt(text_hex)
            self.request.send(crypto_text)

    def check_user(self, key):
        """
        Check that user have permission to communication with server.
        :return:
        True if user have permission.
        False if user doesn't have permission.
        """
        # load database
        directory = os.getcwd()
        with open(directory + '/data.json') as input_file:
            data = json.load(input_file)
        # send message to client
        self.send_mes(key, "Enter username:\n")
        # receive username
        username = self.receive_mes(key)
        # send message to client
        hash_username = hashlib.md5(username.encode()).hexdigest()
        self.send_mes(key, "Enter password:\n")
        # receive password
        password = self.receive_mes(key)
        hash_password = hashlib.md5(password.encode()).hexdigest()
        # check that user exists and password is correct
        if data.get(hash_username) == hash_password:
            # sends a confirmation
            self.send_mes(key, "Ok")
            return True
        else:
            # send a failure
            self.send_mes(key, "No")
            return False

    def handle(self):
        # Read private key from file
        directory = os.getcwd()
        with open(directory + "/private_key.txt") as key_file:
            private_key = key_file.read()
        with open(directory + "/public_key.txt") as key_file:
            public_key = key_file.read()
        bob = DiffieHellman(private_key=int(private_key), public_key=int(public_key))  # class for Diffie-Hellman algorithm
        print("...Connecting from: ", self.client_address)
        data = self.request.recv(2048)  # receive message from Client
        # Generate key for communication with Client
        alice_key = int.from_bytes(data, byteorder="big")  # receive public key from Client
        self.request.send(bob.publicKey.to_bytes(bob.publicKey.bit_length(), byteorder="big"))  # send public key to Client
        bob.gen_key(alice_key)  # generate session key
        key = str(binascii.hexlify(bob.get_key()), "utf-8")  # convert key to string
        # Check user
        if self.check_user(key):
            print("-------Start communication-------")
            while True:
                text = self.receive_mes(key)
                if text is None:
                    break
                # Output message from and to Client
                print("{} wrote:   {}".format(self.client_address[0], text))
                text = text.upper()
                print("Send to {}: {}".format(self.client_address[0], text))
                # Send message to host
                self.send_mes(key, text)
        else:
            print("Close connection.")
            print("Waiting for new connection...")


if __name__ == "__main__":
    while True:
        print("---------Server options:---------")
        print("1) Add new user.")
        print("2) Delete user.")
        print("3) Start server.")
        ans = input("Print your answer:\n")
        while re.match(r"^[1-3]$", ans) is None:
            ans = input("Error! Print your answer:\n")
        if ans == "1":
            add_user()
        if ans == "2":
            del_user()
        if ans == "3":
            # check that database and file with key exists
            if check_data():
                if check_key():
                    start_server()
                else:
                    continue
            else:
                continue
