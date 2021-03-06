import socket
from kuznyechik import Kuznyechik
import binascii
import re
from getpass import getpass
from dfh import DiffieHellman


def partition(lst, siz):
    """
    Split list into chunks of equal length the size of the siz
    :param lst: string should be split into parts
    :param siz: size by which the string is broken.
    :return: list containing the string parts
    """
    return [lst[element:element + siz] for element in range(0, len(lst), siz)]


def send_mes(sock, key, mes):
    """
    Send encrypted message to host.
    :param sock: socket of connection with server.
    :param key: secret key.
    :param mes: message to send.
    :return:
    """
    big_text = partition(mes, 16)  # split the message into blocks of 256 bits
    sock.send(len(big_text).to_bytes(len(big_text).bit_length(), byteorder="big"))  # send amount of blocks to server
    # Encrypt each block and send them to host
    for i in big_text:
        data = bytes(i, "utf-8")  # str -> bytes
        mes = binascii.hexlify(data).zfill(32)  # bytes -> hex and expand message to 256 bit if it's nedeed
        crypto_text = Kuznyechik(key).encrypt(mes)  # encrypt message
        sock.send(crypto_text)  # send encrypted message to host


def receive_mes(sock, key):
    """
    Receive encrypted message from server and decrypt them.
    :param sock: socket of connection with sever.
    :param key: secret key.
    :return: decrypted message.
    """
    data = sock.recv(2048)  # receive amount blocks from host
    size = int.from_bytes(data, byteorder="big")  # bytes -> int
    text = ""  # buffer for message
    # Receive each block end decrypt them
    for i in range(size):
        data = sock.recv(2048)  # receive block from host
        text_hex = Kuznyechik(key).decrypt(data)  # decrypt that block
        text_str = str(binascii.unhexlify(text_hex), "utf-8")  # hex -> str
        text += text_str  # add block in buffer
    return text


def check_user(sock, key):
    """
    Check that user have permissions to communicate with server.
    :param sock: socket of connection with server.
    :return:
    True if user have permissions.
    False if user doesn't have permissions.
    """
    # receive message from server
    mes = receive_mes(sock, key)
    # input username
    username = input(mes)
    while not username:
        username = input("Empty string! " + mes)
    # send username to server
    send_mes(sock, key, username)
    # receive message from server
    mes = receive_mes(sock, key)
    # input password
    password = getpass(mes)
    while not password:
        password = getpass("Empty string! " + mes)
    # send password to server
    send_mes(sock, key, password)
    # receive answer from server
    mes = receive_mes(sock, key)
    # if answer is confirmation
    if re.findall(r"Ok", mes):
        return True
    elif re.findall(r"No", mes):
        print("Invalid username or password.")
        return False


if __name__ == "__main__":
    print("Start Client")
    Alice = DiffieHellman()  # class for Diffie-Hellman algorithm
    # Infinite loop. Activate Client; this will keep running until you interrupt the program with Ctrl-C or send empty string to Server
    while True:
        # Check that user input correct address
        while True:
            try:
                host, port = input("With who, you want to talk? IP Port\n").split(" ")
            except ValueError:
                print("Error! You should enter only IP and Port")
                continue
            except KeyboardInterrupt:
                # If user interrupt the program with Ctrl-C
                print("Close Client.")
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
                # if address isn't correct then output error
                print("Error! Wrong IP or Port.")
        # Create a socket (SOCK_STREAM means a TCP socket)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                # Connect to server and send data
                sock.connect((ip, int(port)))
                # Generates key for communication with host
                sock.send(Alice.publicKey.to_bytes(Alice.publicKey.bit_length(), byteorder="big"))  # send public key to host
                Bob_key = int.from_bytes(sock.recv(2048), byteorder="big")  # receive public key from host
                Alice.gen_key(Bob_key)  # generate session key
                key = str(binascii.hexlify(Alice.get_key()), "utf-8")  # convert key to string
                # check that user have permissions to communicate
                if check_user(sock, key):
                    print("-------Start communication-------")
                    while True:
                        try:
                            # Start communication with host
                            data_str = input("Enter your message:\n")
                            # If empty message then raise exception
                            if not data_str:
                                raise BrokenPipeError
                            send_mes(sock, key, data_str)
                            # Receive data from the server
                            text = receive_mes(sock, key)
                            print("Sent:     {}".format(data_str))  # output message that has been sent to host
                            print("Received: {}".format(text))  # output message from host
                        except BrokenPipeError:
                            # If empty message or there was some problem with connection, close socket and leave program
                            print("Close Client")
                            sock.close()
                            exit(0)
                else:
                    sock.close()
                    break
            except KeyboardInterrupt:
                # Leave program if user interrupt program with Ctr-C
                print("Close Client")
                sock.close()
                break
            # Block with exception
            except TypeError:
                print("Error with host address! You must enter correct host IP and Port.")
            except socket.gaierror:
                print("Error with host address! Nodename nor servname provided, or not known.")
            except ConnectionRefusedError:
                print("Connection refused.")
