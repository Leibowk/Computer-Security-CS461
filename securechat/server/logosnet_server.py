'''
Server's stuff
'''

import argparse
import socket
import select
import queue
import time

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

import LNP

MAX_USR = 100
TIMEOUT = 60


def is_username(name, usernames):
    """
    Returns a string code with status of username
    """
    if (len(name) < 1) or (len(name) > 10) or (' ' in name):
        return "USERNAME-INVALID"

    for snake_s in usernames:
        if name == usernames[snake_s]:
            return "USERNAME-TAKEN"

    return "CERTIFICATE-EXCHANGE"

def is_private(msg, usernames):
    """
    isPrivate returns username of recipient if the msg is private and None otherwise
    """
    str1 = msg.split()[0]

    if str1[0] == '@':

        user = str1[1:len(str1)]
        for sock in usernames:
            if usernames[sock] == user:
                return user

    return None


def broadcast_queue(msg, msg_queues, exclude=[]):
    """
    broadcast_queue loads the message into every message queue,
    excluding sockets in the exclude array
    """

    if msg and len(msg) <= 1000:
        for sock in msg_queues:
            if sock not in exclude:
                msg_queues[sock].put(msg)


def private_queue(msg, msg_queues, pvt_user, usernames):
    """
    private_queue loads the message into the queue of the client with the username pvt_user
    """
    for sock in msg_queues:
        if usernames[sock] == pvt_user:
            msg_queues[sock].put(msg)
            return


def validate_cert(username, cert, ca_public_key):
    """
    validate_cert checks to see if the user has a valid cert for the server.
    """
    if isinstance(username, (bytes, bytearray)):
        username = username.decode()

    try:
        ca_public_key.verify(cert, f"{username}\n".encode(), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False

    return True  # May need to change to some other return value


def get_args():
    """
    get command-line arguments
    """
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--port",
        metavar='p',
        dest='port',
        help="port number",
        type=int,
        default=42069
    )

    parser.add_argument(
        "--ip",
        metavar='i',
        dest='ip',
        help="IP address for client",
        default='127.0.0.1'
    )

    parser.add_argument(
        "--debug",
        help="turn on debugging messages",
        default=True,
        action="store_false"
    )

    return parser.parse_args()


def main():
    """
    Main method. Loops forever until killed
    """
    args = get_args()
    port = args.port
    a_ip = args.ip

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setblocking(0)
    server.bind((a_ip, port))
    server.listen(5)

    inputs = [server]
    outputs = []
    msg_queues = {}
    n_users = 0
    user_connect_time = {}

    # Dictionaries containing buffered messages and message state variable
    # Key for each is a socket object
    msg_buffers = {}
    recv_len = {}
    msg_len = {}
    usernames = {}
    requested_usernames = {}
    msg_ids = {}
    symmetric_keys = {}
    msg_id = None
    server_private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())

    with open("ca-key-public.pem", "rb") as f:
        ca_public_key = load_pem_public_key(f.read(), backend=default_backend())

    while inputs:

        # if 60 seconds are up no username yet, disconnect the client
        users = list(user_connect_time)
        for snake_s in users:
            if (time.time() - user_connect_time[snake_s]) > TIMEOUT:
                LNP.send(snake_s, '', "EXIT")

                inputs.remove(snake_s)
                outputs.remove(snake_s)
                n_users -= 1
                del user_connect_time[snake_s]

        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for snake_s in readable:

            #
            # Processing server connection requests
            #
            if snake_s is server:

                connection, client_addr = snake_s.accept()
                connection.setblocking(0)

                if n_users < MAX_USR:

                    LNP.send(connection, '', "ACCEPT")

                    # set up connection variables
                    inputs.append(connection)
                    outputs.append(connection)
                    n_users += 1
                    user_connect_time[connection] = time.time()

                    if args.debug:
                        print("        SERVER: new connection from " + str(client_addr))

                    #Setting up secure connection here. If new users are
                    # added, it messes up this. So need to do stuff to add
                    # to list and have get for each client.
                    LNP.send(connection, '', "DH-HELLO")

                    # serverPrivateKeys[s] = ec.generate_private_key(ec.SECP384R1(),
                    # backend=default_backend())

                    pub_key = server_private_key.public_key()

                    serial_public = pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.
                                                         PublicFormat.SubjectPublicKeyInfo)

                    LNP.send(connection, serial_public, "DH-REPLY")


                else:  # >100 users
                    LNP.send(connection, '', "FULL")
                    connection.close()

                    if args.debug:
                        print("        SERVER: connection from " +
                              str(client_addr) + " refused, server full")


            #
            # Processing client msgs
            #
            else:

                msg_status = LNP.recv(snake_s, msg_buffers, recv_len, msg_len, msg_ids)
                if msg_id is None:
                    msg_id = msg_status

                if msg_status == "MSG_CMPLT":

                    msg_id, msg = LNP.get_msg_from_queue(snake_s, msg_buffers, recv_len,
                                                         msg_len, msg_ids, symmetric_keys)

                    # LEAVE THE LINE BELOW ENABLED FOR TESTING PURPOSES, DO NOT CHANGE IT EITHER
                    # IF YOU ENCRYPT OR DECRYPT msg MAKE SURE THAT WHATEVER IS PRINTED FROM THE
                    # LINE BELOW IS PLAIN TEXT
                    # Note: for the end-to-end encryption clearly you
                    # will print whatever your receive
                    print("        received " + str(msg) + " from " +
                          str(snake_s.getpeername()), "\n")

                    if msg_id == "DH-KEY-EXCHANGE":
                        # print("Got Reply in Server I HAVE SECRET")
                        new_pub_key = serialization.load_pem_public_key(msg.encode(),
                                                                        backend=default_backend())
                        # privKey = serverPrivateKeys[s]
                        shared_key = server_private_key.exchange(ec.ECDH(), new_pub_key)
                        symm_key = HKDF(algorithm=hashes.SHA256(), length=32,
                                        salt=None, info=b'handshake data',
                                        backend=default_backend()).derive(shared_key)

                        # print("symmKey used in server: ", symmKey)
                        symmetric_keys[snake_s] = symm_key
                        # continue

                    elif msg_id == "CERTIFICATE-EXCHANGE":
                        if validate_cert(requested_usernames[snake_s], msg, ca_public_key):
                            LNP.send(snake_s, '', "USERNAME-ACCEPT", symmetric_keys[snake_s])
                            usernames[snake_s] = requested_usernames[snake_s]
                            del user_connect_time[snake_s]
                            del requested_usernames[snake_s]
                            msg_queues[snake_s] = queue.Queue()
                            msg = "User " + usernames[snake_s] + " has joined"
                            print("        SERVER: " + msg)
                            broadcast_queue(msg, msg_queues)
                            continue

                        #else: (pylint ATHINA complaints about else after a continue)
                        del requested_usernames[snake_s]
                        continue

                    elif msg_id == "NO-CERTIFICATE":
                        LNP.send(snake_s, '', "USERNAME-INVALID", symmetric_keys[snake_s])
                        continue

                    elif msg_id == "P2P-HELLO" or msg_id == "P2P-REPLY" or msg_id == "P2P-KEY-EXCHANGE":
                        to = msg.split()[0][1:]
                        print("message id is: ", msg_id)
                        print("message is: ", msg)
                        # print("The to is at this point: ", to, " ", type(to))

                        #Catch for if we sent the 
                        if to[1] == "@":
                            # print("in fix statement ")
                            to = to.split("@")[1]
                            to = to[:(len(to)-1)]
                        
                        # print("The to AFTER is: ", to, " ", type(to))

                        to_socket = [sock for sock, name in usernames.items() if name == to][0]
                        LNP.send(to_socket, msg.split(" ", 1)[1], msg_id, symmetric_keys[to_socket])
                        continue

                    # Username exists for this client, this is a message
                    if snake_s in usernames:
                        pvt_user = is_private(msg, usernames)
                        msg = "> " + usernames[snake_s] + ": " + msg
                        if pvt_user:
                            private_queue(msg, msg_queues, pvt_user, usernames)
                        else:
                            broadcast_queue(msg, msg_queues, exclude=[snake_s])


                    # no username yet, this message is a username
                    else:
                        username_status = is_username(msg, usernames)
                        # Send back request for certificate
                        # print("symm key being used is: ", symmetric_keys[s])
                        LNP.send(snake_s, msg, username_status, symmetric_keys[snake_s])

                        if username_status == "CERTIFICATE-EXCHANGE":
                            requested_usernames[snake_s] = msg

                        else:  # invalid username
                            user_connect_time[snake_s] = time.time()
                            msg = None


                #
                # Closing connection with client
                #
                elif msg_id == "NO_MSG" or msg_id == "EXIT":

                    if args.debug:
                        print("        SERVER: " + msg_id +
                              ": closing connection with " + str(snake_s.getpeername()))

                    outputs.remove(snake_s)
                    inputs.remove(snake_s)
                    if snake_s in writable:
                        writable.remove(snake_s)
                    if snake_s in msg_queues:
                        del msg_queues[snake_s]

                    # load disconnect message into msg_queues
                    if snake_s in usernames:
                        for sock in msg_queues:
                            msg_queues[sock].put("User " + usernames[snake_s] + " has left")
                        del usernames[snake_s]

                    if snake_s in user_connect_time:
                        del user_connect_time[snake_s]

                    # If user sent disconnect message need to send one back
                    if msg_id == "EXIT":
                        LNP.send(snake_s, '', "EXIT", symmetric_keys[snake_s])

                    n_users -= 1
                    snake_s.close()

        # Send messages to clients
        for snake_s in writable:

            if snake_s in msg_queues:

                try:
                    next_msg = msg_queues[snake_s].get_nowait()

                except queue.Empty:
                    next_msg = None

                if next_msg:
                    # if args.debug:
                    #     print("        sending " + next_msg + " to " + str(snake_s.getpeername()))
                    LNP.send(snake_s, next_msg, None, symmetric_keys[snake_s])

        # Remove exceptional sockets from the server
        for snake_s in exceptional:

            if args.debug:
                print("        SERVER: handling exceptional condition for " +
                      str(snake_s.getpeername()))

            inputs.remove(snake_s)
            # if s in outputs:
            outputs.remove(snake_s)
            del msg_queues[snake_s]
            del usernames[snake_s]
            snake_s.close()


if __name__ == '__main__':
    main()
