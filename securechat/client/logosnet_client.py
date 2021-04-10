'''
Client's stuff
'''

import argparse
import socket
import select
import queue
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

import LNP


def get_args():
    '''
    Gets command line argumnets.
    '''

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

    return parser.parse_args()

def is_private(msg):
    """
    isPrivate returns username of recipient if the msg is private and None otherwise
    """
    str1 = msg.split(' ')[0]

    if str1[0] == '@':
        return True
    return False


# Main method
def main():
    '''
    uses a select loop to process user and server messages. Forwards user input to the server.
    '''

    args = get_args()
    server_addr = args.ip
    port = args.port

    server = socket.socket()
    server.connect((server_addr, port))

    msg_buffer = {}
    recv_len = {}
    msg_len = {}
    msg_ids = {}
    symmetric_keys = {}
    client_private_key = ec.generate_private_key(ec.SECP384R1(),
                                                 backend=default_backend())
    end_to_end_keys = {}
    sender = ""
    receiver = ""
    realMessage = ""
    inputs = [server, sys.stdin]
    outputs = [server]
    message_queue = queue.Queue()

    waiting_accept = True
    username = ''
    username_next = False

    while server in inputs:

        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:

            ###
            ### Process server messages
            ###
            if s == server:

                # This point may iterate multiple times until the message is completely
                # read since LNP.recv, receives a few bytes at a time.
                code = LNP.recv(s, msg_buffer, recv_len, msg_len, msg_ids)

                # This will not happen until the message is switched to
                # MSG_COMPLETE when then it is read from the buffer.
                if code != "LOADING_MSG":
                    code_id, msg = LNP.get_msg_from_queue(s, msg_buffer, recv_len,
                                                          msg_len, msg_ids, symmetric_keys)                        

                    if code_id is not None:
                        code = code_id
                        # print("Message ID: " + id)

                if code == "MSG_CMPLT":
                     
                    # print("As soon as we get msg complt, message is: ", msg)
                    if username_next:
                        print("complete")
                        username_msg = msg
                        username = username_msg.split(' ')[1]
                        sys.stdout.write(username_msg + '\n')
                        sys.stdout.write("> " + username + ": ")
                        sys.stdout.flush()
                        username_next = False

                    elif msg:
                        # If username exists, add message prompt to end of message
                        if username != '':
                            name = msg.split()[2]
                            if name[0] == "b":
                                name = name[2:(len(name)-1)]
                            if is_private(name):
                                    wasSent = msg.split()[1]
                                    algorithm = algorithms.ARC4(end_to_end_keys[receiver])
                                    cipher = Cipher(algorithm, mode=None, backend=default_backend())
                                    decryptor = cipher.decryptor()
                                    part_decrypt = msg.split()[3]

                                    if part_decrypt[0] == "b":
                                        part_decrypt = part_decrypt[2:(len(part_decrypt)-1)]
 
                                    part_decrypt = part_decrypt.encode()
                                    part_decrypt = part_decrypt.decode('unicode-escape').encode('ISO-8859-1')
                                    
                                    decrypted_now = decryptor.update(part_decrypt)
                                    decrypted_now = str(decrypted_now)
                                    decrypted_now = decrypted_now[2:(len(decrypted_now)-1)]

                                    msg = "> " + wasSent + " " +  decrypted_now

                            sys.stdout.write('\r' + msg + '\n')
                            sys.stdout.write("> " + username + ": ")

                        # If username doesnt exist, just write message
                        else:
                            sys.stdout.write(msg)

                        sys.stdout.flush()

                # This and any other codes can be edited in protocol.py, this way
                # you can add new codes for new states, e.g., is this a public
                # key, CODE is PUBKEY and msg contains the key.
                elif code == "ACCEPT":
                    waiting_accept = False
                    sys.stdout.write(msg)
                    sys.stdout.flush()

                elif code == "DH-HELLO":
                    pub_key = client_private_key.public_key()

                    serial_public = pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.
                                                         SubjectPublicKeyInfo)

                    LNP.send(s, serial_public, "DH-KEY-EXCHANGE")

                elif code == "DH-REPLY":
                    new_pub_key = serialization.load_pem_public_key(msg.encode(),
                                                                    backend=default_backend())

                    shared_key = client_private_key.exchange(ec.ECDH(), new_pub_key)
                    symm_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                                    info=b'handshake data',
                                    backend=default_backend()).derive(shared_key)

                    symmetric_keys[s] = symm_key
                
                elif code == "P2P-KEY-EXCHANGE":
                        if msg[0] == "b":
                            msg = msg[2:(len(msg)-1)]
                            msg = msg.replace('\\n', '\n')
                        
                        new_pub_key = serialization.load_pem_public_key(msg.encode(),
                                                                        backend=default_backend())
                        shared_key = client_private_key.exchange(ec.ECDH(), new_pub_key)
                        symm_key = HKDF(algorithm=hashes.SHA256(), length=32,
                                        salt=None, info=b'handshake data',
                                        backend=default_backend()).derive(shared_key)

                        end_to_end_keys[sender] = symm_key

                        algorithm = algorithms.ARC4(end_to_end_keys[sender])
                        cipher = Cipher(algorithm, mode=None, backend=default_backend())
                        encryptor = cipher.encryptor()
                        part_encrypt = realMessage.split(" ", 1)[1]
                        part_encrypt = bytes(part_encrypt, encoding='utf8')
                        encrypted_now = encryptor.update(part_encrypt)
                        toSend = recip
                        sendy = bytes(toSend, encoding='utf8')
                        LNP.send(s,  f"{sendy} {encrypted_now}", None, symmetric_keys[s])
                
                elif code == "P2P-HELLO":
                    sender = msg
                    receiver = username

                    pub_key = client_private_key.public_key()

                    serial_public = pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.
                                                         SubjectPublicKeyInfo)
                    toSend = "@" + sender
                    sendy = bytes(toSend, encoding='utf8')
                                        
                    LNP.send(s, f"{sendy} {serial_public}", "P2P-KEY-EXCHANGE", symmetric_keys[s])

                elif code == "P2P-REPLY":
                    if msg[0] == "b":
                            msg = msg[2:(len(msg)-1)]
                            msg = msg.replace('\\n', '\n')
                    
                    new_pub_key = serialization.load_pem_public_key(msg.encode(),
                                                                    backend=default_backend())

                    shared_key = client_private_key.exchange(ec.ECDH(), new_pub_key)
                    symm_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                                    info=b'handshake data',
                                    backend=default_backend()).derive(shared_key)

                    end_to_end_keys[receiver] = symm_key

                elif code == "USERNAME-INVALID" or code == "USERNAME-TAKEN":
                    sys.stdout.write(msg)
                    sys.stdout.flush()

                elif code == "USERNAME-ACCEPT":
                    username_next = True

                elif code == "NO_MSG" or code == "EXIT":
                    sys.stdout.write(msg + '\n')
                    sys.stdout.flush()
                    inputs.remove(s)
                    if s in writable:
                        writable.remove(s)

                elif code == "CERTIFICATE-EXCHANGE":
                    try:
                        with open(f"{msg}.cert", "rb") as f:
                            LNP.send(s, f.read(), "CERTIFICATE-EXCHANGE", symmetric_keys[s])
                    except FileNotFoundError:
                        LNP.send(s, '', "NO-CERTIFICATE", symmetric_keys[s])
                        sys.stdout.write("No certificate found for that username.\n")
                        sys.stdout.flush()

            ###
            ### Process user input
            ###
            else:

                msg = sys.stdin.readline()

                if not waiting_accept:
                    msg = msg.rstrip()
                    if msg:
                        message_queue.put(msg)
                    if not ((username == '') or (msg == "exit()")):
                        sys.stdout.write("> " + username + ": ")
                        sys.stdout.flush()

        ###
        ### Send messages to server
        ###
        for s in writable:

            try:
                msg = message_queue.get_nowait()
            except queue.Empty:
                msg = None

            # if there is a message to send
            if msg:

                # if exit message, send the exit code
                if msg == "exit()":
                    outputs.remove(s)
                    LNP.send(s, '', "EXIT", symmetric_keys[s])

                # otherwise just send the messsage
                else:
                    if is_private(msg):
                        #check if already have security
                        recip = msg.split()[0]

                        if recip not in end_to_end_keys:
                            #if don't have, create
                            LNP.send(s, f"{recip} {username}", "P2P-HELLO", symmetric_keys[s])

                            receiver = recip[1:]
                            sender = username
                           
                            pub_key = client_private_key.public_key()

                            serial_public = pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.
                                                                PublicFormat.SubjectPublicKeyInfo)

                            recievv = bytes(recip, encoding='utf8')

                            LNP.send(s, f"{recievv} {serial_public}", "P2P-REPLY", symmetric_keys[s])

                            realMessage = msg
                            continue

                        algorithm = algorithms.ARC4(end_to_end_keys[sender])
                        cipher = Cipher(algorithm, mode=None, backend=default_backend())
                        encryptor = cipher.encryptor()
                        part_encrypt = msg.split()[0][1:]
                        encrypted_now = encryptor.update(part_encrypt)
                        message = recip + encrypted_now
                        LNP.send(s, message, None, symmetric_keys[s])

                    else:    
                        LNP.send(s, msg, None, symmetric_keys[s])

        for s in exceptional:
            print("Disconnected: Server exception")
            inputs.remove(s)

    server.close()


if __name__ == '__main__':
    main()
