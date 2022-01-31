from threading import *
import json
import socket
import netifaces as ni
import time
import select
import os
import bisect
import base64

RWND = 10
PORT = 12345
BUFFER_SIZE = 10240
HOSTNAME = socket.gethostname()
x = ni.gateways()
y = x['default'][2][1]
LOCAL_IP = ni.ifaddresses(y)[ni.AF_INET][0]['addr']
TYPE1_DICT_HEAD = {"type": 1, "name": HOSTNAME, "IP": LOCAL_IP}
TYPE2_DICT = {"type": 2, "name": HOSTNAME, "IP": LOCAL_IP}
TYPE2_JSTR = json.dumps(TYPE2_DICT).encode("utf-8")

contacts = {}
ACKS = {}
FILES = {}
contact_names = []
responded_stamps = []

escape = True


def chunkify(file):
    chunks = []
    data = file.read(1500)
    while data:
        chunks.append(data)
        data = file.read(1500)
    return chunks


def type4_wrapper(chunk, seq, filename):
    msg_dict = {"type": 4, "name": filename, "seq": seq, "body": base64.b64encode(chunk).decode('ascii'), "sender": HOSTNAME}
    msg_jstr = json.dumps(msg_dict)
    return msg_jstr


def send_file(recipient, path):
    recipient_ip = contacts[recipient]
    filename = os.path.basename(path)
    ACKS[filename] = {}
    try:
        with open(path, "rb") as file:
            chunks = chunkify(file)
    except FileNotFoundError:
        print_yellow("File not found, please enter a valid path.")
        return
    no_chunks = len(chunks)
    for i in range(no_chunks):
        send_chunk(recipient_ip, chunks[i], i, filename)
    send_chunk(recipient_ip, b'', no_chunks+1, filename) # final, empty chunk


def send_chunk(recipient_ip, chunk, seq, filename):
    if seq not in ACKS[filename]:
        ACKS[filename][seq] = False
    msg = type4_wrapper(chunk, seq, filename)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(msg.encode(), (recipient_ip, PORT))
    ack_daemon = Thread(target=ack_listener, args=(recipient_ip, chunk, seq, filename))
    ack_daemon.setDaemon(True)
    ack_daemon.start()


def ack_listener(recipient_ip, chunk, seq, filename):
    time_started = time.time()
    while not ACKS[filename][seq]:
        if time.time() > time_started + 1:
            break
        pass
    if not ACKS[filename][seq]:
        send_chunk(recipient_ip, chunk, seq, filename)


def discover():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        timestamp = int(time.time())
        TYPE1_DICT = TYPE1_DICT_HEAD
        TYPE1_DICT["ID"] = timestamp
        TYPE1_JSTR = json.dumps(TYPE1_DICT).encode("utf-8")
        for i in range(10):
            s.sendto(TYPE1_JSTR, ('<broadcast>', PORT))


def listen_udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('', PORT))
        result = select.select([s], [], [])
        while True:
            received = result[0][0].recv(BUFFER_SIZE)
            decoded = received.decode("utf-8")
            data_json = json.loads(decoded)
            if data_json["type"] == 1:
                if data_json["ID"] not in responded_stamps \
                        and data_json["IP"] != LOCAL_IP \
                        and data_json["name"] not in contact_names:
                    responded_stamps.append(data_json["ID"])
                    contacts[data_json["name"]] = data_json["IP"]
                    contact_names.append(data_json["name"])
                    destination_ip = data_json["IP"]
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        try:
                            s.connect((destination_ip, PORT))
                            s.sendall(TYPE2_JSTR)
                        except:
                            pass
            elif data_json["type"] == 4:
                payload = data_json["body"]
                sender_name = data_json["sender"]
                if payload == "":
                    save_file(sender_name, filename)
                sender_ip = contacts[sender_name]
                filename = data_json["name"]
                seq = data_json["seq"]
                received_chunk = (seq, payload)
                if filename not in FILES:
                    FILES[filename] = []
                bisect.insort(FILES[filename], received_chunk)
                send_ack(sender_ip, seq, filename)


def save_file(sender, filename):
    file = FILES[filename]
    byte_string = ""
    for chunk in file:
        byte_string += chunk[1]
    byte_data = base64.b64decode(byte_string)
    cwd = os.getcwd()
    path = os.path.join(cwd, filename)
    with open(path, 'wb+') as savefile:
        savefile.write(byte_data)
    FILES[filename] = []
    print_yellow("File {} received from {}, saved at {}.".format(filename, sender, cwd))


def type5_wrapper(seq, filename):
    msg_dict = {"type": 5, "name": filename, "seq": seq, "rwnd": RWND}
    msg_jstr = json.dumps(msg_dict).encode("utf-8")
    return msg_jstr


def send_ack(recipient_ip, seq, filename):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((recipient_ip, PORT))
        s.sendall(type5_wrapper(seq, filename))


def print_red(*message):
    print('\033[91m' + " ".join(message) + '\033[0m')


def print_green(*message):
    print('\033[92m' + " ".join(message) + '\033[0m')


def print_yellow(*message):
    print('\033[93m' + " ".join(message) + '\033[0m')


def listen_tcp():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LOCAL_IP, PORT))
        while True:
            s.listen()
            received = b''
            conn, addr = s.accept()
            with conn:
                while True:
                    data = conn.recv(BUFFER_SIZE)
                    received += data
                    if not data:
                        break

            decoded = received.decode("utf-8")
            data_json = json.loads(decoded)

            if data_json["type"] == 2:
                contacts[data_json["name"]] = data_json["IP"]
                contact_names.append(data_json["name"])

            elif data_json["type"] == 3:
                print_red(data_json["name"] + ": " + data_json["body"])

            elif data_json["type"] == 5:
                filename = data_json["name"]
                seq = data_json["seq"]
                ACKS[filename][seq] = True


def type3_wrapper(message):
    msg_dict = {"type": 3, "name": HOSTNAME, "body": message}
    msg_jstr = json.dumps(msg_dict).encode("utf-8")
    return msg_jstr


def write(message, recipient):
    global escape
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((contacts["{}".format(recipient)], PORT))
            s.sendall(type3_wrapper(message))
        except (KeyError, ConnectionRefusedError):
            contacts.pop(recipient)
            contact_names.remove(recipient)
            print_yellow("{} seems to have gone offline. Returning to the main menu.".format(recipient))
            escape = False
    return


def display_contacts():
    if not contacts.keys():
        print_yellow("There are no online contacts.")
        return
    for key in contacts.keys():
        print_yellow(key)


def chat(recipient):
    global escape
    print_yellow("chatting with", recipient)
    print_yellow("(type --exit to exit a chat)")

    while escape:
        msg = input()
        if msg == "--exit":
            return
        else:
            write(msg, recipient)
    escape = True


def main_menu():
    while True:
        print_green("What would you like to do?")
        print_green("contacts: see online contacts")
        print_green("chat: start a chat with a user")
        print_green("quit: exit the program")
        print_green("sendfile: send a file to a user")
        inp = input()

        if inp == 'contacts':
            display_contacts()

        elif inp == 'quit':
            try:
                print_yellow("Goodbye.")
                return
            except KeyError:
                print_yellow("Goodbye.")
                return

        elif inp == 'sendfile':
            print_green("Who would you like to send a file to?")
            inp = input()
            while inp not in contact_names:
                print_yellow("Please enter the name of an online user, or type --exit to return to the main menu.")
                inp = input()

                if inp == '--exit':
                    break

            if inp != '--exit':
                print_yellow("Please enter the ABSOLUTE path of the file you would like to send.")
                pathinp = input()
                send_file(inp, pathinp)
                print_yellow("File {} sent to {}.".format(os.path.basename(pathinp), inp))

        elif inp == 'chat':
            print_green("Who would you like to chat with?")
            inp = input()
            while inp not in contact_names:
                print_yellow("Please enter the name of an online user, or type --exit to return to the main menu.")
                inp = input()

                if inp == '--exit':
                    break

            if inp != '--exit':
                chat(inp)

            while inp not in contact_names:
                print_yellow("Please enter the name of an online user, or type --exit to return to the main menu.")
                inp = input()

                if inp == '--exit':
                    break

            if inp != '--exit':
                chat(inp)

        else:
            print_yellow("Invalid input.")

def main():
    listener_daemon = Thread(target=listen_tcp)
    listener_daemon.setDaemon(True)
    listener_daemon.start()

    udp_listener_daemon = Thread(target=listen_udp)
    udp_listener_daemon.setDaemon(True)
    udp_listener_daemon.start()
    discover()

    main_menu()


if __name__ == "__main__":
    main()
