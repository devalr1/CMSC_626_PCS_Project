import socket
import time
import sys
import hashlib
import getpass
from configparser import ConfigParser
import rsa
import base64
from cryptography.hazmat.primitives import serialization
import os
import hashlib

userName = None

# Fernet for filename encryption

# READ SERVER PUBLIC KEY FOR ENCRYPTION
server_public_key = None
filename = f'../keys/server.public_key.pem'

with open(filename, 'rb') as f:
    key_data = f.read()
server_public_key = rsa.PublicKey.load_pkcs1(key_data)


# CREATE KEYS FOR EACH USER
def generate_key_pair(username):

    # Generate a new RSA key pair
    (public_key, private_key) = rsa.newkeys(3072)

    # Convert the keys to their PEM string representation
    public_key_pem = public_key.save_pkcs1()
    private_key_pem = private_key.save_pkcs1()

    # Store the keys in separate files in a directory named "keys"    
    if not os.path.exists('../keys'):
        os.makedirs('../keys')
        
    with open(f'../keys/{username}.public_key.pem', 'wb') as f:
        f.write(public_key_pem)
        
    with open(f'../keys/{username}.private_key.pem', 'wb') as f:
        f.write(private_key_pem)

    return private_key, public_key

# READ KEYS FOR COMMUNICATION
def read_keys(username):
    parent_dir = os.path.abspath('..')
    key_dir = os.path.join(parent_dir, "keys")
    public_key_file = os.path.join(key_dir, f"{username}_public.pem")
    private_key_file = os.path.join(key_dir, f"{username}_private.pem")
    
    # Read the public key from the file
    with open(public_key_file, mode="rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
        
    # Read the private key from the file
    with open(private_key_file, mode="rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    
    return public_key, private_key

# READ USER PRIVATE KEY FOR DECRYPTION
def read_private_key_from_file(username):
    private_key_file = f'../keys/{username}.private_key.pem'
    with open(private_key_file, 'rb') as f:
        key_data = f.read()
    private_key = rsa.PrivateKey.load_pkcs1(key_data)
    return private_key


def send_to_all_servers(client_message, content):
    message_recv_from_server1 = send_data_to_server1(content)
    message_recv_from_server2, message_recv_from_server3 = send_data_to_all_servers(client_message, content)
    return message_recv_from_server1, message_recv_from_server2, message_recv_from_server3


def send_data_to_all_servers(client_message, content):
    message_recv_from_server2 = send_data_to_server2(client_message, content)
    message_recv_from_server3 = send_data_to_server3(client_message, content)
    return message_recv_from_server2, message_recv_from_server3


def send_to_server_replicas(client_message, content):
    message_recv_from_server2 = send_to_server2(client_message, content)
    message_recv_from_server3 = send_to_server3(client_message, content)
    return message_recv_from_server2, message_recv_from_server3


def send_to_server1(message):
    # HOST = '10.200.137.77'
    # HOST = socket.gethostbyname(socket.gethostname())
    host = socket.gethostbyname('localhost')
    port = 9090
    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_socket.connect((host, port))

    send_msg = message.encode('utf-8')
    encrypted_msg = rsa.encrypt(send_msg, server_public_key)
    s_socket.send(encrypted_msg)

    message_recv_from_server1 = None
    if (message.split('|')[0] in ["ls"]) or (
            message.split(' ')[0] in ["create", "cd", "delete", "mkdir", "write", "rename"]):
        
        message_recv_from_server1 = s_socket.recv(1024)#.decode('utf-8')
        message_recv_from_server1 = rsa.decrypt(message_recv_from_server1, read_private_key_from_file(userName))

    elif message.split(' ')[0] in ["read"]:
        message_recv_from_server1 = s_socket.recv(1024)
        message_recv_from_server1 = rsa.decrypt(message_recv_from_server1, read_private_key_from_file(userName))
    s_socket.close()
    
    return message_recv_from_server1


def send_data_to_server1(content):
    host = socket.gethostbyname('localhost')
    port = 9090
    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_socket.connect((host, port))
    encrypted_content = rsa.encrypt(content.encode('utf-8'), server_public_key)
    s_socket.send(encrypted_content)

    message_recv_from_server = None
    message_recv_from_server = s_socket.recv(1024)
    message_recv_from_server = rsa.decrypt(message_recv_from_server, read_private_key_from_file(userName))
    s_socket.close()
    
    return message_recv_from_server


def send_to_server2(client_message, content):
    try:
        host = socket.gethostbyname('localhost')
        port = 9091
        s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_socket.connect((host, port))
        status2 = ('Client Connected to Server2', 'Server2')
        print(status2[0], status2[1])

        command = client_message + ' | ' + content

        encrypted_command = rsa.encrypt(command.encode('utf-8'), server_public_key)
        s_socket.send(encrypted_command)#inside .encode('utf-8')
        response = s_socket.recv(1024)
        response = rsa.decrypt(response, read_private_key_from_file(userName))#.decode('utf-8')
        s_socket.close()
        return response
    except ConnectionRefusedError:
        status2 = ('Could not connect to Server2', 'Server2')
        print(status2[0], status2[1])


def send_data_to_server2(client_message, content):
    host = socket.gethostbyname('localhost')
    port = 9091
    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_socket.connect((host, port))
    status2 = ('Client Connected to Server2', 'Server2')
    print(status2[0], status2[1])

    command = client_message + ' | ' + content
    command = rsa.encrypt(command.encode('utf-8'), server_public_key)
    
    s_socket.send(command)
    message_recv_from_server = None
    message_recv_from_server2 = s_socket.recv(1024)
    message_recv_from_server2 = rsa.decrypt(message_recv_from_server2, read_private_key_from_file(userName))

    s_socket.close()
    return message_recv_from_server2


def send_to_server3(client_message, content):
    try:
        host = socket.gethostbyname('localhost')
        port = 9092
        s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_socket.connect((host, port))
        status3 = ('Client Connected to Server3', 'Server3')
        print(status3[0], status3[1])
        command = client_message + ' | ' + content

        encrypted_command = rsa.encrypt(command.encode('utf-8'), server_public_key)
        s_socket.send(encrypted_command)
        response = s_socket.recv(1024)
        response = rsa.decrypt(response, read_private_key_from_file(userName)).decode()
        time.sleep(1)
        s_socket.close()
        return response
    except ConnectionRefusedError:
        status3 = ('Could not connect to Server3', 'Server3')
        print(status3[0], status3[1])


def send_data_to_server3(client_message, content):
    host = socket.gethostbyname('localhost')
    port = 9092
    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_socket.connect((host, port))
    status2 = ('Client Connected to Server3', 'Server3')
    print(status2[0], status2[1])

    command = client_message + ' | ' + content
    command = rsa.encrypt(command.encode('utf-8'), server_public_key)
    s_socket.send(command)
    message_recv_from_server = None
    message_recv_from_server3 = s_socket.recv(1024)
    message_recv_from_server3 = rsa.decrypt(message_recv_from_server3, read_private_key_from_file(userName))

    s_socket.close()
    return message_recv_from_server3


def encrypting_pwd(word):
    result = hashlib.md5(word.encode())
    return result.hexdigest()


def creating_new_user():
    config = ConfigParser()
    config.read('auth.ini')
    username_list = list(config['AUTHENTICATION'])
    username = input("please enter your new username: ")
    if username in username_list:
        print("Error creating new user. user already exists!")
        sys.exit()
    pwd = input("please enter your new password: ")
    enc_pwd = encrypting_pwd(pwd)

    user_pubKey, user_privKey = generate_key_pair(username)

    config.set('AUTHENTICATION', username, enc_pwd)

    with open('auth.ini', 'w') as configfile:
        config.write(configfile)


def revoke_keys(username):
    public_key, private_key = generate_key_pair(username)
    print("Key revocation successful. You now have new keys generated in \"../keys\" directory.")


def main():
    config = ConfigParser()
    config.read('auth.ini')
    username_list = list(config['AUTHENTICATION'])
    #print("username: ", username_list)
    print("-------- WELCOME ---------")
    existing_user = input("Existing user? Y/N: ")
    if existing_user != 'Y':
        print('Please create a new user')
        creating_new_user()
        print('User created successfully')
        sys.exit()
    user_status = 'Not Verified'
    attempt = 0
    while user_status == 'Not Verified':
        username = input("Enter Your Username : ")
        password_bfr = getpass.getpass("Enter Your Password : ")
        password = encrypting_pwd(password_bfr)
        attempt += 1
        if (username in username_list) and (password == config['AUTHENTICATION'][username]):
            user_status = 'Verified user'
            global userName
            userName = username
        else:
            print("1 Please enter a valid password.You have " + str(3 - attempt) + " left.")
        if attempt == 3:
            print("Your access has been denied. Please try again.")
            sys.exit()

    while True:
        print("Hello..", username)
        client_message = input("Enter the command you want to perform: ")
        #message_recv_from_server = send_to_server1(client_message + '|' + username)
        client_message_0 = client_message.split()[0]
        if len(client_message.split()) > 1:
            wanted_filename = client_message.split()[1]
        if client_message_0 == "ls":
            #message_recv_from_server = send_to_server1(client_message + '|' + username)
            
            message_recv_from_server2, message_recv_from_server3 = send_to_server_replicas(
                client_message + '|' + username, "None")
            print("The list of existing files: \n", message_recv_from_server2.decode())
        if client_message_0 == "create": # FORMAT: create filename.txt

            # ask for permissions. Enter them in a file for each file, in a directory called perms            
            
            print('Following are the users: ', username_list)
            read_perm = input('Enter a comma separated list of users who you want to give READ permissions.')
            write_perm = input('Enter a comma separated list of users who you want to give WRITE permissions.')
            delete_perm = input('Enter a comma separated list of users who you want to give DELETE permissions.')
            restore_perm = input('Enter a comma separated list of users who you want to give RESTORE permissions.')
            parent_dir = os.path.abspath('..')
            perms_dir = os.path.join(parent_dir, "perms")

            if not os.path.exists('../perms'):
                os.makedirs('../perms')

            config_perm = ConfigParser()
            config_perm.add_section('PERMISSIONS')
            config_perm.set('PERMISSIONS', 'read', read_perm)
            config_perm.set('PERMISSIONS', 'write', write_perm)
            config_perm.set('PERMISSIONS', 'delete', delete_perm)
            config_perm.set('PERMISSIONS', 'restore', restore_perm)

            wanted_perm_filename = wanted_filename+".ini"
            filename_hash = hashlib.sha256()
            filename_hash.update(wanted_perm_filename.encode())
            wanted_perm_filename = filename_hash.hexdigest()

            perms_file_path = '../perms/'+wanted_perm_filename
            if not os.path.exists(perms_file_path):
                # If the file doesn't exist, create it
                with open(perms_file_path, 'w') as configfile:
                    config_perm.write(configfile)
                print(f"Created {perms_file_path}")
            else:
                # If the file already exists, update it
                # config_perm.read(perms_file_path)
                with open(perms_file_path, 'w') as configfile:
                    config_perm.write(configfile)
                print(f"Updated {perms_file_path}")
            
            message_recv_from_server1 = send_to_server1(client_message + '|' + username)
            message_recv_from_server2, message_recv_from_server3 = send_to_server_replicas(
                client_message + '|' + username, "None")

            # message_recv_from_server = send_to_server2(client_message, "None")
            print(message_recv_from_server1, message_recv_from_server2, message_recv_from_server3)

        if client_message_0 == "delete":
            # read permissions for deletion
            wanted_perm_filename = wanted_filename+".ini"
            filename_hash = hashlib.sha256()
            filename_hash.update(wanted_perm_filename.encode())
            wanted_perm_filename = filename_hash.hexdigest()

            perms_file_path = '../perms/'+wanted_perm_filename
            config_perm = ConfigParser()
            config_perm.read(perms_file_path)

            delete_perm = config_perm.get('PERMISSIONS', 'delete')

            if username not in delete_perm:
                print("Sorry, you do not have permissions to delete the file.")
            else:
                message_recv_from_server1 = send_to_server1(client_message + '|' + username)
                message_recv_from_server2, message_recv_from_server3 = send_to_server_replicas(
                    client_message + '|' + username, "None")
                print(message_recv_from_server1, message_recv_from_server2, message_recv_from_server3)
                if "File successfully deleted" in message_recv_from_server1.decode():
                    # move the permissions config file to recycle of its own
                    # create the "recycle" folder in the current working directory if it doesn't exist
                    recycle_folder = '../perms/recycle'
                    if not os.path.exists(recycle_folder):
                        os.makedirs(recycle_folder)
                    
                    file_path = f'../perms/{wanted_perm_filename}'
                    new_file_path = f'../perms/recycle/{wanted_perm_filename}'
                    os.rename(file_path, new_file_path)

        if client_message_0 == "restore":
            # read permissions for restoration
            wanted_perm_filename = wanted_filename+".ini"
            filename_hash = hashlib.sha256()
            filename_hash.update(wanted_perm_filename.encode())
            wanted_perm_filename = filename_hash.hexdigest()

            perms_file_path = '../perms/recycle/'+wanted_perm_filename
            config_perm = ConfigParser()
            #config_perm.read(perms_file_path)
            #print(perms_file_path)
            #recycle_folder1 = os.path.join(os.getcwd(), 'recycle')
            #recycle_file_path1 = os.path.join(recycle_folder1, wanted_perm_filename)
            config_perm.read(perms_file_path)
            if os.path.isfile(perms_file_path):
                restore_perm = config_perm.get('PERMISSIONS', 'restore')
            else:
                restore_perm = ""
            if username not in restore_perm:
                print("Sorry, you do not have permissions to restore the file.")
            else:
                message_recv_from_server1 = send_to_server1(client_message + '|' + username)
                message_recv_from_server2, message_recv_from_server3 = send_to_server_replicas(
                    client_message + '|' + username, "None")
                print(message_recv_from_server1, message_recv_from_server2, message_recv_from_server3)
                if "File successfully restored" in message_recv_from_server3:
                    # move the permissions config file to recycle of its own
                    # create the "recycle" folder in the current working directory if it doesn't exist
                    recycle_folder = '../perms/recycle'
                    if not os.path.exists(recycle_folder):
                        os.makedirs(recycle_folder)
                    
                    new_file_path = f'../perms/{wanted_perm_filename}'
                    file_path = f'../perms/recycle/{wanted_perm_filename}'
                    os.rename(file_path, new_file_path)

        if client_message_0 == "read": # FORMAT: read filename.txt
            # read permissions for reading
            wanted_perm_filename = wanted_filename+".ini"
            filename_hash = hashlib.sha256()
            filename_hash.update(wanted_perm_filename.encode())
            wanted_perm_filename = filename_hash.hexdigest()

            perms_file_path = '../perms/'+wanted_perm_filename
            config_perm = ConfigParser()
            config_perm.read(perms_file_path)

            read_perm = config_perm.get('PERMISSIONS', 'read')

            if username not in read_perm:
                print("Sorry, you do not have permissions to read the file.")
            else:
                message_recv_from_server1 = send_to_server1(client_message + '|' + username)
                message_recv_from_server2, message_recv_from_server3 = send_to_server_replicas(
                    client_message + '|' + username, "None")
                #decrypted_message = rsa.decrypt(message_recv_from_server1, read_private_key_from_file(userName))
                print(message_recv_from_server1)

        if client_message_0 == "write": # FORMAT: write filename.txt

            # read permissions for deletion
            wanted_perm_filename = wanted_filename+".ini"
            filename_hash = hashlib.sha256()
            filename_hash.update(wanted_perm_filename.encode())
            wanted_perm_filename = filename_hash.hexdigest()

            perms_file_path = '../perms/'+wanted_perm_filename
            config_perm = ConfigParser()
            config_perm.read(perms_file_path)

            write_perm = config_perm.get('PERMISSIONS', 'write')

            if username not in write_perm:
                print("Sorry, you do not have permissions to write to the file.")
            else:
                message_recv_from_server = send_to_server1(client_message + '|' + username)
                content = input("enter the text you want to insert: ")
                message_recv_from_server1 = send_to_all_servers(client_message + '|' + username, content)
                print(message_recv_from_server1)

        if client_message_0 == "revoke":
            revoke_keys(username)


if __name__ == "__main__":
    main()