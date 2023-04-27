import socket
import os
import base64
import datetime
import rsa
import hashlib

userName = None
user_public_key = None

# SERVER PRIVATE KEY TO DECRYPT
server_private_key=None
filename = f'../server.private_key.pem'
with open(filename, 'rb') as f:
    key_data = f.read()
server_private_key = rsa.PrivateKey.load_pkcs1(key_data)

# USER PUBLIC KEY TO ENCRYPT
def get_user_public_key(username):
    public_key_file = f'../../keys/{username}.public_key.pem'
    with open(public_key_file, 'rb') as f:
        key_data = f.read()
    public_key = rsa.PublicKey.load_pkcs1(key_data)
    return public_key


def send_response_to_client(data, communication_socket):
    data = rsa.encrypt(data.encode('utf-8'), user_public_key)    
    communication_socket.send(data)


def send_bytedata_to_client(data, communication_socket):
    data = rsa.encrypt(data, user_public_key)
    communication_socket.send(data)


def listing_files_in_folder():
    directory_path = "."
    existing_files = [file for file in os.listdir(directory_path) if os.path.isfile(file) or os.path.isdir(file)]
    file_list = ""
    for file in existing_files:
        file_list += file + "\n"
    return file_list


def creating_file(wanted_filename, communication_socket, client_address):
    # content = write(filename, communication_socket, server, current_dir)
    filename_hash = hashlib.sha256()
    filename_hash.update(wanted_filename.encode())
    filename_hash_str = filename_hash.hexdigest()
    if filename_hash_str not in (listing_files_in_folder()):
        with open(filename_hash_str, "w") as f:
            print("Created the file in Server 1")
            data = "Created the file in Server 1"
            send_response_to_client(data, communication_socket)
    else:
        data = "File already exist"
        send_response_to_client(data, communication_socket)
    communication_socket.close()
    print(f'Communication with {client_address} ended!')


def deleting_file(wanted_filename, communication_socket, client_address):
    filename_hash = hashlib.sha256()
    filename_hash.update(wanted_filename.encode())
    wanted_filename = filename_hash.hexdigest()
    
    
    if wanted_filename in (listing_files_in_folder()):
        # create the "recycle" folder in the current working directory if it doesn't exist
        recycle_folder = os.path.join(os.getcwd(), 'recycle')
        if not os.path.exists(recycle_folder):
            os.makedirs(recycle_folder)
        
        file_path = os.path.join(os.getcwd(), wanted_filename)
        new_file_path = os.path.join(recycle_folder, wanted_filename)
        os.rename(file_path, new_file_path)
        #os.remove(wanted_filename)
        data = "File successfully deleted"
    else:
        data = "File doesn't exist"
    send_response_to_client(data, communication_socket)

def restoring_file(wanted_filename, communication_socket, client_address):
    filename_hash = hashlib.sha256()
    filename_hash.update(wanted_filename.encode())
    wanted_filename = filename_hash.hexdigest()
    recycle_folder = os.path.join(os.getcwd(), 'recycle')
        
    new_file_path = os.path.join(os.getcwd(), wanted_filename)
    file_path = os.path.join(recycle_folder, wanted_filename)
    
    if os.path.isfile(file_path):
        # create the "recycle" folder in the current working directory if it doesn't exist
        
        os.rename(file_path, new_file_path)
        #os.remove(wanted_filename)
        data = "File successfully restored"
    else:
        data = "File doesn't exist"
    print(data)
    send_response_to_client(data, communication_socket)


def writing_into_file(wanted_filename, s_socket, communication_socket, client_address):
    # content = write(filename, communication_socket, server, current_dir)
    filename_hash = hashlib.sha256()
    filename_hash.update(wanted_filename.encode())
    wanted_filename = filename_hash.hexdigest()
    if wanted_filename in (listing_files_in_folder()):
        with open(wanted_filename, "w") as f:
            data = "enter the text you want to insert: "
            send_response_to_client(data, communication_socket)

            print("waiting for command (IN WRITE)...")
            communication_socket, client_address = s_socket.accept()
            client_write_data = communication_socket.recv(1024)  # .decode('utf-8')
            # DECRYPT HERE TO GET DATA BACK
            #decrypted_data = rsa.decrypt(client_write_data, server_private_key)
            client_write_data_string = str(base64.b64encode(client_write_data), 'utf-8')

            print("Received the content of the file as: (IN WRITE)", client_write_data_string)
            f.write(client_write_data_string)
            send_response_to_client("successfully written the data", communication_socket)
            communication_socket.close()
            print(f'Communication with {client_address} ended!')
    else:
        data = "File doesn't exist"
        send_response_to_client(data, communication_socket)


def reading_file(wanted_filename, s_socket, communication_socket, client_address):
    filename_hash = hashlib.sha256()
    filename_hash.update(wanted_filename.encode())
    wanted_filename = filename_hash.hexdigest()
    if wanted_filename in (listing_files_in_folder()):
        with open(wanted_filename, "r") as f:
            data = f.read()
        data_string = base64.b64decode(data)
        decr_data = rsa.decrypt(data_string, server_private_key)
    else:
        data = "File doesn't exist"
    
    print(decr_data)
    #decrypt data from file send to client
    send_bytedata_to_client(decr_data, communication_socket)
    #send_response_to_client(decr_data, communication_socket)



def logging_activity(command_name, message, user_name, current_dir):
    ct = str(datetime.datetime.now())
    with open(current_dir + "/server_logs", "a") as f:
        f.write(ct + " | " + "Command : " + command_name + " | " + message + "| Username: " + user_name + "\n")


def main():
    host = socket.gethostbyname('localhost')
    # host = '130.85.243.2'
    port = 9090
    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_socket.bind((host, port))
    s_socket.listen(5)
    main_dir = os.getcwd()
    print('Server 1 is listening!......')

    while True:
        communication_socket, client_address = s_socket.accept()
        print(f'Connected to {client_address}')
        # getting username
        # getting password
        # authorizing the client or users
        # users exist? or else create new directory

        print("Processing the message received from client...")
        client_message_initial = communication_socket.recv(1024)        
        client_message_initial = rsa.decrypt(client_message_initial, server_private_key).decode('utf-8')
        print(f'Message from client is: {client_message_initial}')
        client_message, user = client_message_initial.split('|')
        client_message_0 = client_message.split()[0]
        
        global userName
        userName = user
        global user_public_key
        user_public_key = get_user_public_key(user)

        if len(client_message.split()) > 1:
            wanted_filename = client_message.split()[1]

        if client_message_0 == "ls":
            existing_files = listing_files_in_folder()
            if existing_files is None:
                send_response_to_client("No files exist", communication_socket)
            else:
                send_response_to_client(existing_files, communication_socket)
            communication_socket.close()
            print(f'Communication with {client_address} ended!')
        if client_message_0 == "create":
            creating_file(wanted_filename, communication_socket, client_address)
            logging_activity(client_message_0, wanted_filename, user, main_dir)
        if client_message_0 == "delete":
            deleting_file(wanted_filename, communication_socket, client_address)
            logging_activity(client_message_0, wanted_filename, user, main_dir)
        if client_message_0 == "restore":
            restoring_file(wanted_filename, communication_socket, client_address)
            logging_activity(client_message_0, wanted_filename, user, main_dir)
        if client_message_0 == "write":
            writing_into_file(wanted_filename, s_socket, communication_socket, client_address)
            logging_activity(client_message_0, wanted_filename, user, main_dir)
        if client_message_0 == "read":
            reading_file(wanted_filename, s_socket, communication_socket, client_address)
            logging_activity(client_message_0, wanted_filename, user, main_dir)


if __name__ == "__main__":
    main()