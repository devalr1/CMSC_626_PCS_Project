# Peer-to-Peer Distributed File System (CMSC 626 Project)

Deval Rane (KP56059), Zahid Ahsan (), Nitin Budhana ()

This application is a P2P distributed file system developed using python, as the project for the course CMSC 626. 

# How to Run
1. Setup: \
Run `generate_server_keys.py` to generate server public and private keys.
```
python generate_server_keys.py
```

2. Run Server 1: \
Navigate to `server/Server_1/` \
Run `server1.py` to run Server 1. 
```
python server1.py
```

3. Run Server 2: \ 
Navigate to `server/Server_2/` \
Run `server2.py` to run Server 2.
```
python server2.py
```

4. Run Server 3: \
Navigate to `server/Server_3/` \
Run `server3.py` to run Server 3.
```
python server3.py
```

5. Run Client: \
Navigate to `/client`. \
Run `client.py` to run Server 2.
```
python client.py
```

6. Shut Down: \
Use Keyboard Interrupt - `CTRL + C`

# Instruction
This system includes all the features and functionalities described in the requirements for the project.

The system asks to login before you have an existing account or not. If not, the system asks to create a username and password.


FUNCTIONS AVAILABLE TO USERS IN THE FILE SYSTEM:
1. List Files: \
This function is used displaying the files currently being stored in the directory. This is to view the files present in the system. Each file name will be displayed in an encrypted form. 
>	Syntax: ls

2. Create a File: \
This function is used for creating a file to be stored in the directory. While creating the file, the user needs to specify the file name and the permissions associated with the file.
>	Syntax - create [filename]

3. Write to a File: \
The user can write content to an existing file using this function, and this can be done only if that user has WRITE permissions.
>	Syntax - write [filename]

4. Read a File:  \
This function is for reading the content present in an existing file in the directory, only if the logged in user has READ permissions.
>	Syntax - read [filename]

5. Delete a File: \
This function is for deleting a file stored the directory, only if the logged in user has DELETE permissions.
>	Syntax - delete [filename]

6. Restore a File: \
This function is for restoring a file stored in the directory, only if the logged in user has RESTORE permissions.
>	Syntax - restore [filename]

