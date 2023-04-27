import rsa

(public_key, private_key) = rsa.newkeys(3072)

#print(public_key,"**********", private_key)

# Convert the keys to their PEM string representation
public_key_pem = public_key.save_pkcs1()
private_key_pem = private_key.save_pkcs1()


        
with open(f'keys/server.public_key.pem', 'wb') as f:
    f.write(public_key_pem)
        
with open(f'keys/server.private_key.pem', 'wb') as f:
    f.write(private_key_pem)

server_public_key = None
#parent_dir = os.path.abspath('..')
#file_path = os.path.join(parent_dir, 'keys', 'server.public_key.pem')
with open(f'keys/server.public_key.pem', 'rb') as f:
    key_data = f.read()
server_public_key = rsa.PublicKey.load_pkcs1(key_data)

with open(f'keys/server.private_key.pem', 'rb') as f:
    key_data = f.read()
server_private_key = rsa.PrivateKey.load_pkcs1(key_data)

print(server_private_key)
print("------------")
print(server_public_key)
if public_key == server_public_key and private_key==server_private_key:
    print("Keys match after saving and loading")


data = "Hello"
enc = rsa.encrypt(data.encode(), server_public_key)
dcr = rsa.decrypt(enc, server_private_key).decode()
print(dcr)
