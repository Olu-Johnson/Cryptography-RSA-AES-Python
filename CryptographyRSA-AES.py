from Cryptodome.PublicKey import RSA

from Cryptodome.Cipher import PKCS1_OAEP

from Cryptodome.Random import get_random_bytes

from Cryptodome.Cipher import AES

from Cryptodome.Random import get_random_bytes

from Cryptodome.Util.Padding import pad, unpad

import os

def generate_aes_key(secrete_key_path, key_size=16):
    secrete_key = get_random_bytes(key_size)
    with open(secrete_key_path, 'wb') as secrete_key_file:
        secrete_key_file.write(secrete_key)
    return secrete_key



def encrypt_data(data, secrete_key):
    iv = get_random_bytes(16)
    cipher = AES.new(secrete_key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext


def decrypt_data(ciphertext, secrete_key):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = AES.new(secrete_key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(actual_ciphertext)
    data = unpad(padded_data, AES.block_size)
    return data

def decrypt_file(file_path, key_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    with open(key_path, 'rb') as file:
        secrete_key = file.read()
    decrypted_data = decrypt_data(file_data, secrete_key)
    return decrypted_data

# _________________ AES ends _______________________



def generate_rsa_keypair(public_key_path, private_key_path, secret_key_path, key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    secret_key = generate_aes_key(secret_key_path, key_size=16)
    with open(public_key_path, 'wb') as public_key_file:
        public_key_file.write(public_key)

    encryptedPrivateKey = encrypt_data(private_key, secret_key)
    with open(private_key_path, 'wb') as private_key_file:
        private_key_file.write(encryptedPrivateKey)
    return encryptedPrivateKey, public_key


def encrypt_file_with_rsa(file_path, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    chunk_size = rsa_key.size_in_bytes() - 42
    ciphertext = b''
    for i in range(0, len(file_data), chunk_size):
        chunk = file_data[i:i+chunk_size]
        ciphertext += cipher_rsa.encrypt(chunk)
    return ciphertext

def encrypt_directory(directory_path, public_key_path):
    with open(public_key_path, 'rb') as file:
        key_value = file.read()
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypted_content = encrypt_file_with_rsa(file_path, key_value)
            with open(file_path, 'wb') as file:
                file.write(encrypted_content)



def decrypt_rsa(file_path, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    chunk_size = rsa_key.size_in_bytes()
    decrypted_data = b''
    with open(file_path, 'rb') as file:
        ciphertext = file.read()
    for i in range(0, len(ciphertext), chunk_size):
        chunk = ciphertext[i:i+chunk_size]
        decrypted_data += cipher_rsa.decrypt(chunk)
    return decrypted_data

def decrypt_directory(directory_path, private_key_path, secret_key_path):
    # with open(private_key_path, 'rb') as private_key_file:
    #     private_key = private_key_file.read()
    private_key = decrypt_file(private_key_path, secret_key_path)
    print(f"private_key : - {private_key}")
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            decrypted_content = decrypt_rsa(file_path, private_key)
            with open(file_path, 'wb') as file:
                file.write(decrypted_content)

public_key_path = "public-key.txt"
private_key_path = "private-key.txt"
secret_key_path = "secret_key.txt"
directory_path = "image"

# _________ 1 Generate Keys _______________
# generate_rsa_keypair(public_key_path, private_key_path, secret_key_path)

# ____________ 2 Encrypt___________________
# encrypt_directory(directory_path, public_key_path)

# ___________ 3 Decrypt _______________
#decrypt_directory(directory_path, private_key_path, secret_key_path)

