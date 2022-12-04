from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP as enc
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pickle
import os

def retrieve_public_key(filePrefix):
    file = open(filePrefix + "_public.pem", 'r')
    rawKey = file.read()
    return RSA.import_key(rawKey)

def retrieve_private_key(filePrefix):
    file = open(filePrefix + "_private.pem", 'r')
    rawKey = file.read()
    return RSA.import_key(rawKey)

def encrypt(key, data):
    encryption_scheme = enc.new(key)
    encrypted_data = encryption_scheme.encrypt(data)

    return encrypted_data

def decrypt(key, data):
    decryption_scheme = enc.new(key)
    decrypted_data = decryption_scheme.decrypt(data)

    return decrypted_data

def encrypt_with_RSA_AES(key, data):
    session_key = get_random_bytes(16)
    encrypted_session_key = encrypt(key, session_key)

    aes_encrypt = AES.new(session_key, AES.MODE_EAX)
    cipher_text, tag = aes_encrypt.encrypt_and_digest(data)

    encrypted_data = {
        "session_key" : encrypted_session_key,
        "data" : cipher_text,
        "nonce" : aes_encrypt.nonce,
        "tag" : tag
    }

    return pickle.dumps(encrypted_data)

def decrypt_with_RSA_AES(key, data):
    encrypted_data = pickle.loads(data)
    
    session_key = decrypt(key, encrypted_data["session_key"])
    aes_decrypt = AES.new(session_key, AES.MODE_EAX, encrypted_data["nonce"])
    plain_data = aes_decrypt.decrypt_and_verify(encrypted_data["data"], encrypted_data["tag"])

    return plain_data

def generate_keys(filePrefix):
    key = RSA.generate(2048)

    private_key = key.export_key()
    private_filename = filePrefix + "_private.pem"
    if os.path.exists(private_filename):
        os.remove(private_filename)
    file = open(private_filename, "wb")
    file.write(private_key)
    file.close()

    public_key = key.publickey().export_key()
    public_filename = filePrefix + "_public.pem"
    if os.path.exists(public_filename):
        os.remove(public_filename)
    file = open(public_filename, "wb")
    file.write(public_key)
    file.close()