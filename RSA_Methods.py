from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP as enc
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