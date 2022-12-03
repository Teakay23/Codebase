import re
import os
import RSA_Methods
import pickle
import socket
from Crypto.Hash import SHA256

def has_numbers(inputString):
    return bool(re.search(r'\d', inputString))

def hash_package(package):
    hasher = SHA256.new()
    hasher.update(pickle.dumps(package))

    packageWithHash = {
                "package" : package,
                "hash" : hasher.hexdigest()
    }

    return packageWithHash

def hash_matches(package, hash):
    hasher = SHA256.new()
    hasher.update(pickle.dumps(package))

    return hash == hasher.hexdigest()

def send_register_message(username, password):
    RSA_Methods.generate_keys("temp")

    package = {
                "header" : "register",
                "username" : username,
                "password" : password,
                "key" : RSA_Methods.retrieve_public_key("temp").export_key()
    }
    
    packageWithHash = hash_package(package)
    serializedData = pickle.dumps(packageWithHash)

    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.connect((server_ip, server_port))
        serverSocket.send(serializedData)
    except:
        print("Could not connect or send data to server.")
        serverSocket.close()
        return "fail"

    try:
        response = serverSocket.recv(1024)
    except:
        print("Could not receive a response.")
        serverSocket.close()
        return "fail"
    
    response = RSA_Methods.decrypt(RSA_Methods.retrieve_private_key("temp"), response)
    response = pickle.loads(response)

    if hash_matches(response["package"], response["hash"]):
        serverSocket.close()
        return response["package"]
    else:
        print("Server response corrupted")
        serverSocket.close()
        return "fail"

def register_user():
    while(1):
        os.system('cls')
        print("Register an account: (Enter \"exit\" to go back)")
        username = input("Username: ")

        if username == "exit":
            return "back"
        if len(username) < 6 or len(username) > 20:
            print("Username must contain at least 6 characters and at most 20 characters.")
            os.system("pause")
            continue

        password = input("Password: ")
        if password == "exit":
            return "back"
        if len(password) < 6 or len(password) > 20 or password == password.lower() or password == password.upper() or not has_numbers(password):
            print("Password must contain at least 6 characters and at most 20 characters, 1 uppercase, 1 lowercase and 1 number.")
            os.system("pause")
            continue

        confirmPassword = input("Confirm Password: ")
        if confirmPassword == "exit":
            return "back"
        if password != confirmPassword:
            print("Both passwords must match.")
            os.system("pause")
            continue

        result = send_register_message(username, password)

        if result == "success":
            os.rename("temp_public.pem", username + "_public.pem")
            os.rename("temp_private.pem", username + "_private.pem")
            print("User successfully registered")
            os.system("pause")
            return "success"

        if result == "exists":
            print("Username already exists, enter a unique one.")
            os.system("pause")
            continue

        if result == "fail":
            os.remove("temp_public.pem")
            os.remove("temp_private.pem")
            print("Could not register user.")
            os.system("pause")
            return "back"

        else:
            print("Unspecified error occured.")
            os.system("pause")
            return "back"

def login():
    pass

server_ip = "localhost"
server_port = 7000

register_user()