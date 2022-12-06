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

def hash_value(value):
    hasher = SHA256.new()
    hasher.update(pickle.dumps(value))

    return hasher.hexdigest()

def fetch_server_key_and_encrypt(serverSocket, data):
    serverSocket.settimeout(30.0)
    serverKeyResponse = serverSocket.recv(2048)
    serverSocket.settimeout(None)

    serverKeyResponse = pickle.loads(serverKeyResponse)
    if not hash_matches(serverKeyResponse["package"], serverKeyResponse["hash"]):
        raise Exception
    key = RSA_Methods.RSA.import_key(serverKeyResponse["package"])
    return RSA_Methods.encrypt_with_RSA_AES(key, data)

def send_package_and_retrieve_response(package, privateKeyFilePrefix):
    packageWithHash = hash_package(package)
    serializedData = pickle.dumps(packageWithHash)

    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.connect((server_ip, server_port))
        # get server public key and encrypt serialized data here
        encrypted_data = fetch_server_key_and_encrypt(serverSocket, serializedData)
        serverSocket.send(encrypted_data)
    except Exception as e:
        print("Could not communicate with server.", e)
        serverSocket.close()
        return "fail"

    try:
        serverSocket.settimeout(500.0)
        response = serverSocket.recv(2048)
        serverSocket.settimeout(None)
    except:
        print("Could not receive a response.")
        serverSocket.close()
        return "fail"
    
    response = RSA_Methods.decrypt_with_RSA_AES(RSA_Methods.retrieve_private_key(privateKeyFilePrefix), response)
    response = pickle.loads(response)

    if hash_matches(response["package"], response["hash"]):
        serverSocket.close()
        return response["package"]
    else:
        print("Server response corrupted")
        serverSocket.close()
        return "fail"

def send_register_message(username, password):
    RSA_Methods.generate_keys("temp")

    package = {
                "header" : "register",
                "username" : username,
                "password" : hash_value(password),
                "key" : RSA_Methods.retrieve_public_key("temp").export_key()
    }
    
    packageWithHash = hash_package(package)
    serializedData = pickle.dumps(packageWithHash)

    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.connect((server_ip, server_port))
        # get server public key and encrypt serialized data here
        encrypted_data = fetch_server_key_and_encrypt(serverSocket, serializedData)
        serverSocket.send(encrypted_data)
    except Exception as e:
        print("Could not communicate with server.", e)
        serverSocket.close()
        return "fail"

    try:
        serverSocket.settimeout(500.0)
        response = serverSocket.recv(2048)
        serverSocket.settimeout(None)
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
        if len(username) < 6 or len(username) > 20 or " " in username:
            print("Username must contain at least 6 characters and at most 20 characters. And it must not have spaces.")
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
            if os.path.exists(username + "_public.pem"):
                os.remove(username + "_public.pem")
            os.rename("temp_public.pem", username + "_public.pem")
            if os.path.exists(username + "_private.pem"):
                os.remove(username + "_private.pem")
            os.rename("temp_private.pem", username + "_private.pem")
            print("User successfully registered")
            os.system("pause")
            return "back"

        elif result == "exists":
            print("Username already exists, enter a unique one.")
            os.remove("temp_public.pem")
            os.remove("temp_private.pem")
            os.system("pause")
            continue

        elif result == "fail":
            os.remove("temp_public.pem")
            os.remove("temp_private.pem")
            print("Could not register user.")
            os.system("pause")
            return "back"

        else:
            os.remove("temp_public.pem")
            os.remove("temp_private.pem")
            print("Unspecified error occured.")
            os.system("pause")
            return "back"

def send_login_message(username, password):
    RSA_Methods.generate_keys("temp")

    package = {
        "header" : "login",
        "username" : username,
        "password" : hash_value(password),
        "key" : RSA_Methods.retrieve_public_key("temp").export_key()
    }

    packageWithHash = hash_package(package)
    serializedData = pickle.dumps(packageWithHash)

    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.connect((server_ip, server_port))
        # get server public key and encrypt serialized data here
        encrypted_data = fetch_server_key_and_encrypt(serverSocket, serializedData)
        serverSocket.send(encrypted_data)
    except:
        print("Could not connect or send data to server.")
        serverSocket.close()
        return "fail"

    try:
        serverSocket.settimeout(500.0)
        response = serverSocket.recv(2048)
        serverSocket.settimeout(None)
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
    

def login():
    while(1):
        os.system('cls')
        print("Login an account: (Enter \"exit\" to go back)")

        username = input("Username: ")
        if username == "exit":
            return "back"
        if len(username) < 6 or len(username) > 20 or " " in username:
            print("Username must contain at least 6 characters and at most 20 characters. And it must not have spaces.")
            os.system("pause")
            continue

        password = input("Password: ")
        if password == "exit":
            return "back"
        if len(password) < 6 or len(password) > 20:
            print("Password must contain at least 6 characters and at most 20 characters.")
            os.system("pause")
            continue

        result = send_login_message(username, password)

        if result == "fail":
            print("Failed due to server error.")
            os.system("pause")
            return "back"

        elif result == "no user":
            print("User does not exist.")
            os.system("pause")
            continue

        elif result == "wrong pass":
            print("Incorrect password for this user.")
            os.system("pause")
            continue

        elif result == "logged":
            print("Successful login.")
            os.system("pause")
            return username, password

        else:
            print("Unspecified error occured.")
            os.system("pause")
            return "back"  

def send_listgroup_message(username, password):
    package = {
        "header" : "listgroup",
        "username" : username,
        "password" : hash_value(password)
    }

    packageWithHash = hash_package(package)
    serializedData = pickle.dumps(packageWithHash)

    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.connect((server_ip, server_port))
        # get server public key and encrypt serialized data here
        encrypted_data = fetch_server_key_and_encrypt(serverSocket, serializedData)
        serverSocket.send(encrypted_data)
    except:
        print("Could not connect or send data to server.")
        serverSocket.close()
        return "fail"

    try:
        serverSocket.settimeout(500.0)
        response = serverSocket.recv(2048)
        serverSocket.settimeout(None)
    except:
        print("Could not receive a response.")
        serverSocket.close()
        return "fail"

    response = RSA_Methods.decrypt_with_RSA_AES(RSA_Methods.retrieve_private_key(username), response)
    response = pickle.loads(response)

    if hash_matches(response["package"], response["hash"]):
        serverSocket.close()
        return response["package"]
    else:
        print("Server response corrupted.")
        serverSocket.close()
        return "fail"
        
def list_groups(username, password): # send the username and password of the currently logged in user.
    os.system('cls')
    result = send_listgroup_message(username, password)

    if result == "fail":
        print("Could not list user groups.")
        os.system("pause")
        return "back"

    if len(result) == 0:
        print("You are not a part of any groups.")
        os.system("pause")
        return "back"

    print(username, "'s Group List:", sep="")
    for sNo, group in enumerate(result):
        print(sNo+1, ". ", group[1], sep="")

    return result # contains group_id and group name


def send_creategroup_message(username, password, groupName):
    package = {
            "header" : "creategroup",
            "username" : username,
            "password" : hash_value(password),
            "groupname" : groupName
        }

    return send_package_and_retrieve_response(package, username) 

def create_group(username, password):
    while(1):
        os.system('cls')
        print("Create a group: (Enter \"exit\" to go back)")

        groupName = input("Group Name: ")
        if groupName == "exit":
            return "back"
        if len(groupName) < 6 or len(groupName) > 45:
            print("Group Name must contain at least 6 characters and at most 45 characters.")
            os.system("pause")
            continue

        result = send_creategroup_message(username, password, groupName)

        if result == "fail":
            print("Could not create group.")
            os.system("pause")
            return "back"

        if result == "success":
            print("Group created successfully. You can now add users to this group.")
            os.system("pause")
            return "back"

def send_addusers_message(username, password, group_id, userList):
    package = {
        "header" : "adduserstogroup",
        "username" : username,
        "password" : hash_value(password),
        "group_id" : group_id,
        "userList" : userList
    }

    return send_package_and_retrieve_response(package, username)

def add_users_to_group(username, password, group_id):
    while(1):
        os.system("cls")
        print("Enter Usernames of the user you want to add: (Enter \"done\" when list is complete or \"exit\" to go back.)")

        userList = []
        while(1):
            user = input()

            if user == "done":
                break
            if user == "exit":
                return "back"
            if len(user) < 6 or len(user) > 20:
                print("Username should be between 6 and 20 characters.\n")
                continue
            userList.append(user)

        if len(userList) == 0:
            return "back"

        results = send_addusers_message(username, password, group_id, userList)

        if results == "no group":
            print("The selected group does not exist.")
            os.system("pause")
            return "back"

        if results == "not admin":
            print("You are not authorized to add users to this group.")
            os.system("pause")
            return "back"

        print("\n")
        for result in results:
            print(result)
        os.system("pause")
        return "back"

def send_leavegroup_message(username, password, group_id, removeUser):
    package = {
        "header" : "leavegroup",
        "username" : username,
        "password" : hash_value(password),
        "group_id" : group_id,
        "removeUser" : removeUser
    }

    return send_package_and_retrieve_response(package, username)

def remove_from_group(username, password, group_id):
    while(1):
        os.system("cls")
        print("Enter the username you want to remove from the group: (Enter \"exit\" to go back.)")

        removeUser = input("Username: ")
        if removeUser == "exit":
            return "back"
        if len(removeUser) < 6 or len(removeUser) > 20 or " " in removeUser:
            print("Username must contain at least 6 characters and at most 20 characters. And it must not have spaces.")
            os.system("pause")
            continue

        result = send_leavegroup_message(username, password, group_id, removeUser)

        if result == "no group":
            print("The selected group does not exist.")
            os.system("pause")
            return "back"

        if result == "not admin":
            print("You are not authorized to remove users from this group.")
            os.system("pause")
            return "back"

        if result == "admin group":
            print("Admin cannot leave the group.")
            os.system("pause")
            return "back"

        print(result)
        os.system("pause")
        return "back"

def send_deletegroup_message(username, password, group_id):
    package = {
        "header" : "deletegroup",
        "username" : username,
        "password" : hash_value(password),
        "group_id" : group_id
    }

    return send_package_and_retrieve_response(package, username)

def delete_group(username, password, group_id):
    
    result = send_deletegroup_message(username, password, group_id)

    if result == "no group":
        print("This group does not exist.")
        os.system("pause")
        return "back"

    if result == "not admin":
        print("You are not authorized to delete this group.")
        os.system("pause")
        return "back"

    print(result)
    os.system("pause")
    return "back"

server_ip = "localhost"
server_port = 7000

# register_user()
# u, p = login()
# #list_groups("Umer123", "MissMakran1")
# add_users_to_group(u, p, 1)

# u, p = login()
# list_groups(u, p)
# add_users_to_group(u, p, 1)
# remove_from_group("Umer123", "MissMakran1", 1)
# list_groups("Umer123", "MissMakran1")
delete_group("Umer123", "MissMakran1", 1)