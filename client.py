import re
import os
import RSA_Methods
import pickle
import socket
import threading
from Crypto.Hash import SHA256
from datetime import datetime

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

def send_package_and_retrieve_response(package, privateKeyFilePrefix, keepConnectionOpen = False):
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
        response = serverSocket.recv(104857)
        serverSocket.settimeout(None)
    except:
        print("Could not receive a response.")
        serverSocket.close()
        return "fail"
    
    response = RSA_Methods.decrypt_with_RSA_AES(RSA_Methods.retrieve_private_key(privateKeyFilePrefix), response)
    response = pickle.loads(response)

    if hash_matches(response["package"], response["hash"]):
        if keepConnectionOpen:
            return response["package"], serverSocket
        
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

    # packageWithHash = hash_package(package)
    # serializedData = pickle.dumps(packageWithHash)

    # try:
    #     serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     serverSocket.connect((server_ip, server_port))
    #     # get server public key and encrypt serialized data here
    #     encrypted_data = fetch_server_key_and_encrypt(serverSocket, serializedData)
    #     serverSocket.send(encrypted_data)
    # except:
    #     print("Could not connect or send data to server.")
    #     serverSocket.close()
    #     return "fail"

    # try:
    #     serverSocket.settimeout(500.0)
    #     response = serverSocket.recv(2048)
    #     serverSocket.settimeout(None)
    # except:
    #     print("Could not receive a response.")
    #     serverSocket.close()
    #     return "fail"

    # response = RSA_Methods.decrypt_with_RSA_AES(RSA_Methods.retrieve_private_key(username), response)
    # response = pickle.loads(response)

    # if hash_matches(response["package"], response["hash"]):
    #     serverSocket.close()
    #     return response["package"]
    # else:
    #     print("Server response corrupted.")
    #     serverSocket.close()
    #     return "fail"

    return send_package_and_retrieve_response(package, username)
        
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

        if results == "fail":
            print("Communication Error!")
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

def remove_from_group(username, password, group_id, leaveGroup = False):
    while(1):
        os.system("cls")
        if leaveGroup == True:
            removeUser = username
        else:
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

        if result == "fail":
            print("Communication Error!")
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

    if result == "fail":
        print("Communication Error!")
        os.system("pause")
        return "back"

    print(result)
    os.system("pause")
    return "back"

def send_entergroup_message(username, password, group_id):
    package = {
        "header" : "entergroup",
        "username" : username,
        "password" : hash_value(password),
        "group_id" : group_id
    }

    return send_package_and_retrieve_response(package, username, True)

def enter_group(username, password, group_id):

    result, serverSocket = send_entergroup_message(username, password, group_id)

    if result == "no group":
        print("The group you're trying to access does not exist.")
        os.system("pause")
        serverSocket.close()
        return "back"
    
    if result == "not in group":
        print("You are not in this group.")
        os.system("pause")
        serverSocket.close()
        return "back"

    if result == "fail":
        print("Communication Error!")
        os.system("pause")
        return "back"

    groupKeyHex = result["groupKeyHex"]

    for message in result["messages"]:
        print(format_message(groupKeyHex, message))

    listeningThread = threading.Thread(target=listen_for_messages, args=(serverSocket, groupKeyHex))
    listeningThread.start()

    send_message(username, password, group_id, groupKeyHex)

    serverSocket.close()
    return "back"

def format_message(symmetric_key, message):
    decryptedMessage = RSA_Methods.decrypt_AES(symmetric_key, message[1])

    if type(message[2]) != type(str()):
        message_time = message[2].strftime('%Y-%m-%d %H:%M:%S')
    else:
        message_time = message[2]
    return "[" + message_time + "] " + message[0] + "> " + decryptedMessage

def listen_for_messages(serverSocket, symmetric_key):
    while(1):
        try:
            serverSocket.settimeout(None)
            response = serverSocket.recv(2048)
        except:
            print("Exiting group...")
            return

        response = RSA_Methods.decrypt_AES(symmetric_key, response)
        if hash_matches(response["package"], response["hash"]):
            print(format_message(symmetric_key, response["package"]))
        else:
            print("Incoming message was corrupted.")

def send_sendmessage_message(username, password, group_id, groupKeyHex, message):
    encrypted_message = RSA_Methods.encrypt_AES(groupKeyHex, message)

    package = {
        "header" : "sendmessage",
        "username" : username,
        "password" : hash_value(password),
        "group_id" : group_id,
        "message" : encrypted_message
    }

    return send_package_and_retrieve_response(package, username)

def send_message(username, password, group_id, groupKeyHex):
    while(1):
        message = input("Enter a message: (Enter \"\\exit\" to go back) ")

        if len(message) < 1:
            print("Cannot send empty message.")
            continue
        
        if message == "\\exit":
            return "back"

        result = send_sendmessage_message(username, password, group_id, groupKeyHex, message)

        if result == "no group":
            print("The group you're trying to access no longer exists.")
            os.system("pause")
            return "back"
    
        if result == "not in group":
            print("You are no longer in this group.")
            os.system("pause")
            return "back"

        if result == "fail":
            print("Communication Error!")
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
# list_groups("Umer123", "MissMakran1")

def mainScreen():
    loggedUser = None
    loggedUserPassword = None

    while(1):
        try:
            os.system("cls")
            print("Welcome to Radianite Chat App")
            print("1. Login\n2. Register User\n3. Exit\n")
            choice = input("Enter a number: ")

            if choice == "1":
                result = login()
                if result != "back":
                    loggedUser, loggedUserPassword = result
                    loggedInScreen(loggedUser, loggedUserPassword)
            elif choice == "2":
                register_user()
            elif choice == "3":
                exit(0)
            else:
                print("Invalid Input. Try again.")
                os.system("pause")
        except Exception as e:
            print("Unexpected error occured. This may be due to communication error with the server.")
            continue

def loggedInScreen(loggedUser, loggedUserPassword):
    while(1):
        try:
            os.system("cls")
            print("Welcome", loggedUser)
            print("1. Create Group\n2. List Groups\n3. Log out\n")
            choice = input("Enter a number: ")

            if choice == "1":
                create_group(loggedUser, loggedUserPassword)
            elif choice == "2":
                groupsScreen(loggedUser, loggedUserPassword)
            elif choice == "3":
                return
            else:
                print("Invalid Input. Try again.")
                os.system("pause")
        except Exception as e:
            print("Unexpected error occured. This may be due to communication error with the server.")
            continue

def groupsScreen(loggedUser, loggedUserPassword):
    while(1):
        try:
            os.system("cls")
            selectFlag = False
            result = list_groups(loggedUser, loggedUserPassword)

            if result == "back":
                return
            print((len(result)+1), ". Go back\n", sep="")
            choice = input("Enter a number to select the group or go back: ")

            if choice == str(len(result)+1):
                return

            for sNo, group in enumerate(result):
                if choice == str(sNo+1):
                    selectGroupScreen(loggedUser, loggedUserPassword, group[0], group[1])
                    selectFlag = True
                    break
            
            if selectFlag == False:
                print("Invalid Input. Try again.")
                os.system("pause")
        except Exception as e:
            print("Unexpected error occured. This may be due to communication error with the server.")
            continue

def selectGroupScreen(loggedUser, loggedUserPassword, group_id, group_name):
    while(1):
        try:
            os.system("cls")
            print("Selected Group:", group_name)
            print("1. Enter Group Chat\n2. Add Users\n3. Remove a User\n4. Leave Group\n5. Delete Group\n6. Go back")

            choice = input("Enter a number: ")

            if choice == "1":
                os.system("cls")
                enter_group(loggedUser, loggedUserPassword, group_id)
            elif choice == "2":
                add_users_to_group(loggedUser, loggedUserPassword, group_id)
            elif choice == "3":
                remove_from_group(loggedUser, loggedUserPassword, group_id)
            elif choice == "4":
                remove_from_group(loggedUser, loggedUserPassword, group_id, True)
                return
            elif choice == "5":
                delete_group(loggedUser, loggedUserPassword, group_id)
                return
            elif choice == "6":
                return
            else:
                print("Invalid Input. Try again.")
                os.system("pause")
        except Exception as e:
            print("Unexpected error occured. This may be due to communication error with the server.")
            continue

mainScreen()