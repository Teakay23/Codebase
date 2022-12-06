import os
import RSA_Methods
import pickle
import socket
import threading
from Crypto.Hash import SHA256
import mysql.connector
from mysql.connector import Error


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

def hash_value_with_salt(value, salt = os.urandom(32)):
    value = value.encode() + salt
    hasher = SHA256.new()
    hasher.update(value)

    return hasher.hexdigest(), salt.hex()

def send_server_public_key(clientSocket):
    package = RSA_Methods.retrieve_public_key("server").export_key()
    packageWithHash = hash_package(package)
    serializedData = pickle.dumps(packageWithHash)
    clientSocket.send(serializedData)

def listen_for_connections():
    socketObj.listen()

    while(1):
        clientSocket, clientAddress = socketObj.accept()
        print("Server> Connected to address: ", clientAddress)
        # send the server public key to client here
        try:
            send_server_public_key(clientSocket)
        except:
            print("Server> Could not send server public key to client: ", clientAddress)
            continue

        request_handler = threading.Thread(target=listen_for_requests, args=(clientSocket, clientAddress))
        request_handler.start()

def listen_for_requests(clientSocket, clientAddress):
    request = clientSocket.recv(2048)

    # decrypt package with server private key first here
    request = RSA_Methods.decrypt_with_RSA_AES(RSA_Methods.retrieve_private_key("server"), request)
    packageWithHash = pickle.loads(request)
    package = packageWithHash["package"]
    
    if not hash_matches(package, packageWithHash["hash"]):
        print("Server> Received request was corrupted.")
        return

    header = package["header"]

    if header == "register":
        handle_register_request(clientSocket, package)
    elif header == "login":
        handle_login_request(clientSocket, package)
    elif header == "listgroup":
        handle_listgroup_request(clientSocket, package)
    elif header == "creategroup":
        handle_creategroup_request(clientSocket, package)
    elif header == "entergroup":
        handle_entergroup_request(clientSocket, package)
    elif header == "sendmessage":
        handle_sendmessage_request(clientSocket, package)
    elif header == "adduserstogroup":
        handle_adduserstogroup_request(clientSocket, package)
    elif header == "leavegroup":
        handle_leavegroup_request(clientSocket, package)

# main functionality
def handle_register_request(clientSocket, package):
    try:
        dbcursor = dbconnection.cursor()
        dbcursor.execute("SELECT username FROM Users WHERE username = %s;", (package["username"],))
        rows = dbcursor.fetchall()

        if len(rows) > 0:
            responsePackage = "exists"
        else:
            hashedPassword, salt = hash_value_with_salt(package["password"])
            dbcursor.execute("INSERT INTO Users VALUES(%s, %s, %s, %s);", (package["username"], hashedPassword, salt, package["key"],))
            dbconnection.commit()

            print("Server> User registered.")
            responsePackage = "success"
        
        try:
            packageWithHash = hash_package(responsePackage)
            serializedData = pickle.dumps(packageWithHash)
            encryptedData = RSA_Methods.encrypt(RSA_Methods.RSA.import_key(package["key"]), serializedData)
            clientSocket.send(encryptedData)
        except:
            print("Server> Could not send response.")
            dbcursor.execute("DELETE FROM Users WHERE username = %s;", (package["username"],))
            dbconnection.commit()
            print("Server> User registration cancelled.")
    except:
        print("Server> Server ran into an unspecified error.")
    finally:
        clientSocket.close()

def handle_login_request(clientSocket, package):
    try:
        dbcursor = dbconnection.cursor()
        dbcursor.execute("SELECT * FROM Users WHERE username = %s;", (package["username"],))
        rows = dbcursor.fetchall()

        if len(rows) == 0:
            responsePackage = "no user"
        else:
            checkPassword, temp = hash_value_with_salt(package["password"], bytes.fromhex(rows[0][2]))
            if rows[0][1] == checkPassword:
                responsePackage = "logged"
                print("Server> User logged in.")
            else:
                responsePackage = "wrong pass"

        try:
            packageWithHash = hash_package(responsePackage)
            serializedData = pickle.dumps(packageWithHash)
            encryptedData = RSA_Methods.encrypt(RSA_Methods.RSA.import_key(package["key"]), serializedData)
            clientSocket.send(encryptedData)
        except:
            print("Server> Could not send response.")

    except Exception as e:
        print("Server> Could not login user due to unspecified error.\n", e)
    finally:
        clientSocket.close()

def handle_listgroup_request(clientSocket, package):
    try:
        dbcursor = dbconnection.cursor()
        dbcursor.execute("SELECT * FROM Users WHERE username = %s", (package["username"],))
        rows = dbcursor.fetchall()

        if len(rows) == 0:
            raise Exception
        else:
            checkPassword, temp = hash_value_with_salt(package["password"], bytes.fromhex(rows[0][2]))
            clientPublicKey = rows[0][3]
            if rows[0][1] != checkPassword:
                raise Exception
            else:
                dbcursor.execute("SELECT Groups.group_id, Groups.group_name FROM Users INNER JOIN User_Group ON Users.username = User_Group.username INNER JOIN `Groups` ON User_Group.group_id = Groups.group_id WHERE User_Group.username = %s;", (package["username"],))
                rows1 = dbcursor.fetchall()
                groupList = list()

                for row in rows1:
                    groupList.append((row[0], row[1]))

                responsePackage = groupList

        try:
            packageWithHash = hash_package(responsePackage)
            serializedData = pickle.dumps(packageWithHash)
            encryptedData = RSA_Methods.encrypt_with_RSA_AES(RSA_Methods.RSA.import_key(clientPublicKey), serializedData)
            clientSocket.send(encryptedData)
        except Exception as e:
            print("Server> Could not send response.")

    except Exception as e:
        print("Server> Could not return group list due to unspecified error.\n", e)
    finally:
        clientSocket.close()

def handle_creategroup_request(clientSocket, package):
    try:
        dbcursor = dbconnection.cursor()
        dbcursor.execute("SELECT * FROM Users WHERE username = %s;", (package["username"],))
        rows = dbcursor.fetchall()

        if len(rows) == 0:
            raise Exception
        else:
            checkPassword, temp = hash_value_with_salt(package["password"], bytes.fromhex(rows[0][2]))
            clientPublicKey = rows[0][3]
            if rows[0][1] != checkPassword:
                raise Exception
            else:
                dbcursor = dbconnection.cursor()
                dbcursor.execute("SELECT max(group_id) FROM `Groups`;")
                groupId = dbcursor.fetchall()[0][0]
                if groupId == None:
                    groupId = 1
                else:
                    groupId += 1
                dbcursor.execute("INSERT INTO `Groups` VALUES(%s, %s, %s);", (groupId, package["groupname"], package["username"],))

                while(len(rows) > 0):
                    groupKeyHex = RSA_Methods.get_random_bytes(16).hex()
                    dbcursor.execute("SELECT `key` FROM key_storage WHERE `key` = %s;", (groupKeyHex,))
                    rows = dbcursor.fetchall()

                dbcursor.execute("INSERT INTO key_storage VALUES(%s, %s);", (groupId, groupKeyHex,))
                dbcursor.execute("INSERT INTO User_Group VALUES(%s, %s);", (package["username"], groupId,))
                dbconnection.commit()
                responsePackage = "success"
        try:
            packageWithHash = hash_package(responsePackage)
            serializedData = pickle.dumps(packageWithHash)
            encryptedData = RSA_Methods.encrypt_with_RSA_AES(RSA_Methods.RSA.import_key(clientPublicKey), serializedData)
            clientSocket.send(encryptedData)
        except Exception as e:
            print("Server> Could not send response.")
    except Exception as e:
        print("Server> Unspecified error occurred.\n", e)
    finally:
        clientSocket.close()

def handle_entergroup_request(clientSocket, package):
    pass

def handle_sendmessage_request(clientSocket, package):
    pass

# additional functionality
def handle_adduserstogroup_request(clientSocket, package):
    try:
        dbcursor = dbconnection.cursor()
        dbcursor.execute("SELECT * FROM Users WHERE username = %s;", (package["username"],))
        rows = dbcursor.fetchall()

        if len(rows) == 0:
            raise Exception
        else:
            checkPassword, temp = hash_value_with_salt(package["password"], bytes.fromhex(rows[0][2]))
            clientPublicKey = rows[0][3]
            if rows[0][1] != checkPassword:
                raise Exception
            else:
                dbcursor.execute("SELECT admin FROM `Groups` WHERE group_id = %s;", (package["group_id"],))
                rows = dbcursor.fetchall()

                if len(rows) == 0:
                    responsePackage = "no group"
                elif rows[0][0] != package["username"]:
                    responsePackage = "not admin"
                else:
                    responsePackage = []
                    for user in package["userList"]:
                        dbcursor.execute("SELECT * FROM Users WHERE username = %s;", (user,))
                        rows = dbcursor.fetchall()

                        if len(rows) == 0:
                            responsePackage.append(user + " does not exist.")
                            continue
                        
                        dbcursor.execute("SELECT * FROM User_Group WHERE username = %s AND group_id = %s;", (user, package["group_id"],))
                        rows = dbcursor.fetchall()

                        if len(rows) > 0:
                            responsePackage.append(user + " is already in the group.")
                            continue
                        
                        dbcursor.execute("INSERT INTO User_Group VALUES(%s, %s);", (user, package["group_id"]))
                        responsePackage.append(user + " added to the group.")
                    dbconnection.commit()
        try:
            packageWithHash = hash_package(responsePackage)
            serializedData = pickle.dumps(packageWithHash)
            encryptedData = RSA_Methods.encrypt_with_RSA_AES(RSA_Methods.RSA.import_key(clientPublicKey), serializedData)
            clientSocket.send(encryptedData)
        except Exception as e:
            print("Server> Could not send response.")
    except Exception as e:
        print("Server> Unspecified error occurred.\n", e)
    finally:
        clientSocket.close()    

def handle_leavegroup_request(clientSocket, package):
    try:
        dbcursor = dbconnection.cursor()
        dbcursor.execute("SELECT * FROM Users WHERE username = %s;", (package["username"],))
        rows = dbcursor.fetchall()

        if len(rows) == 0:
            raise Exception
        else:
            checkPassword, temp = hash_value_with_salt(package["password"], bytes.fromhex(rows[0][2]))
            clientPublicKey = rows[0][3]
            if rows[0][1] != checkPassword:
                raise Exception
            else:
                dbcursor.execute("SELECT admin FROM `Groups` WHERE group_id = %s;", (package["group_id"],))
                rows = dbcursor.fetchall()

                if len(rows) == 0:
                    responsePackage = "no group"
                elif rows[0][0] != package["username"] and package["username"] != package["removeUser"]:
                    responsePackage = "not admin"
                elif rows[0][0] == package["username"] and package["username"] == package["removeUser"]:
                    responsePackage = "admin group"
                else:
                    dbcursor.execute("SELECT * FROM Users WHERE username = %s;", (package["removeUser"],))
                    rows = dbcursor.fetchall()

                    if len(rows) == 0:
                        responsePackage = package["removeUser"] + " does not exist."
                    else:
                        dbcursor.execute("SELECT * FROM User_Group WHERE username = %s AND group_id = %s;", (package["removeUser"], package["group_id"],))
                        rows = dbcursor.fetchall()

                        if len(rows) == 0:
                            responsePackage = package["removeUser"] + " is not in the group."
                        else:
                            dbcursor.execute("DELETE FROM User_Group WHERE username = %s and group_id = %s;", (package["removeUser"], package["group_id"]))
                            responsePackage = package["removeUser"] + " removed from the group."
                            dbconnection.commit()
        try:
            packageWithHash = hash_package(responsePackage)
            serializedData = pickle.dumps(packageWithHash)
            encryptedData = RSA_Methods.encrypt_with_RSA_AES(RSA_Methods.RSA.import_key(clientPublicKey), serializedData)
            clientSocket.send(encryptedData)
        except Exception as e:
            print("Server> Could not send response.")

    except Exception as e:
        print("Server> Unspecified error occurred.\n", e)
    finally:
        clientSocket.close()  

try:
    dbconnection = mysql.connector.connect(host='localhost', database='IS_Chat', user='root', password='Astera@123456')
    if dbconnection.is_connected():
        print("Server> Connected to mysql server. ")
except Error as e:
    print("Server> Error while connecting to database server.", e)

server_ip = "localhost"
server_port = 7000
RSA_Methods.generate_keys("server")

try:
    socketObj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketObj.bind((server_ip, server_port))
except Exception as e:
    print("Server> Could not initialize server.")
    exit(-1)

listen_for_connections()