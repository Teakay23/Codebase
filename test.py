import mysql.connector
from mysql.connector import Error

try:
    connection = mysql.connector.connect(host='localhost', database='IS_Chat', user='root', password='Astera@123456')

    if connection.is_connected():
        db_info = connection.get_server_info()
        print("You're Connected to mysqlserver version ", db_info)
        cursor = connection.cursor()
        cursor.execute("select database();")
        record = cursor.fetchone()
        print("You're connected to database: ", record)

except Error as e:
    print("Error while connecting to MySQL", e)

finally:
    if connection.is_connected():
        cursor.close()
        connection.close()
        print("MySQL connection is closed.")