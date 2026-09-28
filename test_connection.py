import mysql.connector



try:

    db = mysql.connector.connect(

        host="localhost",

        user="root",

        password="adibobade28#",

        database="vit_cyber_project"

    )



    print("Connected to MySQL successfully!")



    db.close()



except mysql.connector.Error as err:

    print("Connection failed!")

    print(err)