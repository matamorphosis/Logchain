import psycopg2, sys, json, datetime

def Load_Main_Database():

    try:
        with open('db.json') as JSON_File:
            Configuration_Data = json.load(JSON_File)
            DB_Info = Configuration_Data['postgresql']
            DB_Host = DB_Info['host']
            DB_Port = str(int(DB_Info['port']))
            DB_Username = DB_Info['user']
            DB_Password = DB_Info['password']
            DB_Database = DB_Info['database']

    except:
        sys.exit(str(datetime.datetime.now()) + " Failed to load configuration file.")

    try:
        DB_Connection = psycopg2.connect(user=DB_Username,
                                      password=DB_Password,
                                      host=DB_Host,
                                      port=DB_Port,
                                      database=DB_Database)
        return DB_Connection

    except:
        sys.exit(str(datetime.datetime.now()) + " Failed to connect to database.")

try:
    connection = Load_Main_Database()
    cursor = connection.cursor()

    api_query = '''CREATE TABLE api (api_key TEXT PRIMARY KEY NOT NULL);'''
    node_query = '''CREATE TABLE nodes (
          node_id TEXT PRIMARY KEY NOT NULL,
          node_fqdn TEXT NOT NULL,
          node_type TEXT NOT NULL,
          created_at TEXT NOT NULL);'''
    
    cursor.execute(api_query)
    print("[+] API table created successfully in PostgreSQL.")
    cursor.execute(node_query)
    print("[+] Nodes table created successfully in PostgreSQL.")
    connection.commit()
    print("Table created successfully in PostgreSQL ")

except (Exception, psycopg2.DatabaseError) as error :
    print ("Error while creating PostgreSQL table. ", error)

finally:
    #closing database connection.
        if(connection):
            cursor.close()
            connection.close()
            print("PostgreSQL connection closed.")
