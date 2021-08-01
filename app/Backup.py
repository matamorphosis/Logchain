#!/usr/bin/python3
# Logchain Backup Agent Version 1.0
import os, pathlib, shutil, sys, threading, logging, json, tarfile, requests, psycopg2, socket
from datetime import datetime
from py_essentials import hashing as hs
from distutils.dir_util import copy_tree
from uuid import uuid4

def Date():
    return str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

def Load_Agent_Configuration():

    try:
        logging.info(f"{str(Date())} Loading Agent configuration data.")

        with open(Configuration_File) as JSON_File:
            Configuration_Data = json.load(JSON_File)

            if Configuration_Data['agent']['source_log_directories'] and Configuration_Data['agent']['target_backup_directory']:
                return Configuration_Data['agent']

            else:
                return None

    except Exception as e:
        logging.fatal(f"{str(Date())} {str(e)}")
        sys.exit()

def Load_Logchain_API_Configuration():

    try:
        logging.info(f"{str(Date())} Loading API configuration data.")

        with open(Configuration_File) as JSON_File:
            Configuration_Data = json.load(JSON_File)

            if Configuration_Data['api']['host'] and Configuration_Data['api']['port']:
                return Configuration_Data['api']

            else:
                return None

    except Exception as e:
        logging.fatal(f"{str(Date())} {str(e)}.")
        sys.exit()

def Load_Main_Database():
    logging.info(str(Date()) + " Loading Scrummage's Main Database configuration data.")

    try:
        with open(Configuration_File) as JSON_File:
            Configuration_Data = json.load(JSON_File)
            DB_Host = Configuration_Data['postgresql']['host']
            DB_Port = str(int(Configuration_Data['postgresql']['port']))
            DB_Username = Configuration_Data['postgresql']['user']
            DB_Password = Configuration_Data['postgresql']['password']
            DB_Database = Configuration_Data['postgresql']['database']

    except Exception as e:
        logging.fatal(f"{str(Date())} Failed to load configuration file. {e}")
        sys.exit()

    try:
        DB_Connection = psycopg2.connect(user=DB_Username, password=DB_Password, host=DB_Host, port=DB_Port, database=DB_Database)

        if DB_Connection:
            return DB_Connection

        else:
            return None

    except Exception as e:
        logging.fatal(f"{str(Date())} Failed to connect to database. {e}")
        sys.exit()

def Add_to_SIEMChain_Ledger(File_Hash, API_Data, File, Backup_File):
    PSQL_Select_Query = 'SELECT * FROM api'
    Cursor.execute(PSQL_Select_Query)
    Results = Cursor.fetchone()

    if Results:
        Host = API_Data['host'] + ':' + str(int(API_Data['port'])) + '/transactions/new'
        Headers = {'Authorization': f"Bearer {Results[0]}", 'content-type': 'application/json'}
        Data = {"sender": Node_Identifier, "data_hash": File_Hash, "log_file": File, "backup": Backup_File}
        Response = requests.post(Host, data=json.dumps(Data), headers=Headers, verify=API_Data['verify_ssl']).text

        if 'message' in json.loads(Response):
            logging.info(f"{str(Date())} API Response: {json.loads(Response)['message']}")

    else:
        logging.fatal(f"{str(Date())} Failed to retrieve API key from database.")
        sys.exit()

def Make_File(Source_Directory, Target_Directory):
    Source_Directory = Source_Directory.replace("/", "-")
    return f"{Target_Directory}/{str(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))}{Source_Directory}-backup.tar.gz"

def Compress_Directory(File_List, Source_Directory, Backup_File):
    Tar = tarfile.open(Backup_File, "w:gz")

    for File in File_List:
        Full_File = Source_Directory + "/" + File
        Tar.add(Full_File, arcname=File)

    Tar.close()

def Transfer_File(Source_Directory, Real_Source_Directory, File, API_Data, Backup_File):

    # try:
    Full_File = Source_Directory + "/" + File
    Real_Full_File = Real_Source_Directory + "/" + File
    File_Hash = hs.fileChecksum(Full_File, "sha256")
    Add_to_SIEMChain_Ledger(File_Hash, API_Data, File, Backup_File)
    logging.info(f"{str(Date())} Added {Real_Full_File} to chain.")

    # except Exception as e:
    #     logging.fatal(f"{str(Date())} Failed to add file checksum to chain.")
    #     sys.exit(e)

def Threaded_Sync_File(Source_Directory, Real_Source_Directory, File, API_Data, Backup_File):
    thread = threading.Thread(target=Transfer_File, args=(Source_Directory, Real_Source_Directory, File, API_Data, Backup_File))
    thread.start()
    return thread

def Sync_Directory(Source_Directory, Real_Source_Directory, File, API_Data, Backup_File):
    threads = []
    threads.append(Threaded_Sync_File(Source_Directory, Real_Source_Directory, File, API_Data, Backup_File))

    for thread in threads:
        thread.join()

if __name__ == '__main__':

    try:

        try:
            Logchain_Working_Directory = pathlib.Path(__file__).parent.absolute()

            if str(Logchain_Working_Directory) != str(os.getcwd()):
                print(f"[i] Logchain Backup has been called from outside the Logchain directory, changing the working directory to {str(Logchain_Working_Directory)}.")
                os.chdir(Logchain_Working_Directory)

                if str(Logchain_Working_Directory) != str(os.getcwd()):
                    sys.exit(f'{str(Date())} Error setting the working directory.')

        except:
            sys.exit(f'{str(Date())} Error setting the working directory.')

        logging.basicConfig()
        logging.getLogger().setLevel(logging.INFO)
        Configuration_File = os.path.join(os.path.dirname(os.path.realpath('__file__')), 'config/agent/config.json')
        Connection = Load_Main_Database()
        Cursor = Connection.cursor()
        Config_Data = Load_Agent_Configuration()
        PSQL_Select_Query = 'SELECT * FROM nodes WHERE node_fqdn = %s AND node_type = %s'
        Cursor.execute(PSQL_Select_Query, (socket.getfqdn(), "Agent",))
        Results = Cursor.fetchone()

        if not Results:
            logging.info(f"{str(Date())} Node initialising for the first time.")
            Node_Identifier = str(uuid4()).replace('-', '')
            PSQL_Insert_Query ='INSERT INTO nodes (node_id, node_fqdn, node_type, created_at) VALUES (%s,%s,%s,%s)'
            Cursor.execute(PSQL_Insert_Query, (Node_Identifier, socket.getfqdn(), "Agent", datetime.now()))
            Connection.commit()

        else:
            Node_Identifier = Results[0]

        API_Data = Load_Logchain_API_Configuration()

        if Config_Data and API_Data:
            logging.info(f"{str(Date())} SIEM Chain Agent log backup initialising.")

            for Directory in Config_Data['source_log_directories']:
                Target_Directory = Config_Data['target_backup_directory']
                Backup_File = Make_File(Directory, Target_Directory)
                Temp_Directory = '/tmp/Logchain/agent'

                if os.path.exists(Temp_Directory):
                    shutil.rmtree(Temp_Directory)

                os.makedirs(Temp_Directory)
                copy_tree(Directory, Temp_Directory)

                for File in os.listdir(Temp_Directory):
                    Sync_Directory(Temp_Directory, Directory, File, API_Data, Backup_File)

                Compress_Directory(os.listdir(Temp_Directory), Temp_Directory, Backup_File)
                shutil.rmtree(Temp_Directory)

            logging.info(f"{str(Date())} SIEM Chain Agent log backup complete")

        else:
            sys.exit(f"{str(Date())} Loading configuration failed.")

    except Exception as e:
        logging.fatal(f"{str(Date())} {str(e)}")
        sys.exit()