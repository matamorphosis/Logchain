#!/usr/bin/python3
# Logchain Verification Agent Version 1.0
import os, sys, pathlib, argparse, requests, threading, json, tarfile, logging, shutil, time
from datetime import datetime
from py_essentials import hashing as hs

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
        logging.warning(f"{str(Date())} {str(e)}.")
        sys.exit()

def API_Check(File, Full_File, API_Data, Backup_File):

    def Check(File, Full_File, API_Data, Backup_File):

        try:
            State = 0
            Host = f"{API_Data['host']}:{str(int(API_Data['port']))}/chain"
            Response = requests.get(Host, verify=API_Data['verify_ssl']).text
            Response = json.loads(Response)

            if 'chain' in Response:

                for Transactions in Response['chain']:

                    if Transactions.get('transactions') and Transactions.get('transactions') != []:

                        for Transaction in Transactions['transactions']:

                            if Transaction['backup'] == Backup_File and Transaction['log_file'] == File:

                                if Transaction['data_hash'] == hs.fileChecksum(Full_File, "sha256"):
                                    return 2

                                else:
                                    return 1

                        return State

        except Exception as e:
            print(e)

    Result = Check(File, Full_File, API_Data, Backup_File)

    if Result == 2:
        logging.info(f"{str(Date())} Successfully verified {File} against the Logchain ledger.")

    elif Result == 1:
        logging.warning(f"{str(Date())} {File} was found in the Logchain ledger but the checksum did not match. This backup appears to have been tampered with.")

    elif Result == 0:
        logging.info(f"{str(Date())} {File} was not found in the Logchain ledger, if you are sure this backup was created by the Logchain Backup Agent, then it could still be in the current block which has not been mined yet.")

    else:
        logging.warning(f"{str(Date())} Unable to get valid response from ledger.")

def Extract(File, Directory):

    try:
        tar = tarfile.open(File, "r:gz")
        tar.extractall(Directory)
        tar.close()
        return True

    except:
        return False

def Check_Backup(Tar_File):
    API_Data = Load_Logchain_API_Configuration()

    if Tar_File.endswith('.tar.gz'):
        Temp_Directory = '/tmp/Logchain/verify'

        if os.path.exists(Temp_Directory):
            shutil.rmtree(Temp_Directory)

        os.makedirs(Temp_Directory)
        Decompressed = Extract(Tar_File, Temp_Directory)

        if Decompressed:

            for File in os.listdir(Temp_Directory):
                Full_File = Temp_Directory + "/" + File
                Thread = threading.Thread(target=API_Check, args=(File, Full_File, API_Data, Tar_File))
                Thread.start()

        else:
            logging.warning(f"{str(Date())} Failed to decompress the provided file.")

    else:
        logging.warning(f"{str(Date())} Please provide a valid tar file with gzip compression (.tar.gz file).")
        sys.exit()

if __name__ == '__main__':

    try:

        try:
            Logchain_Working_Directory = pathlib.Path(__file__).parent.absolute()

            if str(Logchain_Working_Directory) != str(os.getcwd()):
                print(f"[i] Logchain Verify has been called from outside the Logchain directory, changing the working directory to {str(Logchain_Working_Directory)}.")
                os.chdir(Logchain_Working_Directory)

                if str(Logchain_Working_Directory) != str(os.getcwd()):
                    sys.exit(f'{str(Date())} Error setting the working directory.')

        except:
            sys.exit(f'{str(Date())} Error setting the working directory.')

        logging.basicConfig()
        logging.getLogger().setLevel(logging.INFO)
        Configuration_File = os.path.join(os.path.dirname(os.path.realpath('__file__')), 'config/agent/config.json')
        Parser = argparse.ArgumentParser(description='Tool used to verify backup logs against the Logchain Distributed Ledger.')
        Parser.add_argument('-t', '--tarfile', type=str, help='This option is used to specify a .tar.gz backup file, generated by the Logchain Backup Agent, which contents you desire to verify against the Logchain Distributed Ledger. To run. ./Verify.py -t /var/log/backup/backup.tar.gz')
        Arguments = Parser.parse_args()

        if Arguments.tarfile:

            if Arguments.tarfile != "*":
                Check_Backup(Arguments.tarfile)

            else:
                Config_Data = Load_Agent_Configuration()

                if Config_Data:

                    for File in os.listdir(Config_Data['target_backup_directory']):
                        Complete_File = os.path.join(Config_Data['target_backup_directory'], File)
                        Check_Backup(Complete_File)
                        time.sleep(2)

        else:
            logging.warning(f"{str(Date())} No arguments supplied.")
            sys.exit()

    except Exception as e:
        logging.warning(f"{str(Date())} {str(e)}.")
        sys.exit()