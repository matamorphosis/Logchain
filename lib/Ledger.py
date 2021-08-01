#!/usr/bin/python3
# Logchain API Ledger Version 1.0
import hashlib, json, requests, pathlib, os, sys, logging, jwt, ssl, psycopg2, secrets, socket
from time import time
from urllib.parse import urlparse
from uuid import uuid4
from flask import Flask, jsonify, request
from logging.handlers import RotatingFileHandler
from flask_compress import Compress
from signal import signal, SIGINT
from datetime import datetime, timedelta

def Date():
    return str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

def Load_SIEM_Chain_Configuration():

    try:
        logging.info(str(Date()) + " Loading web application's configuration data.")

        with open(Configuration_File) as JSON_File:
            Configuration_Data = json.load(JSON_File)

            if Configuration_Data["web-app"]["api-validity-minutes"] < 60:
                sys.exit("[-] API Key Validity Limit too short. Minimum should be 60 minutes.")

            else:
                return Configuration_Data["web-app"]

    except Exception as e:
        app.logger.fatal(f"{str(Date())} {str(e)}")
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
        app.logger.fatal(f"{str(Date())} Failed to load configuration file. {str(e)}")
        sys.exit()

    try:
        DB_Connection = psycopg2.connect(user=DB_Username, password=DB_Password, host=DB_Host, port=DB_Port, database=DB_Database)

        if DB_Connection:
            return DB_Connection

        else:
            return None

    except Exception as e:
        app.logger.fatal(f"{str(Date())} Failed to connect to database. {e}")
        sys.exit()


def API_Generation(**kwargs):

    try:

        if "Expired_Token" in kwargs:
            PSQL_Delete_Query = "DELETE FROM api WHERE api_key = %s;"
            Cursor.execute(PSQL_Delete_Query, (kwargs["Expired_Token"],))

        Expiry_Hours = API_Validity_Limit / 60
        Expiry = datetime.utcnow() + timedelta(hours=Expiry_Hours)
        payload = {"iss": socket.getfqdn(), "iat": datetime.utcnow(), "exp": Expiry, "nonce": secrets.token_hex(32)}
        JWT = jwt.encode(payload, API_Secret, algorithm='HS256')
        PSQL_Query = 'INSERT INTO api (api_key) VALUES (%s)'
        Cursor.execute(PSQL_Query, (JWT.decode('utf-8'),))
        Connection.commit()
        return JWT.decode('utf-8')

    except Exception as e:
        logging.warning(f"{str(Date())} Failed to generate API token. {e}")


def API_Verification(auth_token):

    try:
        Decoded_Token = jwt.decode(auth_token, API_Secret, algorithm='HS256')
        PSQL_Select_Query = 'SELECT * FROM api WHERE api_key = %s'
        Cursor.execute(PSQL_Select_Query, (auth_token,))
        User_Details = Cursor.fetchone()

        if auth_token == User_Details[0] and Decoded_Token:
            return {"Token": True, "Message": "Token verification successful."}

        else:
            return {"Token": False, "Message": "Invalid token."}

    except jwt.ExpiredSignatureError:
        API_Key = API_Generation(Expired_Token=auth_token)
        return {"Token": True, "Message": f"Token expired, please use the new token {API_Key}."}

    except jwt.DecodeError:
        return {"Token": False, "Message": "Failed to decode token."}

    except jwt.InvalidTokenError:
        return {"Token": False, "Message": "Invalid token."}


class Blockchain:

    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.new_block(previous_hash='1', proof=100)  # Creates the very first block.

    def register_node(self, address):
        # Add a new node to the list of nodes using the "address" parameter: Example node "http://192.168.0.0:5000"

        parsed_url = urlparse(address)

        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)

        elif parsed_url.path:
            self.nodes.add(parsed_url.path)  # Accepts an URL without scheme like "192.168.0.0:5000".

        else:
            raise ValueError('Invalid URL')

    def valid_chain(self, chain):
        # Determine if a given blockchain is valid using the chain parameter: Blockchain returns True if valid or False if not.

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            last_block_hash = self.hash(last_block)  # Check that the hash of the block is correct

            if block['previous_hash'] != last_block_hash:
                return False

            if not self.valid_proof(last_block['proof'], block['proof'],
                                    last_block_hash):  # Check that the Proof of Work is correct
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        # This is our consensus algorithm, it resolves conflicts by replacing our chain with the longest one in the network. It will return: True if our chain was replaced, False if not.
        new_chain = None
        max_length = len(self.chain)  # We're only looking for chains longer than ours

        # Grab and verify the chains from all the nodes in our network
        for node in self.nodes:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        # Create a new Block in the Blockchain proof parameter. The proof given by the Proof of Work algorithm previous_hash parameter: Hash of previous Block returns New Block

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, data_hash, log_file, backup):
        """Creates a new transaction to go into the next mined Block. sender parameter: Address of the Sender, recipient parameter: Address of the Recipient, amount parameter: Amount, return: The index of the Block that will hold this transaction"""

        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'data_hash': data_hash,
            'log_file': log_file,
            'backup': backup,
            'timestamp': time()
        })

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """Creates a SHA-256 hash of a Block. block parameter: Block"""

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        last_block parameter: <dict> last Block, return parameter: <int>"""

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """Validates the Proof. parameter last_proof: <int> Previous Proof. parameter proof: <int> Current Proof, parameter last_hash: <str> The hash of the Previous Blocl. Return: <bool> True if correct, False if not."""

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


# Instantiate the Node
app = Flask(__name__)

# Instantiate the Blockchain
blockchain = Blockchain()


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"Error": "Page not found."}), 404


app.register_error_handler(404, page_not_found)


@app.after_request
def apply_caching(response):
    try:
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["X-Content-Type"] = "nosniff"
        response.headers["Server"] = ""
        response.headers["Pragma"] = "no-cache"
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, pre-check=0, post-check=0, max-age=0, s-maxage=0"
        return response

    except Exception as e:
        app.logger.error(e)


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender=Node_Identifier,
        recipient=Node_Identifier,
        data_hash=0,
        log_file=None,
        backup=None
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():

    if 'Authorization' in request.headers:

        if any(item in request.headers['Authorization'] for item in ['bearer', 'Bearer']):
            Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
            Authentication_Verified = API_Verification(Auth_Token)

            if Authentication_Verified["Token"]:
                values = request.get_json()

                # Check that the required fields are in the POST'ed data
                required = ['sender', 'data_hash', 'log_file', 'backup']

                if not all(k in values for k in required):
                    return 'Missing values', 400

                # Create a new Transaction
                index = blockchain.new_transaction(values['sender'], Node_Identifier, values['data_hash'],
                                                   values['log_file'], values['backup'])
                response = {'message': f'Transaction will be added to Block {index}'}
                return jsonify(response), 201

            else:
                return jsonify(Authentication_Verified), 500

        else:
            return jsonify({"Error": "Missing Bearer token."}), 500

    else:
        return jsonify({"Error": "Missing Authorization header."}), 500


@app.route('/chain', methods=['GET'])
def full_chain():
    # Allow all users to read chain.
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    if 'Authorization' in request.headers:

        if any(item in request.headers['Authorization'] for item in ['bearer', 'Bearer']):
            Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
            Authentication_Verified = API_Verification(Auth_Token)

            if Authentication_Verified["Token"]:
                values = request.get_json()
                nodes = values.get('nodes')

                if nodes is None:
                    return jsonify({"Error: Please supply a valid list of nodes"}), 400

                for node in nodes:
                    blockchain.register_node(node)

                response = {
                    'message': 'New nodes have been added',
                    'total_nodes': list(blockchain.nodes),
                }
                return jsonify(response), 201

            else:
                return jsonify({"Error": "Invalid token provided."}), 500

        else:
            return jsonify({"Error": "Missing Bearer token."}), 500

    else:
        return jsonify({"Error": "Missing Authorization header."}), 500


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    if 'Authorization' in request.headers:

        if any(item in request.headers['Authorization'] for item in ['bearer', 'Bearer']):
            Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
            Authentication_Verified = API_Verification(Auth_Token)

            if Authentication_Verified["Token"]:
                replaced = blockchain.resolve_conflicts()

                if replaced:
                    response = {
                        'message': 'Our chain was replaced',
                        'new_chain': blockchain.chain
                    }

                else:
                    response = {
                        'message': 'Our chain is authoritative',
                        'chain': blockchain.chain
                    }

                return jsonify(response), 200

            else:
                return jsonify({"Error": "Invalid token provided."}), 500

        else:
            return jsonify({"Error": "Missing Bearer token."}), 500

    else:
        return jsonify({"Error": "Missing Authorization header."}), 500


@app.route('/api/initialise', methods=['GET'])
def api_init():

    try:
        PSQL_Select_Query = 'SELECT * FROM api'
        Cursor.execute(PSQL_Select_Query,)
        User_Details = Cursor.fetchone()

        if User_Details:
            return jsonify({"Error": "API already initialised."}), 500

        else:
            API_Generation()
            return jsonify({"Message": "API Initialised."}), 200

    except Exception as e:
        return jsonify({"Error": "Failed to initialise API."}), 500

if __name__ == '__main__':

    try:

        def handler(signal_received, frame):
            print('[i] CTRL-C detected. Shutting program down.')
            sys.exit()

        try:
            Logchain_Working_Directory = pathlib.Path(__file__).parent.absolute()

            if str(Logchain_Working_Directory) != str(os.getcwd()):
                print(f"[i] Logchain Ledger has been called from outside the Logchain directory, changing the working directory to {str(Logchain_Working_Directory)}.")
                os.chdir(Logchain_Working_Directory)

                if str(Logchain_Working_Directory) != str(os.getcwd()):
                    sys.exit(f'{str(Date())} Error setting the working directory.')

        except:
            sys.exit(f'{str(Date())} Error setting the working directory.')

        signal(SIGINT, handler)
        Configuration_File = os.path.join(os.path.dirname(os.path.realpath('__file__')), 'config/ledger/config.json')
        formatter = logging.Formatter("[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")
        handler = RotatingFileHandler('Logchain.log', maxBytes=10000, backupCount=5)
        handler.setLevel(logging.INFO)
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)
        App_Details = Load_SIEM_Chain_Configuration()
        app.secret_key = os.urandom(24)
        Compress(app)
        API_Secret = App_Details["api-secret"]
        API_Validity_Limit = App_Details["api-validity-minutes"]
        Connection = Load_Main_Database()
        Cursor = Connection.cursor()
        PSQL_Select_Query = 'SELECT * FROM nodes WHERE node_fqdn = %s AND node_type = %s'
        Cursor.execute(PSQL_Select_Query, (socket.getfqdn(), "Ledger",))
        Results = Cursor.fetchone()

        if not Results:
            logging.info(f"{str(Date())} Node initialising for the first time.")
            Node_Identifier = str(uuid4()).replace('-', '')
            PSQL_Insert_Query = 'INSERT INTO nodes (node_id, node_fqdn, node_type, created_at) VALUES (%s,%s,%s,%s)'
            Cursor.execute(PSQL_Insert_Query, (Node_Identifier, socket.getfqdn(), "Ledger", datetime.now()))
            Connection.commit()

        else:
            Node_Identifier = Results[0]

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.load_cert_chain(certfile=App_Details["certificate-file"], keyfile=App_Details["key-file"])

        except:
            app.logger.fatal(f'{str(Date())} Error initiating SSL.')
            sys.exit()

        app.run(debug=App_Details["debug"], host=App_Details["host"], port=App_Details["port"], threaded=True, ssl_context=context)

    except Exception as e:
        exit(str(e))