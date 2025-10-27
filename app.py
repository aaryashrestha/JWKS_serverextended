from datetime import datetime, timedelta, timezone
import sqlite3
import time
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jose import jwt
from flask import Flask, jsonify, request

class KeyStore:
    #Manages RSA keys in SQLite database with the proper parameterization
    def __init__(self, db_path='totally_not_my_privateKeys.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db() #Database initialization
        self._seed_keys()

    def _init_db(self):
        #database is initialized with a safe parameterized query
        with self.conn:
            self.conn.execute(''' 
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
            ''')

    def _seed_keys(self):
        #Seed the database with a valid and expired key
        now = datetime.now(timezone.utc)
        if not self.get_key(expired=False):
            self.generate_key(expiry=now + timedelta(hours=1))  # Valid key
        if not self.get_key(expired=True):
            self.generate_key(expiry=now - timedelta(minutes=1))  # Expired key

    def generate_key(self, expiry=None):
        #Generate a new RSA key and store it in the database with proper serialization
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        exp_timestamp = int(expiry.timestamp()) if expiry else None
        
        with self.conn:
            cursor = self.conn.execute(
                'INSERT INTO keys (key, exp) VALUES (?, ?)',
                (pem, exp_timestamp)
            )
        return cursor.lastrowid

    def get_key(self, expired=False):
        #Retrieve a private key from the database with a parameterized query
        now = int(datetime.now(timezone.utc).timestamp())
        operator = '<' if expired else '>'
        
        cursor = self.conn.execute(
            f'SELECT kid, key FROM keys WHERE exp {operator} ? ORDER BY kid DESC LIMIT 1',
            (now,)
        )
        result = cursor.fetchone()
        
        if not result:
            return None
            
        kid, pem = result
        return kid, serialization.load_pem_private_key(pem, password=None)

    def get_jwks(self):

        now = int(datetime.now(timezone.utc).timestamp())
        cursor = self.conn.execute(
            'SELECT kid, key FROM keys WHERE exp > ?',
            (now,)
        )
        
        jwks = []
        for kid, pem in cursor:
            public_key = serialization.load_pem_private_key(
                pem,
                password=None
            ).public_key()
            
            public_numbers = public_key.public_numbers()
            jwks.append({
                "kty": "RSA",
                "kid": str(kid),
                "use": "sig",
                "alg": "RS256",
                "n": int_to_base64url(public_numbers.n),
                "e": int_to_base64url(public_numbers.e),
            })
        return {"keys": jwks}

    def close(self):
        """Safely close database connection with Windows file lock handling"""
        if self.conn:
            self.conn.close()
            self.conn = None
            if self.db_path != ':memory:': 
                for _ in range(5): 
                    try:
                        if os.path.exists(self.db_path):
                            os.remove(self.db_path)
                        break
                    except (PermissionError, FileNotFoundError):
                        time.sleep(0.1)

def int_to_base64url(value):
    """Convert integer to Base64URL-encoded string"""
    byte_length = (value.bit_length() + 7) // 8
    bytes_value = value.to_bytes(byte_length, byteorder='big')
    return base64.urlsafe_b64encode(bytes_value).decode('utf-8').rstrip('=')

app = Flask(__name__)
keystore = KeyStore()

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """Serve valid public keys from database"""
    return jsonify(keystore.get_jwks())

@app.route('/auth', methods=['POST'])
def auth():
    """Issue JWT with database-backed key using secure queries"""
    try:
        expired = request.args.get('expired', '').lower() in ['true', '1']
        key_data = keystore.get_key(expired=expired)
        
        if not key_data:
            return jsonify({"error": "Key not found"}), 500
            
        kid, private_key = key_data
        #Serialize private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        payload = {
            "sub": "userABC",
            "iss": "jwks-server",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        
        token = jwt.encode(
            payload,
            private_key_pem,
            algorithm='RS256',
            headers={'kid': str(kid)}
        )
        return jsonify({"token": token})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    try:
        app.run(port=8080)
    finally:
        keystore.close()