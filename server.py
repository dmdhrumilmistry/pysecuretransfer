import socket, os, base64, json
from typing_extensions import ParamSpecArgs
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


SEPARATOR = "<D|M>"
BUFFER_SIZE = 4096
# FILE_PATH = r'path_of_file'
FILE_PATH = r'C:\Users\there\Downloads\test.jpg'


class Users:
    def __init__(self, users:list=None) -> None:
        self.__users = {}
        self.create_users(users)

    def create_users(self, users:list):
        try:
            for user, password in users:
                self.__users[user] = password
            return True
        except ValueError:
            print('[*] Users only accepts list of tuples consisting of (username, password). Ignoring passed list.')
        except TypeError:
            print('[*] No Users Created')
        finally:
            return False


    def auth_user(self, user:str, passwd:str):
        '''
        authenticates user
        '''
        if user in self.__users and self.__users[user] == passwd:
            return True
        return False


    def gen_key_from_pass(self, passwd:str)->bytes:
        '''
        Generates key from password.
        '''

        # TODO: change salt 
        salt = b'SecretSalt'  
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        passwd = bytes(passwd, encoding='utf-8')
        key = base64.urlsafe_b64encode(kdf.derive(passwd))
        return key


    def encrypt_data(self, passwd_hash:str, data:str)->bytes:
        '''
        encrypts data which is passed with the help of key as
        another parameter and returns encrypted data in form 
        of bytes
        '''
        KEY = passwd_hash
        if type(data) == str:
            data = data.encode('utf-8')
        encrypter = Fernet(KEY)
        enc_data = encrypter.encrypt(data)
        return enc_data


    def decrypt_data(self, passwd_hash:str, data:str)->bytes:
        '''
        decrypts data which is passed with the help of key as
        another parameter and returns decrypted data in form 
        of bytes
        '''
        KEY = passwd_hash
        data = data.encode('utf-8')
        decrypter = Fernet(KEY)
        dec_data = decrypter.decrypt(data)
        return dec_data


class Server:
    def __init__(self, ip:str='127.0.0.1',port:int=4444, users:list=None) -> None:
        self.ip = ip
        self.port = port
        self.users = Users(users)
        self.passwd_hash = None


    def send(self, data:str):
        if type(data) == bytes:
            data = str(data, encoding='utf-8')

        json_data = json.dumps(data)
        bytes_json_data = bytes(json_data, encoding='utf-8')
        print('send:', bytes_json_data)
        self.connection.send(bytes_json_data)


    def receive(self):
        print('in receive')
        bytes_json_data = b''
        while True:
            try:
                bytes_json_data += self.connection.recv(BUFFER_SIZE)
                data = json.loads(bytes_json_data)
                return data
            except json.JSONDecodeError:
                continue


    def close_conn(self):
        self.send('exit')
        self.connection.close()


    def authenticate_user(self):
        self.send('auth_user')
        username = self.receive()
        passwd = self.receive()

        if self.users.auth_user(username, passwd):
            self.passwd_hash = self.users.gen_key_from_pass(passwd)
            return True
        return False


    def send_file(self, file_path:str):
        
        if os.name == 'nt':
            file_name = file_path.split('\\')[-1]
        else:
            file_name = file_path.split('/')[-1]

        print(f'[*] Sending {file_name}')
        with open(file_path, "rb") as f:
            file_data = f.read()
        
        # encrypt file data
        # enc_file_data = self.users.encrypt_data(self.passwd_hash, file_data).decode('utf-8')
        # print(enc_file_data)
        
        # Creating packet
        # packet = transfer_send (sep) filename (sep) data
        # packet = f'transfer_send{SEPARATOR}{file_name}{SEPARATOR}{str(enc_file_data)}'
        packet = f'transfer_send{SEPARATOR}{file_name}{SEPARATOR}{str(file_data)}'

        self.send(packet)
        print(packet)
        
        if self.receive() == 'transfer_completed':
            return True
        return False


    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.ip, self.port))
        self.server.listen(0)
        print(f'[*] Waiting for incoming connections on {self.ip}:{self.port}')

        self.connection, self.conn_addr = self.server.accept()

        print(f'[*] Incoming from {self.conn_addr}')

        # auth incoming connection
        if self.authenticate_user():
            print(f'{self.conn_addr} Authenticated successfully')
            self.send('Authenticated')

            # if self.send_file(FILE_PATH):
                # print(f'[*] File {FILE_PATH} successfully transferred.')
            # else:
                # print(f'[!] Transferred Failed')
                
        else:
            # close connection if user is not authenticated
            print(f'{self.conn_addr} unsuccessfull authentication attempt')
        
        self.close_conn()


if __name__=='__main__':
    IP = '127.0.0.1'
    PORT = 4444
    USERS = [('1234','1234'),]
    server = Server(IP, PORT, USERS)
    server.start()
    