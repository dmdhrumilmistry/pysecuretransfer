import socket, os, base64, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from PyTerminalColor.TerminalColor import TerminalColor


class Users:
    def __init__(self, users:list=None) -> None:
        self.__users = {}
        self.create_users(users)
        self.colorize = TerminalColor(fgcolor='YELLOW', bgcolor='BLACK', style='BOLD')


    def create_users(self, users:list):
        '''
        create users for authentication using passed list[tuple(username, password)]
        '''
        try:
            for user, password in users:
                self.__users[user] = password
            return True
        except ValueError:
            self.colorize.cprint('[!] Users only accepts list of tuples consisting of (username, password). Ignoring passed list.', use_default=False, fgcolor='YELLOW', bgcolor='RED', style='BOLD')
        except TypeError:
            self.colorize.cprint('[!] No Users were created\n', use_default=False, fgcolor='YELLOW', bgcolor='RED', style='BOLD')
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
    def __init__(self, ip:str='127.0.0.1', port:int=4444, users:list=None, file_path:str='') -> None:
        self.SEPARATOR = "<D|M>"
        self.BUFFER_SIZE = 4096
        self.FILE_PATH = file_path
        self.LINE_SIZE = 60

        self.ip = ip
        self.port = port
        self.users = Users(users)
        self.passwd_hash = None
        self.colorize = TerminalColor(fgcolor='YELLOW', bgcolor='BLACK', style='BOLD')



    def send(self, data:str):
        '''
        sends data serially
        '''
        if type(data) == bytes:
            data = str(data, encoding='utf-8')

        json_data = json.dumps(data)
        bytes_json_data = bytes(json_data, encoding='utf-8')
        self.connection.send(bytes_json_data)


    def receive(self):
        '''
        receives data serially
        '''
        bytes_json_data = b''
        while True:
            try:
                bytes_json_data += self.connection.recv(self.BUFFER_SIZE)
                data = json.loads(bytes_json_data)
                return data
            except json.JSONDecodeError:
                continue


    def close_conn(self):
        '''
        forcely close connection
        '''
        print('-'*self.LINE_SIZE)
        self.colorize.cprint(f'[!] Closing {self.conn_addr} connection.', use_default=False, fgcolor='YELLOW', bgcolor='RED', style='BOLD')
        self.send('exit')
        self.connection.close()
        print('-'*self.LINE_SIZE)




    def authenticate_user(self):
        '''
        authenticate user before transferring file
        '''
        # send authentication request
        self.send('auth_user')

        # accept username and password
        username = self.receive()
        passwd = self.receive()

        if self.users.auth_user(username, passwd):
            self.passwd_hash = self.users.gen_key_from_pass(passwd)
            return True
        return False


    def send_file(self):
        '''
        sends file securely.
        '''

        if os.name == 'nt':
            file_name = self.FILE_PATH.split('\\')[-1]
        else:
            file_name = self.FILE_PATH.split('/')[-1]

        self.colorize.cprint(f'[*] Sending {file_name}', use_default=False, fgcolor='YELLOW')
        with open(self.FILE_PATH, "rb") as f:
            file_data = f.read()

            # encode file data to base64 format 
            file_data = base64.b64encode(file_data)
        
        # encrypt file data
        enc_file_data = self.users.encrypt_data(self.passwd_hash, file_data).decode('utf-8')
        
        # Creating packet
        # packet = transfer_send (sep) filename (sep) data
        packet = f'transfer_send{self.SEPARATOR}{file_name}{self.SEPARATOR}{str(enc_file_data)}'

        # send packet over network
        self.send(packet)
        
        # receive acknowledgement
        if self.receive() == 'transfer_completed':
            return True
        return False


    def start(self):
        '''
        starts server
        '''
        print()

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.ip, self.port))
        self.server.listen(0)

        print('-'*self.LINE_SIZE)
        self.colorize.cprint(f'[*] Waiting for incoming connections on {self.ip}:{self.port}')
        self.connection, self.conn_addr = self.server.accept()
        print('-'*self.LINE_SIZE)


        self.colorize.cprint(f'[*] Incoming from {self.conn_addr}')

        # auth incoming connection
        if self.authenticate_user():
            self.colorize.cprint(f'[*] {self.conn_addr} Authenticated successfully. Logged in',use_default=False, fgcolor='GREEN', style='BOLD')
            self.send('Authenticated')
            print('-'*self.LINE_SIZE)


            if self.send_file():
                self.colorize.cprint(f'[*] File {self.FILE_PATH} successfully transferred.', use_default=False, fgcolor='GREEN', style='ITALIC')
            else:
                self.colorize.cprint(f'[!] Transferred Failed', use_default=False, fgcolor='YELLOW', bgcolor='RED', style='BOLD')
                
        else:
            # close connection if user is not authenticated
            self.colorize.cprint(f'[!] {self.conn_addr} unsuccessfull authentication attempt', use_default=False, fgcolor='YELLOW', bgcolor='RED', style='BOLD')
        
        self.close_conn()



if __name__=='__main__':
    FILE_PATH = r'path_to_file'
    IP = '127.0.0.1'
    PORT = 4444
    USERS = [
        ('1234','1234'),
        ]
    server = Server(IP, PORT, USERS, FILE_PATH)
    server.start()
    
