import socket, sys, os, base64, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from PyTerminalColor.TerminalColor import TerminalColor




class Client:
    def __init__(self, ip:str='127.0.0.1', port:int=4444, save_path:str='') -> None:
        self.SEPARATOR = "<D|M>"
        self.BUFFER_SIZE = 4096
        self.SAVE_PATH = save_path
        self.LINE_SIZE = 60


        self.ip = ip
        self.port = port
        self.passwd_hash = None
        self.colorize = TerminalColor(fgcolor='YELLOW', bgcolor='BLACK', style='BOLD')


    def __gen_key_from_pass(self, passwd:str)->bytes:
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

        key = base64.urlsafe_b64encode(kdf.derive(passwd.encode('utf-8')))
        return key


    def encrypt_data(self, user:str, data:str)->bytes:
        '''
        encrypts data which is passed with the help of key as
        another parameter and returns encrypted data in form 
        of bytes
        '''
        KEY = self.__gen_key_from_pass(user)
        data = data.encode('utf-8')
        encrypter = Fernet(KEY)
        enc_data = encrypter.encrypt(data)
        return enc_data


    def decrypt_data(self, data:str)->bytes:
        '''
        decrypts data which is passed with the help of key as
        another parameter and returns decrypted data in form 
        of bytes
        '''
        KEY = self.passwd_hash
        if type(data) == str:
            data = data.encode('utf-8')
        decrypter = Fernet(KEY)
        dec_data = decrypter.decrypt(data)
        return dec_data


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


    def save_file(self, file_name:str, data:bytes):
        '''
        receive and save file over the connection
        '''
        # packet = transfer_send (sep) filename (sep) data

        # create file save path 
        file_name = os.path.join(self.SAVE_PATH, file_name)

        # Start receiving file packets
        self.colorize.cprint(f'[*] Receiving File {file_name}:')

        with open(file_name, "wb") as f:
            decrypted_file_data = self.decrypt_data(data)

            # decode base64 data
            data = base64.b64decode(decrypted_file_data)
            f.write(data)

        # inform server that the transfer has been completed
        self.colorize.cprint('[*] Transfer Complete', use_default=False, fgcolor='GREEN', style='BOLD')
        self.send('transfer_completed')


    def start(self):
        '''
        start client
        '''
        print()
        print('-'*self.LINE_SIZE)
        self.colorize.cprint(f'[*] Trying to connect to {self.ip}:{self.port}', use_default=False, fgcolor='YELLOW', bgcolor='RED', style='BOLD')
        print('-'*self.LINE_SIZE)


        # create socket for connection and connect to server
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # try to connect to the server
        connected = False
        while not connected:
            try:
                self.connection.connect((self.ip, self.port))
                connected = True
            except ConnectionRefusedError:
                self.colorize.cprint('\r[*] Peer seems to be offline.', end='', use_default=False, fgcolor='YELLOW', bgcolor='RED', style='BOLD')
        
        print()
        self.colorize.cprint('[*] Connection Established', use_default=False, fgcolor='GREEN', style='ITALIC')
        print('-'*self.LINE_SIZE)


        try:
            while True:

                message = self.receive()
                # split string to get data 
                message_list = message.split(self.SEPARATOR)

                # authenticate user
                if message == 'exit':
                    self.colorize.cprint('[!] Connection closed by remote host.', use_default=False, fgcolor='YELLOW', bgcolor='RED', style='BOLD')
                    print()
                    self.connection.close()
                    sys.exit()

                elif 'auth_user' == message:
                    username = input('[+] Enter your username: ')
                    self.send(username)
                    passwd = input('[+] Enter your password: ')
                    self.send(passwd)
                    print('-'*self.LINE_SIZE)

                    auth_result = self.receive()
                    if 'exit' == auth_result:
                        self.colorize.cprint('[!] Invalid Details. Exiting.', use_default=False, fgcolor='YELLOW', bgcolor='RED', style='BOLD')
                        break
                    else:
                        self.colorize.cprint('[*] Authenticated', use_default=False, fgcolor='GREEN', style='BOLD')
                        self.passwd_hash = self.__gen_key_from_pass(passwd)
                        print('-'*self.LINE_SIZE)

                # receive file from server peer
                elif 'transfer_send' == message_list[0] :
                    self.colorize.cprint('[*] Encrypted File Incoming')
                    self.save_file(file_name=message_list[1], data=message_list[2].encode('utf-8'))
                    break


        except KeyboardInterrupt:
            self.colorize.cprint('\r\n[!] ctrl+c detected! Exiting Progam')
            sys.exit()

        finally:
            self.connection.close()
            print('-'*self.LINE_SIZE)

            

if __name__ == '__main__':
    SAVE_PATH = r'C:\Users\there\Desktop'
    IP = '127.0.0.1'
    PORT = 4444
    client = Client(IP, PORT, SAVE_PATH)
    client.start()
