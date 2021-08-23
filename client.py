import socket, sys, os, base64, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


SEPARATOR = "<D|M>"
BUFFER_SIZE = 4096
SAVE_PATH = r'C:\Users\there\Desktop'


class Client:
    def __init__(self, ip:str='127.0.0.1', port:int=4444) -> None:
        self.ip = ip
        self.port = port
        self.passwd_hash = None


    def __gen_key_from_pass(self, passwd:str)->bytes:
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
                # print('Listener Rec: ',data)
                return data
            except json.JSONDecodeError:
                continue


    def save_file(self, file_name:str, data:bytes):
        '''receive file over the connection'''
        # packet = transfer_send (sep) filename (sep) data
        
        # create file save path 
        file_name = os.path.join(SAVE_PATH, file_name)

        print(file_name)
        # Start receiving file packets
        print(f'[*] Receiving File {file_name}:')

        with open(file_name, "wb") as f:
            # decrypted_file_data = self.decrypt_data(data)
            # f.write(decrypted_file_data)
            f.write(data)
        # inform server that the transfer has been completed
        print('[*] Transfer Complete')
        self.send('transfer_completed')


    def start(self):
        # create socket for connection and connect to server
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # try to connect to the server
        try:
            self.connection.connect((self.ip, self.port))
        except ConnectionRefusedError:
            print('\r[*] Peer seems to be offline.', end='')
        
        print()
        print('[*] Connection Established')

        try:
            while True:
                message = self.receive()
                print(message)
                # list of strings
                # message_list = message.split(SEPARATOR)

                # authenticate user
                if message == 'exit':
                    print('[!] Connection closed by remote host.')
                    print('EXIT MESSAGE :', message)
                    self.connection.close()
                    sys.exit()

                elif 'auth_user' == message:
                    username = input('[+] Enter your username: ')
                    self.send(username)
                    passwd = input('[+] Enter your password: ')
                    self.send(passwd)
                    auth_result = self.receive()
                    if 'exit' != auth_result:
                        print('[*] Authenticated')
                        self.passwd_hash = self.__gen_key_from_pass(passwd)


                # receive file from server peer

                # bug: accepts only part of the packet, and saves that chunk
                # elif 'transfer_send' == message_list[0] :
                #     print('[*] Packet Received')
                #     self.save_file(file_name=message_list[1], data=message_list[2].encode('utf-8'))
                #     break

        except KeyboardInterrupt:
            print('[!] ctrl+c detected! Exiting Progam')
            sys.exit()

        finally:
            self.connection.close()


if __name__ == '__main__':
    IP = '127.0.0.1'
    PORT = 4444
    client = Client(IP, PORT)
    client.start()