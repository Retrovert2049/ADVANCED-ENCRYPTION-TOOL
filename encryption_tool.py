from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import getpass

class AESCipher:
    def __init__(self, key):
        self.key = key
        self.backend = default_backend()

    def encrypt_file(self, input_file, output_file):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        with open(input_file, 'rb') as f:
            plaintext = f.read()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        with open(output_file, 'wb') as f:
            f.write(iv + ciphertext)

    def decrypt_file(self, input_file, output_file):
        with open(input_file, 'rb') as f:
            iv = f.read(16)
            ciphertext = f.read()

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        with open(output_file, 'wb') as f:
            f.write(plaintext)

def main():
    password = getpass.getpass('Enter password: ')
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    cipher = AESCipher(key)

    while True:
        print('1. Encrypt file')
        print('2. Decrypt file')
        print('3. Exit')
        choice = input('Choose an option: ')
        if choice == '1':
            input_file = input('Enter input file path: ')
            output_file = input('Enter output file path: ')
            cipher.encrypt_file(input_file, output_file)
            print('File encrypted successfully.')
        elif choice == '2':
            input_file = input('Enter input file path: ')
            output_file = input('Enter output file path: ')
            cipher.decrypt_file(input_file, output_file)
            print('File decrypted successfully.')
        elif choice == '3':
            break
        else:
            print('Invalid choice. Please try again.')
if __name__ == '__main__':
    main()
