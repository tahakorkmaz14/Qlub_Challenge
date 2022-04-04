from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii


def encrypt(message: str, key_file_name: str):
    """Encrypts a message using RSA Encryption
    Arguments:
        message (str): Data to be encrypted
        key_file_name (str): Public Key File Name to be used for encryption
    """
    with open(key_file_name, "rb") as file:
        public_key = RSA.importKey(file.read())

    rsa = PKCS1_OAEP.new(public_key)
    encrypted_text = rsa.encrypt(message.encode())
    return binascii.hexlify(encrypted_text).decode()


def decrypt(message: str, key_file_name: str):
    """Decrypts a message using RSA Encryption
    Arguments:
        message (str): Data to be decrypted
        key_file_name (str): Private Key File Name to be used for Decryption
    """
    message = binascii.unhexlify(message.encode())
    with open(key_file_name, "rb") as file:
        private_key = RSA.importKey(file.read())

    rsa = PKCS1_OAEP.new(private_key)
    decrypted_text = rsa.decrypt(message)
    return decrypted_text.decode()


def generate_key(bits=4096):
    """Genrates Public and Private Key Pairs for RSA Encryption and saves to the disk.
    Files are saved to the disk with name - id_rsa and id_rsa.pub
    Arguments:
        bits (int, optional): RSA Key bits length. Defaults to 4096.
    """
    working_directory = Path.cwd()
    keypair = RSA.generate(bits)

    private_key_file = working_directory / "key_rsa"
    with open(private_key_file, "wb") as file:
        file.write(keypair.export_key())

    public_key_file = working_directory / "key_rsa.pub"
    with open(public_key_file, "wb") as file:
        file.write(keypair.publickey().export_key())

