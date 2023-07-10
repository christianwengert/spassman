import argparse
import dataclasses
import getpass
import pathlib
import random
import secrets
import string

from nacl.pwhash import argon2i
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

LEN_INDICATOR = 2  # 2 bytes is enough for password


NONCE_SIZE = 12


ARGON_SALT_LENGTH = 16

user_config = pathlib.Path('~/.spassman').expanduser()
if not user_config.exists():
    with open(user_config, 'wb') as f:
        salt = secrets.token_bytes(ARGON_SALT_LENGTH)
        f.write(salt)
with open(user_config, 'rb') as f:
    salt = f.read()


@dataclasses.dataclass
class Record:
    username: str
    password: str

    def serialize(self) -> bytes:
        plen = len(self.password).to_bytes(length=LEN_INDICATOR, byteorder='big')  # raises if it does not fit, which is OK
        ulen = len(self.username).to_bytes(length=LEN_INDICATOR, byteorder='big')
        # add random padding
        return plen + self.password.encode() + ulen + self.username.encode() + secrets.token_bytes(random.randint(0, 256))

    @staticmethod
    def deserialize(blob: bytes):
        pwlen = int.from_bytes(blob[:LEN_INDICATOR], 'big')
        blob = blob[LEN_INDICATOR:]

        password = blob[:pwlen].decode()
        blob = blob[pwlen:]

        ulen = int.from_bytes(blob[:LEN_INDICATOR], 'big')
        blob = blob[LEN_INDICATOR:]

        username = blob[:ulen].decode()
        return Record(username=username, password=password)


def mkpassword(length: int) -> str:
    letters = string.ascii_letters
    digits = string.digits
    special_chars = string.printable
    alphabet = letters + digits + special_chars
    pwd_vec = [secrets.choice(alphabet) for _ in range(length)]
    return ''.join(pwd_vec)


def mkrecord(username: str, password: str) -> bytes:
    # encrypt credentials
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(NONCE_SIZE)
    cipher = ChaCha20Poly1305(key)
    payload = Record(username, password).serialize()
    encrypted_payload = nonce + cipher.encrypt(nonce, payload, None)
    # derive the key, use argon2i
    master_password = getpass.getpass('master password')
    master_key = kdf(master_password)
    # encrypt the key
    key_cipher = ChaCha20Poly1305(master_key)
    key_nonce = secrets.token_bytes(NONCE_SIZE)
    encrypted_key = key_cipher.encrypt(key_nonce, key, None)
    blob = key_nonce + encrypted_key + encrypted_payload
    return blob


def kdf(master_password: str) -> bytes:
    return argon2i.kdf(32, master_password.encode(), salt)



def decrypt_record(blob: bytes) -> Record:
    # derive the key, use argon2i
    master_password = getpass.getpass('master password')
    master_key = kdf(master_password)

    key_cipher = ChaCha20Poly1305(master_key)
    key_nonce, encrypted_key = blob[:12], blob[12:12 + 48]

    decrypted_key = key_cipher.decrypt(key_nonce, encrypted_key, None)
    cipher = ChaCha20Poly1305(decrypted_key)
    encrypted_payload = blob[12 + 48:]

    dec = cipher.decrypt(encrypted_payload[:NONCE_SIZE], encrypted_payload[NONCE_SIZE:], None)

    return Record.deserialize(dec)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='spassman',
        description='symmetric encryption only password manager. Quantum Safe!',
        epilog='k thanks')

    # group = parser.add_mutually_exclusive_group()
    # group.add_argument('--init', type=pathlib.Path, required=False, help='Init a new password safe, must be a folder')
    parser.add_argument('--store', type=pathlib.Path, required=False, help='Path to the password safe, must be a folder')
    #

    # group.add_argument('generate', required=False, type=str)
    subparsers = parser.add_subparsers(dest="command")
    generate_parser = subparsers.add_parser('generate')
    generate_parser.add_argument('service')
    insert_parser = subparsers.add_parser('insert')
    insert_parser.add_argument('service')
    # subparsers = parser.add_subparsers(help='generate help', dest='generate')
    #
    # parser_a = subparsers.add_parser('command', help='command_generate help')
    # parser_a.add_argument('service', type=str)
    #
    # parser_b = subparsers.add_parser('insert', help='command_generate help')
    # parser_b.add_argument('service2', type=str)

    args = parser.parse_args()

    if args.command == 'generate':
        username = input('username')
        password = mkpassword(20)
        blob = mkrecord(username, password)
        a = decrypt_record(blob)
        print(a)
    if args.command == 'insert':
        username = input('username')
        password = getpass.getpass('password')
        blob = mkrecord(username, password)
        a = decrypt_record(blob)
        print(a)

    # parser.print_help()
