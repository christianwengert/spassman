import argparse
import dataclasses
import getpass
import pathlib
import random
import secrets
import string

from nacl.pwhash import argon2i
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from utils import mk_config

LEN_INDICATOR = 2  # 2 bytes is enough for password
NONCE_SIZE = 12
ARGON_SALT_LENGTH = 16
ARGON_KEY_LENGTH = 32


# Simply store necessary configuration in ~/.spassman
CONFIG = mk_config()


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
    # Creates a password of ~128 but entropy
    # todo: multi word
    # todo: makes dashes in between for better visibility?
    letters = string.ascii_letters
    digits = string.digits
    special_chars = string.printable
    alphabet = letters + digits + special_chars
    pwd_vec = [secrets.choice(alphabet) for _ in range(length)]
    return ''.join(pwd_vec)


def mkrecord(username: str, password: str) -> bytes:
    # encrypt credentials
    key = secrets.token_bytes(32)  # pure cryptographically random key of 256 bit
    nonce = secrets.token_bytes(NONCE_SIZE)
    cipher = ChaCha20Poly1305(key)
    payload = Record(username, password).serialize()
    encrypted_payload = nonce + cipher.encrypt(nonce, payload, None)

    master_key = get_master_key()

    # encrypt the file key with the master key
    key_cipher = ChaCha20Poly1305(master_key)
    key_nonce = secrets.token_bytes(NONCE_SIZE)
    encrypted_key = key_cipher.encrypt(key_nonce, key, None)
    blob = key_nonce + encrypted_key + encrypted_payload
    return blob


def get_master_key() -> bytes:
    # Uses Argon to derive a key from the master password
    master_password = getpass.getpass('master password')
    return argon2i.kdf(ARGON_KEY_LENGTH, master_password.encode(), CONFIG['salt'])


def decrypt_record(blob: bytes) -> Record:
    master_key = get_master_key()

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

    parser.add_argument('--store', type=pathlib.Path, required=False, help='Path to the password safe, must be a folder')
    subparsers = parser.add_subparsers(dest="command")
    generate_parser = subparsers.add_parser('generate')
    generate_parser.add_argument('service')
    insert_parser = subparsers.add_parser('insert')
    insert_parser.add_argument('service')
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
    if args.command == 'test':
        print('Not implemented yet')  # todo make tests here
    if args.command == 'backup':
        print('Not implemented yet')  # todo
        print('- We need all the password files')
        print('- We need the salt for the argon key derivation')
