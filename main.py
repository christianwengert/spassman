import argparse
import base64
import dataclasses
import getpass
import pathlib
import random
import secrets
import string

from nacl.pwhash import argon2i
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from utils import mk_config, ARGON_SALT_LENGTH, dump_to_file

LEN_INDICATOR = 2  # 2 bytes is enough for password
NONCE_SIZE = 12

ARGON_KEY_LENGTH = 32


# Simply store necessary configuration in ~/.spassman, this is data that can stay in memory
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


def mkrecord(service: str, username: str, password: str):
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

    # Save the record to file
    file = pathlib.Path(CONFIG['store']) / f'{service}.bin'
    dump_to_file(blob, file)


def get_master_key() -> bytes:
    # Uses Argon to derive a key from the master password
    master_password = getpass.getpass('master password')
    key = argon2i.kdf(ARGON_KEY_LENGTH, master_password.encode(), CONFIG['salt'].to_bytes(ARGON_SALT_LENGTH))
    del master_password  # note: We do not have really control over memory, but is this a problem?
    return key


def decrypt_record(blob: bytes) -> Record:
    master_key = get_master_key()

    key_cipher = ChaCha20Poly1305(master_key)
    key_nonce, encrypted_key = blob[:12], blob[12:12 + 48]

    decrypted_key = key_cipher.decrypt(key_nonce, encrypted_key, None)
    cipher = ChaCha20Poly1305(decrypted_key)
    encrypted_payload = blob[12 + 48:]

    dec = cipher.decrypt(encrypted_payload[:NONCE_SIZE], encrypted_payload[NONCE_SIZE:], None)

    return Record.deserialize(dec)


def ask_for_entry():
    # Gives the user a list of all passwords that can be selected
    p = pathlib.Path(CONFIG['store'])

    files = list(p.glob('*.bin'))
    for i, entry in enumerate(files):
        servicename = base64.b64decode(entry.name[:-4]).decode('ascii')

        print(f'[{i:2}] {servicename}')

    index = None
    while index is None:
        r = input('Type the number of the entry you want ')
        try:
            index = int(r)
        except Exception as _e:
            pass
        if index and (index < 0 or index >= len(files)):
            index = None
    return files[index]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='spassman',
        description='symmetric encryption only password manager. Quantum Safe!',
        epilog='k thanks')

    # parser.add_argument('--store', type=pathlib.Path, required=False, help='Path to the password safe, must be a folder')  # todo, for now this is at ~/.spassman/store
    subparsers = parser.add_subparsers(dest="command")
    generate_parser = subparsers.add_parser('generate')
    generate_parser.add_argument('service')
    insert_parser = subparsers.add_parser('insert')
    insert_parser.add_argument('service')
    args = parser.parse_args()

    if args.command is None:
        entry = ask_for_entry()
        with open(pathlib.Path(CONFIG['store']) / f'{entry}', 'rb') as f:
            blob = f.read()
        decrypted_entry = decrypt_record(blob)
        print(decrypted_entry)

    if args.command in ['generate', 'insert']:
        username = input('username')
        if args.command == 'insert':
            password = getpass.getpass('password')
        else:
            password = mkpassword(20)
        servicename = base64.b64encode(args.service.encode()).decode('ascii')

        mkrecord(servicename, username, password)
            
    if args.command == 'test':
        username = secrets.token_hex(16)
        password = mkpassword(20)
        mkrecord(args.service, username, password)
        with open(pathlib.Path(CONFIG['store']) / f'{args.service}.bin', 'rb') as f:
            blob = f.read()
        a = decrypt_record(blob)
        assert a.username == username
        assert a.password == password
        
    if args.command == 'backup':
        print('Not implemented yet')  # todo
        print('- We need all the password files')
        print('- We need the salt for the argon key derivation')
