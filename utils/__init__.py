import pathlib
import secrets
import tomllib
from typing import Dict

ARGON_SALT_LENGTH = 16


def mk_config() -> Dict:
    config_dir = pathlib.Path('~/.spassman/').expanduser()
    if not config_dir.exists():
        config_dir.mkdir()
    store_dir = config_dir / 'store'  # todo: this could be set dynamically via command line.
    if not store_dir.exists():
        store_dir.mkdir()
    config_file = config_dir / 'config.toml'
    if not config_file.exists():
        salt = secrets.token_bytes(ARGON_SALT_LENGTH)
        with open(config_file, 'w') as f:
            f.writelines(
                [
                    f'store = "{store_dir}"\n',
                    f'salt = 0x{salt.hex()}'
                ]
            )
    with open(config_file, 'rb') as f:
        config = tomllib.load(f)
    return config


def dump_to_file(blob: bytes, file: pathlib.Path):
    # Saves the bunary blob to file ./spassman/store/{service}.bin
    # Asks what to do if already exists
    if not file.exists():
        overwrite = True
    else:
        overwrite = False
        while not overwrite:
            r = input(f'A entry for {file} already exist. Do you want to overwrite? y/n')
            if r == 'y':
                overwrite = True
            if r == 'n':
                break

    if overwrite:
        with open(file, 'wb') as f:
            f.write(blob)
