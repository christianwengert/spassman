import pathlib
import secrets
import tomllib
from typing import Dict

from main import ARGON_SALT_LENGTH


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
