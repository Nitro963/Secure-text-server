import argparse
import asyncio
import functools
import json
import logging
import tempfile
import os
from enum import Enum, auto

from concurrent.futures.thread import ThreadPoolExecutor
from pathlib import Path

from typing import Tuple, Optional
from typing.io import IO

from Crypto.PublicKey import RSA

from Encryptor import SymmetricEncryptor, AsymmetricEncryptor

parser = argparse.ArgumentParser()

parser.add_argument("remote_host",
                    type=str)

parser.add_argument("remote_port",
                    type=int)

args = parser.parse_args()

CHUNK = 1024

BUFFER_LIMIT = 256 * 1024 * 1024


class DataMode(Enum):
    FILE = auto()
    BYTES = auto()


class Client:
    def __init__(self, name: str, remote_host_address: Tuple[str, int]):
        self.name = name
        self.address = remote_host_address
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.events = {}

        self.server_public_key = None

        keys = (f'client_keys/{name}_public.pem', f'client_keys/{name}_private.pem')

        self.client_public_key, self.client_private_key = AsymmetricEncryptor.read_key_pairs(keys)

        self.encryptor = None

        @self.event()
        async def disconnect():
            print('remote host disconnected')

    async def write_to_file(self, file: IO, reader: asyncio.StreamReader, data_len: int, iv: bytes):
        remaining = data_len

        while remaining > 0:
            chunk = min(remaining, CHUNK)

            encrypted_data = await reader.read(chunk)

            if len(encrypted_data) != chunk:
                raise ConnectionError

            data = self.encryptor.decrypt(encrypted_data, iv)

            file.write(data)

            remaining -= chunk

    async def create_connection(self, connection_event: Optional[asyncio.Event] = None):
        reader, writer = await asyncio.open_connection(*self.address)
        self.reader = reader
        self.writer = writer

        # SENDING PUBLIC KEY TO  SERVER
        public_key_len = len(self.client_public_key.export_key()).to_bytes(8, 'big')
        writer.write(public_key_len)
        writer.write(self.client_public_key.export_key())

        # RECEIVING SERVER PUBLIC KEY AND SEND ENCRYPTED SESSION KEY
        key_len = int.from_bytes(await reader.read(8), 'big')

        self.server_public_key = RSA.import_key(await reader.read(key_len))

        self.encryptor = SymmetricEncryptor(SymmetricEncryptor.generate_key())

        enc_session_key = AsymmetricEncryptor.encrypt(self.server_public_key, self.encryptor.session_key)

        writer.write(len(enc_session_key).to_bytes(8, 'big'))

        writer.write(enc_session_key)

        await writer.drain()

        if connection_event:
            connection_event.set()
        try:
            await self._process_incoming_events()
        except ConnectionError:
            asyncio.ensure_future(self.events['disconnect'][0](None))
        finally:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except ConnectionError:
                pass
            self.reader = None
            self.writer = None

    async def _process_incoming_events(self):

        async def default_event(param):
            pass

        while True:
            iv = await self.reader.read(16)

            if len(iv) != 16:
                raise ConnectionError

            encrypted_data = await self.reader.read(16)

            if len(encrypted_data) != 16:
                raise ConnectionError

            data = self.encryptor.decrypt(encrypted_data, iv)

            data_len = int.from_bytes(data, 'big')

            encrypted_data = await self.reader.read(data_len)

            if len(encrypted_data) != data_len:
                raise ConnectionError

            data = self.encryptor.decrypt(encrypted_data, iv)

            data = json.loads(data)

            data_len = data['data_length']

            event_coroutine, data_mode = self.events.get(data['event'],
                                                         (default_event,
                                                          DataMode.FILE if data_len > BUFFER_LIMIT else DataMode.BYTES))

            buffer = None

            if data_mode == DataMode.BYTES:
                buffer = await self.reader.read(data_len)

                if len(buffer) != data_len:
                    raise ConnectionError

                buffer = self.encryptor.decrypt(buffer, iv)

            if data_mode == DataMode.FILE:
                tmp_file = tempfile.TemporaryFile()
                await self.write_to_file(tmp_file, self.reader, data_len, iv)
                buffer = tmp_file

            asyncio.ensure_future(event_coroutine(buffer))

    def event(self, name=None, data_mode: DataMode = DataMode.BYTES):
        @functools.wraps(self.event)
        def inner_function(func):
            event_name = name if name is not None else func.__name__

            logging.info(f"Registering event {event_name!r}")

            @functools.wraps(func)
            async def wrapper(data):
                reserved_events = {
                    'connect': lambda: func(),
                    'disconnect': lambda: func(),
                    'pong': lambda: func(),
                    'message': lambda: func(data.decode(encoding='utf-8')),
                }

                await reserved_events.get(event_name, lambda: func(data))()

            self.events[event_name] = (wrapper, data_mode)

        return inner_function

    def is_connected(self) -> bool:
        return self.reader is not None

    async def send(self, event: str, data: bytes):
        if not self.is_connected():
            raise ConnectionError

        iv = SymmetricEncryptor.generate_iv()

        self.writer.write(iv)

        encrypted_data = self.encryptor.encrypt(data, iv)

        header = json.dumps({'event': event, 'data_length': len(encrypted_data)}).encode()

        encrypted_header = self.encryptor.encrypt(header, iv)

        encrypted_len = self.encryptor.encrypt(len(encrypted_header).to_bytes(8, 'big'), iv)

        self.writer.write(encrypted_len)

        self.writer.write(encrypted_header)

        self.writer.write(encrypted_data)

        await self.writer.drain()

    async def send_file(self, event: str, path: Path):
        if not self.is_connected():
            raise ConnectionError

        iv = SymmetricEncryptor.generate_iv()

        self.writer.write(iv)

        data_size = path.stat().st_size

        padding_len = 16 - data_size % 16

        header = json.dumps({'event': event, 'data_length': data_size + padding_len}).encode()

        encrypted_header = self.encryptor.encrypt(header, iv)

        encrypted_len = self.encryptor.encrypt(len(encrypted_header).to_bytes(8, 'big'), iv)

        self.writer.write(encrypted_len)

        self.writer.write(encrypted_header)

        with open(path, 'rb') as f:
            while True:
                data = f.read(1024)

                if not data:
                    break

                self.writer.write(self.encryptor.encrypt(data, iv))

        await self.writer.drain()


def edit_file(file_name: str):
    with open(f'{file_name}', 'ab') as f:
        print("Enter Your New Text.")
        try:
            while True:
                s = input()
                f.write(s.encode())
        except EOFError:
            pass


async def main():

    client = Client('NitroClient', (args.remote_host, args.remote_port))

    logging.basicConfig(level=logging.INFO)

    view_event = asyncio.Event()

    @client.event()
    async def view(data):
        print(data.decode(encoding='utf-8'))
        view_event.set()

    @client.event(data_mode=DataMode.BYTES)
    async def file_edit(data: bytes):
        print(data.decode())

    with ThreadPoolExecutor(2) as pool:
        try:
            connection_event = asyncio.Event()

            asyncio.ensure_future(client.create_connection(connection_event))

            await connection_event.wait()

            while True:
                result = await asyncio.get_running_loop().run_in_executor(pool, input, 'Enter Your Command: ')

                result = int(result)

                if not result:
                    break

                if result == 1:
                    view_event.clear()
                    file_name = await asyncio.get_running_loop().run_in_executor(pool, input, 'Enter file name: ')
                    await client.send('view', file_name.encode())
                    print("waiting for server response...")
                    await view_event.wait()
                    await asyncio.get_running_loop().run_in_executor(pool, input, 'Enter Any Key..')

                if result == 2:
                    file_name = await asyncio.get_running_loop().run_in_executor(pool, input, 'Enter file name: ')

                    with open(f'{file_name}', 'wb') as f:
                        f.write(len(file_name).to_bytes(8, 'big'))
                        f.write(file_name.encode())

                    await asyncio.get_running_loop().run_in_executor(pool, edit_file, file_name)

                    await client.send_file('file_edit', Path(f'{file_name}'))

                    os.remove(file_name)

        except ConnectionError:
            pass
        except Exception as e:
            logging.error(e, exc_info=e)

asyncio.run(main())
