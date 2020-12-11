import asyncio
import logging
import functools
import json
import tempfile
import argparse

from typing import Dict, Tuple, Callable, Coroutine, Optional
from typing.io import IO
from enum import Enum, auto
from Crypto.PublicKey import RSA

from Encryptor import SymmetricEncryptor, AsymmetricEncryptor

parser = argparse.ArgumentParser()

parser.add_argument("name",
                    type=str)

parser.add_argument("host",
                    type=str)

parser.add_argument("port",
                    type=int)

args = parser.parse_args()

CHUNK = 1024

BUFFER_LIMIT = 256 * 1024 * 1024


class DataMode(Enum):
    FILE = auto()
    BYTES = auto()


class Server:
    def __init__(self, name: str, address: Tuple[str, int]):
        self.name = name
        self.address = address
        self.clients: Dict[Tuple[str, int],
                           Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}

        self.events: Dict[name,
                          Tuple[Callable[[Tuple[str, int], Optional[IO, bytes, str]],
                                         Coroutine],
                                DataMode]] = {}

        keys = (f'server_keys/{name}_public.pem', f'server_keys/{name}_private.pem')

        self.public_key, self.private_key = AsymmetricEncryptor.read_key_pairs(keys)

        self.encryptors: Dict[Tuple[str, int], SymmetricEncryptor] = {}

        self.clients_public_keys = {}

        @self.event()
        async def connect(sid: Tuple[str, int]):
            logging.info(f'{sid} jumped into {self.name} server.')

        @self.event()
        async def disconnect(sid: Tuple[str, int]):
            logging.info(f'{sid} left {self.name} server.')

        @self.event()
        async def pong(sid: Tuple[str, int]):
            logging.info(f'Pong! from {sid}')

        @self.event()
        async def message(sid: Tuple[str, int], data: str):
            logging.info(f'{sid} say\'s {data}')

    def event(self, name=None, data_mode: DataMode = DataMode.BYTES):
        @functools.wraps(self.event)
        def inner_function(func):
            event_name = name if name is not None else func.__name__

            logging.info(f"Registering event {event_name!r}")

            @functools.wraps(func)
            async def wrapper(sid: Tuple[str, int], data):
                reserved_events = {
                    'connect': lambda: func(sid),
                    'disconnect': lambda: func(sid),
                    'pong': lambda: func(sid),
                    'message': lambda: func(sid, data.decode(encoding='utf-8')),
                }

                await reserved_events.get(event_name, lambda: func(sid, data))()

            self.events[event_name] = (wrapper, data_mode)

        return inner_function

    async def write_to_file(self, sid: Tuple[str, int], file: IO,
                            reader: asyncio.StreamReader, data_len: int, iv: bytes):

        remaining = data_len

        while remaining > 0:
            chunk = min(remaining, CHUNK)

            encrypted_data = await reader.read(chunk)

            if len(encrypted_data) != chunk:
                raise ConnectionError

            data = self.encryptors[sid].decrypt(encrypted_data, iv)

            file.write(data)

            remaining -= chunk

    async def on_connection_made(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        sio = (reader, writer)

        sid = writer.get_extra_info('peername')

        self.clients[sid] = sio

        # RECEIVING CLIENT PUBLIC KEY
        client_pub_key_len = int.from_bytes(await reader.read(8), 'big')

        self.clients_public_keys[sid] = RSA.import_key(await reader.read(client_pub_key_len))

        # SENDING SERVER PUBLIC KEY TO CLIENT
        writer.write(len(self.public_key.export_key()).to_bytes(8, 'big'))

        writer.write(self.public_key.export_key())

        await writer.drain()

        # RECEIVING ENCRYPTED SESSION KEY FROM CLIENT
        data_len = int.from_bytes(await reader.read(8), 'big')

        enc_session_key = await reader.read(data_len)

        session_key = AsymmetricEncryptor.decrypt(self.private_key, enc_session_key)

        self.encryptors[sid] = SymmetricEncryptor(session_key)

        await self.events['connect'][0](sid, None)

        async def default_event(param):
            pass

        try:
            while True:

                iv = await reader.read(16)

                if len(iv) != 16:
                    raise ConnectionError

                encrypted_data = await reader.read(16)

                if len(encrypted_data) != 16:
                    raise ConnectionError

                data = self.encryptors[sid].decrypt(encrypted_data, iv)

                data_len = int.from_bytes(data, 'big')

                encrypted_data = await reader.read(data_len)

                if len(encrypted_data) != data_len:
                    raise ConnectionError

                data = self.encryptors[sid].decrypt(encrypted_data, iv)

                data = json.loads(data)

                data_len = data['data_length']

                event_coroutine, data_mode = self.events.get(data['event'],
                                                             (default_event,
                                                              DataMode.FILE if data_len > BUFFER_LIMIT
                                                              else DataMode.BYTES))
                buffer = None

                if data_mode == DataMode.BYTES:
                    buffer = await reader.read(data_len)

                    if len(buffer) != data_len:
                        raise ConnectionError

                    buffer = self.encryptors[sid].decrypt(buffer, iv)

                if data_mode == DataMode.FILE:
                    tmp_file = tempfile.TemporaryFile()
                    await self.write_to_file(sid, tmp_file, reader, data_len, iv)
                    tmp_file.seek(0)
                    buffer = tmp_file

                asyncio.ensure_future(event_coroutine(sid, buffer))

        except ConnectionError:
            asyncio.ensure_future(self.events['disconnect'][0](sid, None))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            del self.clients[sid]

    async def send(self, to: Tuple[str, int], event: str, data: bytes):
        _, writer = self.clients[to]

        iv = SymmetricEncryptor.generate_iv()

        writer.write(iv)

        encrypted_data = self.encryptors[to].encrypt(data, iv)

        header = json.dumps({'event': event, 'data_length': len(encrypted_data)}).encode()

        encrypted_header = self.encryptors[to].encrypt(header, iv)

        encrypted_len = self.encryptors[to].encrypt(len(encrypted_header).to_bytes(8, 'big'), iv)

        writer.write(encrypted_len)

        writer.write(encrypted_header)

        writer.write(encrypted_data)

        await writer.drain()


async def start_server(name='Nitro', host='localhost', port=8080):
    logging.basicConfig(level=logging.INFO)

    server = Server(name, (host, port))

    @server.event()
    async def view(sid, data):
        s = ''
        try:
            with open(f'files/{data.decode()}') as f:
                s = ''.join([s, f.readline()])
        except FileExistsError:
            await server.send(sid, 'view', b'File not found')
        except FileNotFoundError:
            await server.send(sid, 'view', b'File not found')

        await server.send(sid, 'view', s.encode())

    @server.event(data_mode=DataMode.FILE)
    async def file_edit(sid, file: IO):
        file_name_len = int.from_bytes(file.read(8), 'big')

        file_name = file.read(file_name_len).decode()
        try:
            with open(f'files/{file_name}', 'wb') as f:
                while True:
                    data = file.read(CHUNK)

                    if not data:
                        break

                    f.write(data)
        except FileExistsError:
            await server.send(sid, 'file_edit', b'File not found')
        except FileNotFoundError:
            await server.send(sid, 'file_edit', b'File not found')

        await server.send(sid, 'file_edit', b'Editing done')

    abstract_server = await asyncio.start_server(
        server.on_connection_made, server.address[0], server.address[1])

    logging.info(f'Serving on {server.address}')

    async with abstract_server:
        await abstract_server.serve_forever()


asyncio.run(start_server(args.name, args.host, args.port))
