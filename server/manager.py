import asyncio
import logging
import functools
import json
from io import BufferedWriter
from typing import Dict, Tuple, Callable, Coroutine
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto import Random
from Encryptor import Encryptor

CHUNK = 1024


class Socket:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.writer = writer
        self.reader = reader
        self.sid = self.writer.get_extra_info('peername')

    async def send(self, data: bytes):
        self.writer.write(data)

        await self.writer.drain()


class Server(Encryptor):
    def __init__(self, name: str, address: Tuple[str, int]):
        self.name = name
        self.address = address
        self.clients: Dict[Tuple[str, int], Socket] = {}
        self.events: Dict[name, Callable[[Tuple[str, int], int], Coroutine]] = {}
        self.iv = b''

        @self.event
        async def connect(sid: Tuple[str, int]):
            logging.info(f'{sid} jumped into {self.name} server.')

        @self.event
        async def disconnect(sid: Tuple[str, int]):
            logging.info(f'{sid} left {self.name} server.')

        @self.event
        async def pong(sid: Tuple[str, int]):
            logging.info(f'Pong! from {sid}')

        @self.event
        async def message(sid: Tuple[str, int], data: str):
            decryptedText = self.decrypt_message(data,self.iv)
            logging.info(f'{sid} say\'s {decryptedText}')

        @self.event
        async def iv(sid: Tuple[str, int], data: str):
            self.iv = data
            logging.info(f'{sid} iv is {data}')

    def event(self, func, name=None):
        name = name if name is not None else func.__name__

        logging.info(f"Registering event {name!r}")

        @functools.wraps(func)
        async def wrapper(sid: Tuple[str, int], data_len: int):
            buffer = await self.clients[sid].reader.read(data_len)

            if len(buffer) != data_len:
                raise ConnectionAbortedError

            reserved_events = {
                'connect': lambda: func(sid),
                'disconnect': lambda: func(sid),
                'pong': lambda: func(sid),
                'message': lambda: func(sid, buffer),
            }

            await reserved_events.get(name, lambda: func(sid, buffer))()

        self.events[name] = wrapper

    @staticmethod
    async def write_to_file(file: BufferedWriter, reader: asyncio.StreamReader, data_len: int):
        remaining = data_len

        while remaining > 0:
            chunk = min(remaining, CHUNK)

            data = await reader.read(chunk)

            if len(data) != chunk:
                raise ConnectionAbortedError

            file.write(data)

            remaining -= chunk

    async def on_connection_made(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        sio = Socket(reader, writer)

        self.clients[sio.sid] = sio

        await self.events['connect'](sio.sid, 0)

        try:
            while True:
                data = await reader.read(8)

                if len(data) != 8:
                    raise ConnectionAbortedError

                # decrypt data

                data_len = int.from_bytes(data, 'big')

                data = await reader.read(data_len)

                if len(data) != data_len:
                    raise ConnectionAbortedError

                # decrypt data

                data = json.loads(data)

                await self.events[data['event']](sio.sid, data['data_length'])

        except ConnectionAbortedError:
            asyncio.ensure_future(self.events['disconnect'](sio.sid, 0))
        finally:
            self.clients[sio.sid].writer.close()
            await self.clients[sio.sid].writer.wait_closed()
            del self.clients[sio.sid]


async def start_server(name='Nitro', host='localhost', port=8888):
    logging.basicConfig(level=logging.INFO)

    server = Server(name, (host, port))

    # @server.event
    # async def view(sid, data):
    #     print(f'{sid} want\'s to view')

    abstract_server = await asyncio.start_server(
        server.on_connection_made, server.address[0], server.address[1])

    logging.info(f'Serving on {server.address}')

    async with abstract_server:
        await abstract_server.serve_forever()
