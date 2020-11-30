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

from Encryptor import Encryptor

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
        self.encryptor = Encryptor()

    async def write_to_file(self, file: IO, reader: asyncio.StreamReader, data_len: int, iv: bytes):
        remaining = data_len

        while remaining > 0:
            chunk = min(remaining, CHUNK)

            encrypted_data = await reader.read(chunk)

            if len(encrypted_data) != chunk:
                raise ConnectionError

            data = self.encryptor.decrypt_message(encrypted_data, iv)

            file.write(data)

            remaining -= chunk

    async def create_connection(self, connection_event: Optional[asyncio.Event] = None):
        reader, writer = await asyncio.open_connection(*self.address)
        self.reader = reader
        self.writer = writer

        # handshaking

        if connection_event:
            connection_event.set()
        try:
            await self._process_incoming_events()
        except ConnectionError:
            # self.events['disconnect']()
            pass
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

            data = self.encryptor.decrypt_message(encrypted_data, iv)

            data_len = int.from_bytes(data, 'big')

            encrypted_data = await self.reader.read(data_len)

            if len(encrypted_data) != data_len:
                raise ConnectionError

            data = self.encryptor.decrypt_message(encrypted_data, iv)

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

                buffer = self.encryptor.decrypt_message(buffer, iv)

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

        iv = Encryptor.generate_iv()

        self.writer.write(iv)

        encrypted_data = self.encryptor.encrypt_message(data, iv)

        header = json.dumps({'event': event, 'data_length': len(encrypted_data)}).encode()

        encrypted_header = self.encryptor.encrypt_message(header, iv)

        encrypted_len = self.encryptor.encrypt_message(len(encrypted_header).to_bytes(8, 'big'), iv)

        self.writer.write(encrypted_len)

        self.writer.write(encrypted_header)

        self.writer.write(encrypted_data)

        await self.writer.drain()


client = Client('NitroClient', ('127.0.0.1', 8080))


@client.event()
async def message(data):
    print(data)


async def main():

    logging.basicConfig(level=logging.INFO)

    view_event = asyncio.Event()

    @client.event()
    async def view(data):
        print(data.decode(encoding='utf-8'))
        view_event.set()

    @client.event()
    async def edit(data):
        print(data.decode(encoding='utf-8'))

    @client.event(data_mode=DataMode.FILE)
    async def file_edit(file: IO):
        pass

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
                    await client.send('view', b'New Text Document.txt')
                    print("waiting for server response...")
                    await view_event.wait()
                    await asyncio.get_running_loop().run_in_executor(pool, input, 'Enter Any Key..')

                if result == 2:
                    # file_name = await asyncio.get_running_loop().run_in_executor(pool, input, 'Enter file name')

                    file_name = 'New Text Document 1.txt'

                    s = 'Hello, World!!'

                    await client.send('edit', ''.join([file_name, s]).encode())

        except ConnectionError:
            pass
        except Exception as e:
            logging.error(e)

asyncio.run(main())
