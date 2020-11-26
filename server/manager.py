import asyncio
import logging
import functools
import json

CHUNK = 1024

BUFFER_SIZE = 256 * 1024 * 1024


class Socket:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.writer = writer
        self.reader = reader
        self.sid = self.writer.get_extra_info('peername')

    async def send(self, data: bytes):
        self.writer.write(data)

        await self.writer.drain()


class Server:
    def __init__(self, name, address):
        self.name = name
        self.address = address
        self.clients = {}
        self.events = {}

        @self.event
        async def connect(sid):
            logging.info(f'{sid} jumped into {self.name} server.')

        @self.event
        async def disconnect(sid):
            logging.info(f'{sid} left {self.name} server.')

        @self.event
        async def pong(sid):
            logging.info(f'Pong! from {sid}')

        @self.event
        async def message(sid, data):
            logging.info(f'{sid} say\'s {data}')

    def event(self, func, name=None):
        name = name if name is not None else func.__name__

        logging.info(f"Registering event {name!r}")

        @functools.wraps(func)
        async def wrapper(sid, data_len):

            buffer = await self._read_bytes(self.clients[sid].reader, data_len)

            reserved_events = {
                'connect': lambda: func(sid),
                'disconnect': lambda: func(sid),
                'pong': lambda: func(sid),
                'message': lambda: func(sid, buffer.decode(encoding='utf-8')),
            }

            await reserved_events.get(name, lambda: func(sid, buffer))()

        self.events[name] = wrapper

    @staticmethod
    async def _read_bytes(reader, data_len):
        buffer = bytearray(BUFFER_SIZE)

        remaining = data_len
        i = 0

        while remaining > 0:
            chunk = min(remaining, CHUNK)

            buffer[i:i + chunk] = await reader.read(chunk)

            i += chunk

            remaining -= chunk

        return buffer[:data_len]

    async def on_connection_made(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        sio = Socket(reader, writer)

        self.clients[sio.sid] = sio

        await self.events['connect'](sio.sid, 0)

        while True:

            data = await reader.read(8)

            if not data:
                asyncio.ensure_future(self.events['disconnect'](sio.sid, 0))
                del self.clients[sio.sid]
                break

            # decrypt data

            data_len = int.from_bytes(data, 'big')

            data = await self._read_bytes(reader, data_len)

            # decrypt data

            data = json.loads(data)

            await self.events[data['event']](sio.sid, data['data_length'])


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
