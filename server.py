import asyncio
import logging
import functools
import json
import tempfile
from pathlib import Path

from typing import Dict, Tuple, Callable, Coroutine, Optional
from typing.io import IO
from enum import Enum, auto
from Crypto.PublicKey import RSA
from hashlib import sha512
from OpenSSL import crypto
from Encryptor import SymmetricEncryptor, AsymmetricEncryptor
from client import Client

TYPE_RSA = crypto.TYPE_RSA

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
        self.certData = {}
        self.csr = crypto.X509Req()
        self.cs = crypto.X509Req()
        self.generate_csr()

        @self.event()
        async def connect(sid: Tuple[str, int]):
            print(f'{sid} jumped into {self.name} server.')

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

            print(f"Registering event {event_name!r}")

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

    def generate_csr(self):
        csrfile = 'incommon.csr'
        req = crypto.X509Req()
        # Return an X509Name object representing the subject of the certificate.
        req.get_subject().CN = 'CA'
        req.get_subject().countryName = 'SY'
        req.get_subject().stateOrProvinceName = 'Damascus'
        req.get_subject().localityName = 'Southern Syria'
        req.get_subject().organizationName = 'AI inc.'
        req.get_subject().organizationalUnitName = 'Information Security'

        # # Set the public key of the certificate to pkey.
        opensslPublicKey = crypto.load_publickey(crypto.FILETYPE_PEM,
                                                 open(f'server_keys/Nitro_public.pem').read())
        req.set_pubkey(opensslPublicKey)

        self.certData['CN']=self.name
        self.certData['countryName'] = 'SY'
        self.certData['stateOrProvinceName'] = 'Damascus'
        self.certData['localityName'] = 'Southern Syria'
        self.certData['organizationName'] = 'AI inc.'
        self.certData['organizationalUnitName'] = 'Information Security'

    async def write_to_file(self, sid: Tuple[str, int], file: IO,
                            reader: asyncio.StreamReader, data_len: int, iv: bytes):
        remaining = data_len
        file_hash = sha512()
        while remaining > 0:
            chunk = min(remaining, CHUNK)

            encrypted_data = await reader.read(chunk)

            if len(encrypted_data) != chunk:
                raise ConnectionError

            data = self.encryptors[sid].decrypt(encrypted_data, iv)

            file.write(data)

            file_hash.update(data)

            remaining -= chunk

        return file_hash.digest()

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

        if self.name != 'CA':
            #sending CS
            cs_file = f'CS/{self.name}_cs.cs'

            await self.send_file(sid, 'recv_ca', Path(cs_file))

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
                hsh = 0
                if data_mode == DataMode.BYTES:
                    buffer = await reader.read(data_len)

                    if len(buffer) != data_len:
                        raise ConnectionError

                    buffer = self.encryptors[sid].decrypt(buffer, iv)

                    hsh = sha512(buffer).digest()

                if data_mode == DataMode.FILE:
                    tmp_file = tempfile.TemporaryFile()
                    hsh = await self.write_to_file(sid, tmp_file, reader, data_len, iv)
                    tmp_file.seek(0)
                    buffer = tmp_file
                hsh = int.from_bytes(hsh, 'big')

                # receive and verify the signature
                signature = await reader.read(2048)

                signature = int.from_bytes(signature, 'big')

                client_pub_key = self.clients_public_keys[sid]

                hash_from_sign = pow(signature, client_pub_key.e, client_pub_key.n)

                if hsh != hash_from_sign:
                    # the file was modified from the last signed
                    print("something wrong with the signature")
                    pass
                else:
                    print("the signature is correct")

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

    async def send_file(self, to: Tuple[str, int], event: str, path: Path):
        _, writer = self.clients[to]

        iv = SymmetricEncryptor.generate_iv()

        writer.write(iv)

        data_size = path.stat().st_size

        padding_len = 16 - data_size % 16

        header = json.dumps({'event': event, 'data_length': data_size + padding_len}).encode()

        encrypted_header = self.encryptors[to].encrypt(header, iv)

        encrypted_len = self.encryptors[to].encrypt(len(encrypted_header).to_bytes(8, 'big'), iv)

        writer.write(encrypted_len)

        writer.write(encrypted_header)
        file_hash = sha512()
        with open(path, 'rb') as f:
            while True:
                data = f.read(1024)

                if not data:
                    break

                file_hash.update(data)

                writer.write(self.encryptors[to].encrypt(data, iv))

        # generate and send the signature
        hsh = int.from_bytes(file_hash.digest(), 'big')

        signature = pow(hsh, self.private_key.d, self.private_key.n)

        # here we must send the signature
        writer.write(signature.to_bytes(2048, 'big'))

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
            return
        except FileNotFoundError:
            await server.send(sid, 'file_edit', b'File not found')
            return

        await server.send(sid, 'file_edit', b'Editing done')

    client_ca = Client(name, ('localhost', 6666))

    cs_event = asyncio.Event()

    asyncio.ensure_future(client_ca.create_connection(cs_event))

    await cs_event.wait()

    cs_event.clear()

    @client_ca.event()
    async def recv_cs(data):
        cs_file = f'CS/{name}_cs.csr'

        print(str(data.decode()))

        server.cs = crypto.load_certificate(crypto.FILETYPE_PEM, str(data.decode()))

        with open(cs_file, 'wb+') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM,server.cs))
        cs_event.set()

    print("asdfas")
    data = json.dumps(server.certData).encode()
    print(type(data))
    await client_ca.send('issue_cs', data)
    print("issue done")
    await cs_event.wait()

    abstract_server = await asyncio.start_server(
        server.on_connection_made, server.address[0], server.address[1])

    logging.info(f'Serving on {server.address}')

    async with abstract_server:
        await abstract_server.serve_forever()
