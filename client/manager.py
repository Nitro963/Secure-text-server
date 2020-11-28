import asyncio
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Encryptor import Encryptor

class Client(Encryptor):
    def __init__(self, writer, reader):
        self.reader = reader
        self.writer = writer
        self.iv = ''

    async def send_iv(self, iv: str):
        data = json.dumps({'event': 'iv', 'data_length': len(iv)}).encode()
        self.writer.write(len(data).to_bytes(8, 'big'))
        self.writer.write(data)
        await self.writer.drain()
        self.writer.write(iv)
        await self.writer.drain()

    async def send_event(self, event: str, message: str):
        # GENERATE AND SEND IV FOR EACH MESSAGE
        iv = Random.new().read(AES.block_size)
        await self.send_iv(iv)
        # ENCRYPTION
        ciphertext = self.encrypt_message(message,iv)

        data = json.dumps({'event': event, 'data_length': len(ciphertext)}).encode()
        self.writer.write(len(data).to_bytes(8, 'big'))
        self.writer.write(data)
        await self.writer.drain()
        self.writer.write(ciphertext)
        await self.writer.drain()
        print('sent!')

    async def send_message(self, message):
        data = json.dumps({'event': 'message', 'data_length': len(message)}).encode()
        self.writer.write(len(data).to_bytes(8, 'big'))
        self.writer.write(data)
        await self.writer.drain()
        self.writer.write(message)
        await self.writer.drain()
        print('sent!')

    async def receive_message(self):
        iv = await self.reader.read(16)
        data = await self.reader.read(84)
        # DECRYPTION
        return self.decrypt_message(data,iv)

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()
        print('closed!')


async def start_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', 8888)
    client = Client(writer, reader)
    await client.send_event('message', 'Hello, World!'.encode('UTF-8'))
    await client.close()


async def request(host: str, port: int, name: str, action: str):
    reader, writer = await asyncio.open_connection(host, port)
    client = Client(writer, reader)
    await client.send_event(action, bytes(name, encoding='utf-8'))
    await client.close()
