import asyncio
import json


class Client:
    def __init__(self, writer, reader):
        self.reader = reader
        self.writer = writer

    async def send_message(self, message):
        data = json.dumps({'event': 'message', 'data_length': len(message)}).encode()
        self.writer.write(len(data).to_bytes(8, 'big'))
        self.writer.write(data)
        await self.writer.drain()
        self.writer.write(message)
        await self.writer.drain()
        print('sent!')

    async def receive_message(self):
        data = await self.reader.read(100)
        return data.decode()

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()
        print('closed!')


async def start_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', 8888)
    client = Client(writer, reader)
    await client.send_message('Hello, World!'.encode('UTF-8'))
    await client.close()


async def request(host: str, port: int, name: str, action: str):
    reader, writer = await asyncio.open_connection(host, port)
    client = Client(writer, reader)
    await client.send_message(name.encode('UTF-8'))
    await client.close()
