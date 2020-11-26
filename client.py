import asyncio
import json


async def tcp_echo_client():
    reader, writer = await asyncio.open_connection(
        '127.0.0.1', 8888)

    message = b'Hello, World'

    data = json.dumps({'event': 'message', 'data_length': len(message)}).encode()

    writer.write(len(data).to_bytes(8, 'big'))

    writer.write(data)

    await writer.drain()

    writer.write(message)

    await writer.drain()

    print('Close the connection')
    writer.close()
    await writer.wait_closed()


asyncio.run(tcp_echo_client())
