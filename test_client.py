import asyncio
from client.manager import start_client, request

if __name__ == '__main__':
    # asyncio.run(start_client())
    asyncio.run(request('127.0.0.1', 8888, 'text_file_name', 'view'))
