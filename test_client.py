import asyncio
from client.manager import start_client, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto import Random


if __name__ == '__main__':
    #asyncio.run(start_client())




    asyncio.run(request('127.0.0.1', 8888, 'hello baby', 'message'))

