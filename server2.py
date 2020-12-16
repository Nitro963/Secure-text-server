from server import start_server
import asyncio
import argparse

parser = argparse.ArgumentParser()

parser.add_argument("name",
                    type=str)

parser.add_argument("host",
                    type=str)

parser.add_argument("port",
                    type=int)

args = parser.parse_args()

asyncio.run(start_server(args.name, args.host, args.port))
