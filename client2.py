from client import main
import asyncio
import argparse

parser = argparse.ArgumentParser()

parser.add_argument("name",
                    type=str)


parser.add_argument("remote_host",
                    type=str)

parser.add_argument("remote_port",
                    type=int)

args = parser.parse_args()

asyncio.run(main(args))
