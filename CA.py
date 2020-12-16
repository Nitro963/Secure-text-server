import logging
import datetime

from Crypto.PublicKey import RSA

from server import Server, DataMode
from pathlib import Path
import json
import os
from OpenSSL import crypto
import asyncio

ca = Server('CA', ('localhost', 6666))

logging.basicConfig(level=logging.INFO)


@ca.event()
async def issue_cs(sid, data):
    req = crypto.load_certificate_request(crypto.FILETYPE_PEM, data)

    check_csr = f'server_keys/CA/{req.get_subject().CN}_public.pem'
    if os.path.exists(check_csr):
        crypto_public_key = crypto.load_publickey(crypto.FILETYPE_PEM, open(check_csr,'rb').read())
        if req.verify(crypto_public_key):
            cs = crypto.X509()
            ca_private_key = ca.private_key.exportKey()
            crypto_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_private_key)

            issue_date = datetime.datetime.now()

            cs.set_notBefore(issue_date.strftime("%Y%m%d%H%M%SZ").encode("ascii"))

            issue_date_end = issue_date + datetime.timedelta(days=30)

            cs.set_notAfter(issue_date_end.strftime("%Y%m%d%H%M%SZ").encode("ascii"))

            cs.set_subject(req.get_subject())

            cs.set_pubkey(crypto_public_key)
            cs.sign(crypto_private_key, "sha1")
            with open(f'CS/CA/{cs.get_subject().CN}_Cs.cs', 'wb+') as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cs))
            print(f"sending cs to {sid}")
            await ca.send(sid, 'recv_cs', crypto.dump_certificate(crypto.FILETYPE_PEM, cs))
        else:
            # close connection
            await ca.terminate_connection(sid)
    else:
        await ca.terminate_connection(sid)


@ca.event()
async def verify_cs(sid, data):
    cs = crypto.load_certificate(crypto.FILETYPE_PEM, data)

    other_name = cs.get_subject().CN

    cs_file = f'CS/CA/{other_name}_Cs.cs'
    bool_res = False
    if os.path.exists(cs_file):
        cs_from_file = crypto.load_certificate(crypto.FILETYPE_PEM, open(cs_file, "rb").read())

        if cs_from_file.get_subject() == cs.get_subject():
            if cs_from_file.get_pubkey().__eq__(cs.get_pubkey()):
                # the CS is verified
                bool_res = True
        else:
            # the CS is invalid
            bool_res = False
    else:
        # first time to see this CS
        bool_res = False

    await ca.send(sid, 'cs_verification', bool_res.to_bytes(4, 'big'))


async def main():
    abstract_server = await asyncio.start_server(
        ca.on_connection_made, ca.address[0], ca.address[1])

    print(f'Serving on {ca.address}')

    async with abstract_server:
        await abstract_server.serve_forever()


asyncio.run(main())
