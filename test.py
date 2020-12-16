import datetime

from OpenSSL import crypto

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
opensslPrivateKey = crypto.load_privatekey(crypto.FILETYPE_PEM, open(f'server_keys/Nitro_private.pem').read())

req.set_pubkey(opensslPublicKey)

req.sign(opensslPrivateKey, "sha1")

with open('temp.csr','wb') as f:
     f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

req = crypto.load_certificate_request(crypto.FILETYPE_PEM,crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

cs = crypto.X509()
cs.set_subject(req.get_subject())
cs.set_pubkey(req.get_pubkey())
opensslPrivateKey = crypto.load_privatekey(crypto.FILETYPE_PEM, open(f'server_keys/CA_private.pem').read())
cs.sign(opensslPrivateKey, "sha1")
issue_date = datetime.datetime.now()

cs.set_notBefore(issue_date.strftime("%Y%m%d%H%M%SZ").encode("ascii"))

issue_date_end = issue_date + datetime.timedelta(days=365)

cs.set_notAfter(issue_date_end.strftime("%Y%m%d%H%M%SZ").encode("ascii"))

req = crypto.load_certificate(crypto.FILETYPE_PEM, crypto.dump_certificate(crypto.FILETYPE_PEM, cs))
#
# print(req)
