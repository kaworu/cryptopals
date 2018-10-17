#!/usr/bin/env python
#
# Set 4 / Challenge 31 & 32:
# Implement and break HMAC-SHA1 with an artificial timing leak

import time, os, argparse
import binascii, hashlib, hmac
import bottle

# short-cutting, byte-at-a-time, artificially delayed comparison function.
def insecure_compare(known, unknown):
    if len(known) != len(unknown):
        return False
    for i in range(len(known)):
        if known[i] != unknown[i]:
            return False
        time.sleep(config.delay / 1000.0)
    return True

# HTTP route to test a given file against its HMAC-SHA1 signature (in hex).
# Example:
#     http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
@bottle.route('/test')
def test():
    # retrieve the file and signature parameters from the query.
    try:
        filepath  = bottle.request.query['file']
        signature = bottle.request.query['signature']
    except KeyError:
        bottle.abort(400) # Bad Request
    # read the requested file.
    try:
        fh = open(filepath, "r")
    except IOError:
        bottle.abort(404) # Not Found
    content = fh.read()
    fh.close()
    # verify the given signature.
    known_signature = hmac.new(config.key, content, hashlib.sha1).hexdigest()
    match = insecure_compare(known_signature.upper(), signature.upper())
    # OK if the signature is good, Internal Server Error otherwise.
    status = 200 if match else 500
    return bottle.HTTPResponse(status=status, body=known_signature)

# script arguments handling.
parser = argparse.ArgumentParser(description="Run a timing-leaking HMAC-SHA1 HTTP server")
opt = parser.add_argument
opt("-H", "--hostname",  required=True, help="server hostname")
opt("-p", "--port",      required=True, help="server port", type=int)
opt("-k", "--key",       required=True, help="HMAC key given as hexadecimal string")
opt("-d", "--delay",     required=True, help="artificial delay in milliseconds", type=float)
config = parser.parse_args()
config.key = binascii.unhexlify(config.key)

# launch the server.
bottle.run(host=config.hostname, port=config.port)
