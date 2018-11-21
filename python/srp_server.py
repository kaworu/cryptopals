#!/usr/bin/env python

# Set 5 / Challenge 37:
# Break SRP with a zero key:
#    Get your SRP working in an actual client-server setting.

import random, os, argparse
import binascii, hashlib, hmac
import socket

# SRP parameters
N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3


# helper functions

def hex_to_int(s):
    return int(s, 16)

def int_to_hex(i):
    return b"%x" % i

def bytes_to_hex(buf):
    return binascii.hexlify(buf)

def hex_to_bytes(s):
    # NOTE: binascii.unhexlify() expect an even count of byte.
    if len(s) % 2 == 1:
        s = b"0" + s
    return binascii.unhexlify(s)

def bytes_to_int(buf):
    s = bytes_to_hex(buf)
    return hex_to_int(s)

def int_to_bytes(i):
    s = int_to_hex(i)
    return hex_to_bytes(s)

def sha256(s):
    m = hashlib.sha256()
    m.update(s)
    return m.digest()

def hmac_sha256(key, content):
    m = hmac.new(key, content, hashlib.sha256)
    return m.digest()


# SRP Protocol implementation using receive() and send() to talk with the
# client.
#
# We've Agreed on N=[NIST Prime], g=2, k=3, I (email), P (password)
def srp(receive, send, I, P):
    # 32 bytes long salt, inspired by the test vectors from SRP for TLS
    # Authentication (see https://tools.ietf.org/html/rfc5054#appendix-B).
    salt = os.urandom(32) # Generate salt as random integer
    xH = sha256(salt + P) # Generate string xH=SHA256(salt|password)
    x = bytes_to_int(xH)  # Convert xH to integer x somehow
    v = pow(g, x, N)      # Generate v=g**x % N
    xH, x = None, None    # Save everything but x, xH

    # C->S: Send I, A=g**a % N (a la Diffie Hellman)
    ident, A = receive().decode().split(",")
    # XXX: not a timing-safe comparison.
    if ident != I: return
    A = hex_to_int(A)

    # S->C: Send salt, B=kv + g**b % N
    # XXX: the random module is not cryptographically secure.
    # The secret module require Python >= 3.6
    b = random.randint(1, N - 1)
    B = (k * v + pow(g, b, N)) % N
    send(bytes_to_hex(salt) + b"," + int_to_hex(B))

    # Compute string uH = SHA256(A|B), u = integer of uH
    uH = sha256(int_to_bytes(A) + int_to_bytes(B))
    u = bytes_to_int(uH)

    # Generate S = (A * v\*\*u) \*\* b % N
    # Generate K = SHA256(S)
    S = pow(A * pow(v, u, N), b, N)
    K = sha256(int_to_bytes(S))

    # C->S: Send HMAC-SHA256(K, salt)
    token = hex_to_bytes(receive())

    # Send "OK" if HMAC-SHA256(K, salt) validates
    known_token = hmac_sha256(K, salt)
    # NOTE: timing safe comparison even though the client can only try once.
    if hmac.compare_digest(known_token, token):
        send(b"OK")
    else:
        send(b"NO")


# script arguments handling.
parser = argparse.ArgumentParser(description="Run a Secure Remote Password protocol server")
opt = parser.add_argument
opt("-H", "--hostname",  required=True, help="server hostname")
opt("-p", "--port",      required=True, help="server port", type=int)
opt("-I", "--id",        required=True, help="client identifier")
opt("-P", "--password",  required=True, help="expected client password")
config = parser.parse_args()


# Socket stuff
server = socket.socket()
# see https://stackoverflow.com/a/27360648
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((config.hostname, config.port))
try:
    server.listen(0)
    print("===> listening", (config.hostname, config.port))
    while True:
        client, addr = server.accept()
        print("===> connection", addr)
        try:
            send = lambda msg: client.sendall(msg)
            receive = lambda: client.recv(4096).rstrip(b"\n")
            srp(receive, send, config.id, config.password.encode())
        finally:
            client.close()
            client = None
            print("===> closed", addr)
finally:
    server.close()
    server = None
