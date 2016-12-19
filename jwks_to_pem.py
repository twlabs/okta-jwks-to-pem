#! /usr/bin/env nix-shell
#! nix-shell -i python -p python27Packages.requests2 -p python27Packages.cryptography

import argparse
import base64
import os
import struct

import redis
import requests
import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers


def intarr2long(arr):
    return int(''.join(['%02x' % byte for byte in arr]), 16)


def base64_to_long(data):
    if isinstance(data, six.text_type):
        data = data.encode('ascii')

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return intarr2long(struct.unpack('%sB' % len(_d), _d))


def jwks_to_pem_keys(json_web_keys):
    pem_keys = []
    for jwk in json_web_keys['keys']:
        exponent = base64_to_long(jwk['e'])
        modulus = base64_to_long(jwk['n'])
        numbers = RSAPublicNumbers(exponent, modulus)
        public_key = numbers.public_key(backend=default_backend())
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pem_keys.append(pem)
    return pem_keys


def show_pems_in_console(json_web_keys, pem_keys):
    for jwk, pem in zip(json_web_keys['keys'], pem_keys):
        print("PEM for KID '{}'".format(jwk['kid']))
        print(pem)


def store_pems_in_redis(json_web_keys, pem_keys):
    r = redis.from_url(os.environ.get('redis_url'))
    for jwk, pem in zip(json_web_keys['keys'], pem_keys):
        r.hset('okta_public_keys', jwk['kid'], pem)
    print('Public keys were stored in redis successfully')


def output_pem_keys(json_web_keys, pem_keys):
    if args.output == 'redis':
        store_pems_in_redis(json_web_keys, pem_keys)
    else:
        show_pems_in_console(json_web_keys, pem_keys)


arg_parser = argparse.ArgumentParser(
    description='JWK to PEM conversion tool')
arg_parser.add_argument('--org',
                        dest='org',
                        help='Domain for Okta org',
                        required=True)
arg_parser.add_argument('--output',
                        dest='output',
                        help='Public keys destination. Default option is console.'
                             'It is needed an env variable redis_url '
                             'to store the pem keys in redis',
                        choices=['console', 'redis'],
                        required=False)
args = arg_parser.parse_args()

print('Fetching JWKS from {}'.format(args.org))

jwks = requests.get('https://{}/oauth2/v1/keys'.format(args.org)).json()
pems = jwks_to_pem_keys(jwks)
output_pem_keys(jwks, pems)
