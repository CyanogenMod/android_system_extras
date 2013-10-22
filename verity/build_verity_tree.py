#! /usr/bin/env python

import os
import sys
import math
import hashlib
import binascii

HASH_FUNCTION = "SHA256"
HASH_FUNCTION_SIZE = 32
BLOCK_SIZE = 4096
HASHES_PER_BLOCK = BLOCK_SIZE / HASH_FUNCTION_SIZE

def generate_salt():
    return os.urandom(HASH_FUNCTION_SIZE)

def get_hash_image_blocks(data_image_size):
    data_image_blocks = data_image_size / BLOCK_SIZE
    return data_image_blocks / (HASH_FUNCTION_SIZE * 2)

def get_hash_image_size(data_image_size):
    return get_hash_image_blocks(data_image_size) * BLOCK_SIZE

def blockify(data):
    blocks = []
    for i in range(0, len(data), BLOCK_SIZE):
        chunk = data[i:i+BLOCK_SIZE]
        blocks.append(chunk)
    return blocks

def read_blocks(image_path):
    image = open(image_path, "rb").read()
    return blockify(image)

def hash_block(data, salt):
    hasher = hashlib.new(HASH_FUNCTION)
    hasher.update(salt)
    hasher.update(data)
    return hasher.digest()

def block_align(level):
    pad_size = (BLOCK_SIZE - (len(level) % BLOCK_SIZE)) % BLOCK_SIZE
    pad = '\x00' * pad_size
    return level + pad

def generate_hashes(data_blocks, salt):
    levels = []
    root_hash = ''
    while True:
        hashes = [hash_block(b, salt) for b in data_blocks]
        if len(hashes) == 1:
            root_hash = hashes[0]
            break
        else:
            level = ''.join(hashes)
            level = block_align(level)
            levels.insert(0, level)
            data_blocks = blockify(level)
    return root_hash, ''.join(levels)

def write_hashes(hashes, hash_image, hash_image_size):
    hashes = hashes.ljust(hash_image_size, '\x00')
    with open(hash_image, 'wb+') as hash_file:
        hash_file.write(hashes)

def generate_hash_image(data_image, hash_image, hash_image_size, salt):
    blocks = read_blocks(data_image)
    root_hash, hashes = generate_hashes(blocks, salt)
    write_hashes(hashes, hash_image, hash_image_size)
    return root_hash

def build_verity_tree(data_image, hash_image, data_image_size):
    salt = generate_salt()
    hash_image_size = get_hash_image_size(data_image_size)
    root_hash = generate_hash_image(data_image, hash_image, hash_image_size, salt)
    print binascii.hexlify(root_hash), binascii.hexlify(salt)

if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "-s":
        print get_hash_image_size(int(sys.argv[2]))
    elif len(sys.argv) == 4:
        data_image = sys.argv[1]
        hash_image = sys.argv[2]
        data_image_size = int(sys.argv[3])
        build_verity_tree(data_image, hash_image, data_image_size)
    else:
        exit(-1)
