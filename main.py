#!/usr/bin/python3
import base64
import codecs
import random
import sys
import operator
import os
from Crypto.Cipher import AES

aes_block_size = 16

# this function seems useless since bytearray.fromhex() exists
def hex_str_to_bytearray(s):
    ba = bytearray()
    len_str = len(s)
    if s[0:2] == "0x":
        len_str -= 2
    nb_bytes = (len_str // 2)
    if len_str % 2 != 0:
        nb_bytes += 1
    bInt = int(s, 16)
    ba.extend(bInt.to_bytes(nb_bytes, byteorder='big'))
    return ba


def hex_str_to_b64_str(hex_str):
    decoded_str = codecs.decode(hex_str, 'hex')
    b64 = codecs.encode(decoded_str, 'base64')

    return codecs.decode(b64).rstrip()


def rate_alpha_num_space(ba):
    nb_alpha_num_space = 0
    len_ba = len(ba)

    for i in ba:
        if (i == 0x20 or (ord('a') <= i <= ord('z'))
                 or (ord('A') <= i <= ord('Z'))):
            nb_alpha_num_space += 1

    return nb_alpha_num_space / len_ba


def is_plain_text(ba, rate=0.90):
    if (rate_alpha_num_space(ba) >= rate):
        return True
    return False


def xor_buffer(b1, b2):
    if len(b1) != len(b2):
        raise ValueError("bytearrays are not the same length")
    b3 = bytearray(len(b1))
    for i in range(0, len(b1)):
        b3[i] = b2[i] ^ b1[i]
    return b3


def xor_key(data_in, key):
    """
    Return xored data.

    Args:
        data_in bytearray: data to decode
        key bytearray: key used to decode
    Returns:
        bytearray: data_in ^ key
    """
    key_len = len(key)
    dataOut = bytearray(len(data_in))
    for i in range(0, len(data_in)):
        dataOut[i] = data_in[i] ^ key[i % key_len]
    return dataOut


def count_byte_occurrence(ba):
    """
    Return sorted list of tuple.

    Args:
        ba bytearray: Ciphered text
    Returns:
        list: a sorted list of 256 tuples (char, %presence)
    """
    tab = [0] * 256
    strlen = len(ba)

    for i in ba:
        tab[i] = tab[i] + (1 / strlen)

    sortedBytes = list(zip(range(0, 256), tab))
    sortedBytes.sort(key=operator.itemgetter(1))

    return sortedBytes


def display_char_occurrences(sortedOcc):
    for i in reversed(sortedOcc):
        if i[1] == 0:
            break
        print(hex(i[0]), ":", i[1])


def hamming_distance(a, b):
    """
    Return the hamming distance of patterns a and b.
    a and b must have the same length.

    Args:
        a bytearray: first pattern
        b bytearray: second pattern
    Returns:
        int: the hamming distance of a and b or -1 if it can't
        be computed
    """
    if (len(a) != len(b) or len(a) == 0):
        return -1
    p1_xor_p2 = xor_buffer(a, b)
    int_p1_xor_p2 = int.from_bytes(p1_xor_p2, byteorder='big', signed=False)
    result = bin(int_p1_xor_p2).count("1")
    return result


def read_b64_file(path):
    """
    Read file which encodes data in b64 on several lines.

    Args:
        path string: path to file
    Returns:
        bytearray: data decoded from message in the given file
    """
    try:
        file = open(path, 'r')
    except (OSError, IOError) as e:
        print("Can't open file " + path + "(" + e.errno + ")" + ".")
        return None
    string_file = str()
    for line in file:
        lineWithoutReturn = line.rstrip()
        string_file += lineWithoutReturn
    res = base64.b64decode(string_file)
    file.close()
    return res


def split_bytearray(ba, nb_ba):
    """
    Split a bytearray into several bytearrays.
    The bytes are split in round robin between the output bytearrays.

    Args:
      ba bytearray: bytearray to split
      nb_ba int: number of bytearray
    Returns:
      list: list of nb_ba bytearray with all original bytes
    """
    tab = list()
    len_ba = len(ba)

    # create sub bytearray with appropriate len
    rest = len_ba % nb_ba
    for i in range(0, nb_ba):
        len_sub_ba = len_ba // nb_ba
        if rest - i > 0:
            len_sub_ba += 1
        tab.append(bytearray(len_sub_ba))

    # dispatch bytes
    for i in range(0, len(ba)):
        ba_index = i % nb_ba
        tab[ba_index][i // nb_ba] = (ba[i])

    return tab


def guess_key_len_HD(ba, max_len):
    hamming_distances = [0] * max_len

    for i in range(1, max_len + 1):
        nb_hd = 20
        for j in range(0, nb_hd):
            ba1 = ba[(2 * j) * i:(2 * j + 1) * i]
            ba2 = ba[(2 * j + 1) * i:(2 * j + 2) * i]
            hamming_distances[i - 1] += hamming_distance(ba1, ba2) / i
        hamming_distances[i - 1] = hamming_distances[i - 1] / nb_hd

    sorted_HD = list(zip(range(1, max_len + 1), hamming_distances))
    sorted_HD.sort(key=operator.itemgetter(1))
    return(sorted_HD[0][0])


def decrypt_xor_text(cipher_text):
    secret_key = bytearray()

    key_len = guess_key_len_HD(cipher_text, 42)
    print("best key length using hamming distance method:", key_len)
    subtext = split_bytearray(cipher_text, key_len)

    print("display of the most common bytes of each sets")
    byte_occ_list = list()
    for i in subtext:
        byte_occ_list.append(count_byte_occurrence(i)[250:256])
    for index, i in enumerate(byte_occ_list):
        print("###", index)
        display_char_occurrences(i)

    for i in byte_occ_list:
        most_present_byte = i[-1][0]
        char_key = most_present_byte ^ 0x20
        secret_key.append(char_key)
        print("xoring " + hex(most_present_byte) + " and 0x20: ",
              chr(char_key), hex(char_key))

    print("The secrekt key is: " + 'secret_key.decode("ascii")')
    print("The plain text is:")
    plain_text = xor_key(cipher_text, secret_key)
    print(plain_text.decode("utf-8"))
    return plain_text


def pattern_inventory(ba, block_len):
    """
    Return the set of all the pattern of size block_len
    in input ba
    The size of ba must be a multiple of block_len
    Args:
      ba bytearray: bytearray where patterns are inventoried
      block_len: size of the patterns
    Returns:
      set: set of all patterns presents in ba
    """
    if len(ba) % block_len != 0:
        return None
    result = set()
    for i in range(0, len(ba), block_len):
        pattern = ba[i:i + block_len]
        result.add(int.from_bytes(pattern, byteorder='big', signed=False))
    return result


def padding_block(block_to_fill, block_len):
    """
    Return a padded block of data with PKCS#7
    Args:
      block_to_fill bytearray: bytearray to complete
      block_len int: size of block
    Returns:
      bytearray: completed block following PCKS#7 convention
    """
    len_block_to_fill = len(block_to_fill)
    if len_block_to_fill == block_len:
        return block_to_fill
    elif len_block_to_fill > block_len:
        return None
    block = bytearray(block_len)
    for i in range(0, len_block_to_fill):
        block[i] = block_to_fill[i]
    pattern_and_number = block_len - len_block_to_fill
    for i in range(len_block_to_fill, len_block_to_fill + pattern_and_number):
        block[i] = pattern_and_number
    return block

def aes_encrypt_ecb(plain_text, key):
    obj = AES.new(bytes(key), AES.MODE_ECB)

    cipher_text = bytearray()
    chunks_plain_text = split_bytearray_to_blocks(plain_text, aes_block_size)

    for chunk in chunks_plain_text:
        aes_ciphered_chunk = obj.encrypt(bytes(chunk))
        cipher_text.extend(aes_ciphered_chunk)

    return cipher_text

def aes_decrypt_ecb(ba, key):
    obj = AES.new(bytes(key), AES.MODE_ECB)
    decrypted_text = obj.decrypt(bytes(ba))
    return decrypted_text

def split_bytearray_to_blocks(ba, block_size):
    """
    Split a bytearray into several bytearrays.
    The bytes are split in round robin between the output bytearrays.

    Args:
      ba bytearray: bytearray to split
      block_size int: size of outputs
    Returns:
      list: list of bytearrays of size blocksize
    """
    tab = list()
    len_ba = len(ba)
    start_index = 0
    end_index = block_size
    while(end_index < len_ba):
        tab.append(ba[start_index:end_index])
        start_index = end_index
        end_index += block_size

    if start_index < len_ba:
        last_chunk = padding_block(ba[start_index:len_ba] ,aes_block_size)
        tab.append(last_chunk)

    return tab

def aes_encrypt_cbc(key, plain_text, initialization_vector):
    if len(initialization_vector) != aes_block_size:
        raise ValueError("Initialization vector wrong size")
    cipher_text = bytearray()
    chunks_plain_text = split_bytearray_to_blocks(plain_text, aes_block_size)
    previous_result = initialization_vector

    for chunk in chunks_plain_text:
        xor_chunk_chunk = xor_buffer(previous_result, chunk)
        aes_ciphered_chunk = aes_encrypt_ecb(xor_chunk_chunk, key)
        previous_result = aes_ciphered_chunk
        cipher_text.extend(aes_ciphered_chunk)

    return cipher_text

def aes_decrypt_cbc(key, cipher_text, initialization_vector):
    if len(initialization_vector) != aes_block_size:
        raise ValueError("Initialization vector wrong size")
    plain_text = bytearray()
    chunks_cipher_text = split_bytearray_to_blocks(cipher_text, aes_block_size)
    previous_result = initialization_vector

    for chunk in chunks_cipher_text:
        aes_deciphered_chunk = aes_decrypt_ecb(chunk, key)
        plain_chunk = xor_buffer(previous_result, aes_deciphered_chunk)
        previous_result = chunk
        plain_text.extend(plain_chunk)

    return plain_text

def generate_random_aes_key():
    """
    Generate a random 128 bits AES key
    """
    random_key = bytearray()
    random_key.extend(os.urandom(16))
    return random_key

def random_padding(plain_text):
    """
    Append and prepend 5-10 random bytes to the plain_text
    """
    rdm_buffer_size_prepended = random.randint(5,10)
    rdm_buffer_size_appended = random.randint(5,10)

    extended_plain_text = bytearray()
    extended_plain_text.extend(os.urandom(rdm_buffer_size_prepended))
    extended_plain_text.extend(plain_text)
    extended_plain_text.extend(os.urandom(rdm_buffer_size_appended))

    return extended_plain_text

def encrypt_cbc_aes_rdm_key_rdm_IV(plain_text):
    """
    Encrypt input data(bytearray) with both random IV and key
    Append and prepend 5-10 random bytes to the plain_text
    """
    init_vector = generate_random_aes_key()
    key = generate_random_aes_key()
    extended_plain_text = random_padding(plain_text)
  
    return aes_encrypt_cbc(key, extended_plain_text, init_vector)

def encrypt_ecb_aes_rdm_key(plain_text):
    key = generate_random_aes_key()
    extended_plain_text = random_padding(plain_text)

    return aes_encrypt_ecb(extended_plain_text, key)

def rdm_encrypt_aes_cbc_or_ecb(plain_text):
    aes_ecb_or_aes_cbc = random.randint(0,1)
    if aes_ecb_or_aes_cbc == 0:
        return encrypt_ecb_aes_rdm_key(plain_text), 0
    elif aes_ecb_or_aes_cbc == 1:
        return encrypt_cbc_aes_rdm_key_rdm_IV(plain_text), 1
    else:
        raise Exception("This should not happen")

def oracle_aes_ecb_or_aes_cbc(cipher_text):
    """
    return 0 if the aes cipher text is ecb and 1 if cbc
    """
    second_cipher_block = cipher_text[16:32]
    third_cipher_block = cipher_text[32:48]
    if second_cipher_block == third_cipher_block:
        return 0
    return 1


if __name__ == "__main__":
    pass