#!/usr/bin/python3
import base64
import codecs
import sys
import operator
import os


def hex_str_to_bytearray(s):
    ba = bytearray()
    nb_bytes = (len(s) // 2) - 2 + 1
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
        if i == (0x20 or (ord('a') <= i <= ord('z'))
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
        data_in bytearay: data to decode
        key bytearray: key used to decode
    Returns:
        bytearray: data_in ^ key
    """
    key_len = len(key)
    dataOut = bytearray(len(data_in))
    for i in range(0, len(data_in)):
        dataOut[i] = data_in[i] ^ key[i % key_len]
    return dataOut


def count_byte_occurence(ba):
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


def display_char_occurences(sortedOcc):
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

    # create sub bytearray with appropirate len
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
        byte_occ_list.append(count_byte_occurence(i)[250:256])
    for index, i in enumerate(byte_occ_list):
        print("###", index)
        display_char_occurences(i)

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


if __name__ == "__main__":
    pass
