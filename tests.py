#!/usr/bin/python3
# pylint: disable-msg=w0614
import unittest
from main import *
import os


class MyTests(unittest.TestCase):

    def test_b64(self):
        print("Testing hex_str_to_b64_str()...")
        input_str = ("49276d206b696c6c696e6720796f757220627261696e206c696b6520"
                     "6120706f69736f6e6f7573206d757368726f6f6d")
        expected_str = ("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3Vz"
                        "IG11c2hyb29t")
        self.assertEqual(expected_str, hex_str_to_b64_str(input_str))

    def test_hex_str_to_bytearray(self):
        print("Testing hex_str_to_bytearray()...")
        cipher_text_str = ("0x1b37373331363f78151b7f2b783431333d78397828372d36"
                           "3c78373e783a393b3736")
        cipher_text = hex_str_to_bytearray(cipher_text_str)
        self.assertEqual(bytearray(b'\x1b77316?x\x15\x1b\x7f+x413=x9x(7-6<x7>x:9;76'), cipher_text)

    def test_xor_buffer(self):
        print("Testing XorBuffer()...")
        b1 = bytearray()
        b1int = 0x1c0111001f010100061a024b53535009181c
        b1.extend(b1int.to_bytes(20, byteorder='big'))
        b2 = bytearray()
        b2int = 0x686974207468652062756c6c277320657965
        b2.extend(b2int.to_bytes(20, byteorder='big'))
        b3 = bytearray()
        b3int = 0x746865206b696420646f6e277420706c6179
        b3.extend(b3int.to_bytes(20, byteorder='big'))
        self.assertEqual(b3, xor_buffer(b1, b2))

    def test_finding_one_byte_key(self):
        print("Testing Xoring decription...")
        cipher_text_str = "0x1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        cipher_text = hex_str_to_bytearray(cipher_text_str)
        print("Cipher text is:", cipher_text.hex())
        res = count_byte_occurence(cipher_text)
        display_char_occurences(res)
        self.assertEqual(res[255][0], 0x78)
        for i in range(1, 237):
            self.assertEqual(res[i][1], 0.0)
        print("e is the most common char in english and we know the key is only one byte long.")
        print("Space is also very common.")
        print("Good candidates for keys are 'e', 'E' and ' '.")
        print("The most present char is:", hex(res[255][0]))

        def try_key(char):
            likely_key_int = res[255][0] ^ ord(char)
            likely_key = bytearray()
            likely_key.extend(likely_key_int.to_bytes(1, byteorder='big'))
            print("trying key", hex(likely_key_int), "deduced assuming the most presnt char is", char + ".")
            print("xoring", hex(likely_key_int), "and cipher_text...")
            plain_text = xor_key(cipher_text, likely_key)
            if is_plain_text(plain_text):
                print("The message seems readable. The key seems to be ", hex(likely_key_int) + ".")
                print("Plain Message: ", str(plain_text))
            else:
                print("The message seems not readable. The key seems not to be ", hex(likely_key_int) + ".")
            return plain_text

        try_key('e')
        try_key('E')
        solution = try_key(' ')

        solution_expected = bytearray(b"Cooking MC\'s like a pound of bacon")
        self.assertEqual(solution_expected, solution)

    def test_xor_encription(self):
        print("Testing Xoring Encription...")
        plain_text_str = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        key_str = "ICE"
        plain_text = bytearray(plain_text_str, "ascii")
        key = bytearray(key_str, "ascii")
        expected_result = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                           "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
        print("Xoring plain text:\n" + plain_text_str + "\nwith key " + key_str + ".")
        cipher_text = xor_key(plain_text, key).hex()
        print("output: " + cipher_text)
        self.assertEqual(expected_result, cipher_text)

    def test_hamming_distance(self):
        print("Testing Hamming distance computation...")
        pattern1_str = "this is a test"
        pattern2_str = "wokka wokka!!!"
        pattern1 = bytearray(pattern1_str, "ascii")
        pattern2 = bytearray(pattern2_str, "ascii")
        expected_result = 37
        print("Computing hamming distance between", pattern1_str, "and", pattern2_str + ":")
        result = hamming_distance(pattern1, pattern2)
        print("Hamming distance is " + str(result) + ".")
        self.assertEqual(expected_result, result)

    def test_read_b64_file(self):
        print("Testing read_b64_file()...")
        path_to_file = os.path.dirname(os.path.realpath(__file__)) + "/set1/testReadB64.txt"
        ba = read_b64_file(path_to_file)
        print(ba)
        expectedRes = "abcdefhH87"
        self.assertEqual(expectedRes, ba.decode("ascii"))

    def test_split_bytearray(self):
        print("Testing test_split_bytearray()...")
        ba = hex_str_to_bytearray("0xffaabb11cc99ee88dd")
        expected_res_1 = [bytearray(b'\xff\xbb\xcc\xee\xdd'), bytearray(b'\xaa\x11\x99\x88')]
        expected_res_2 = [bytearray(b'\xff\x11\xee'), bytearray(b'\xaa\xcc\x88'), bytearray(b'\xbb\x99\xdd')]
        res1 = split_bytearray(ba, 2)
        res2 = split_bytearray(ba, 3)
        self.assertEqual(ba, split_bytearray(ba, 1)[0])
        self.assertEqual(expected_res_1, res1)
        self.assertEqual(expected_res_2, res2)

    def test_decrypt_xor_text(self):
        print(">>> Resolving set1/challenge6.txt")
        path_to_challenge6 = os.path.dirname(os.path.realpath(__file__)) + "/set1/challenge6.txt"
        cipher_text = read_b64_file(path_to_challenge6)
        plain_text = decrypt_xor_text(cipher_text)
        self.assertEqual("I'm back and", plain_text[0:12].decode("utf-8"))

        print(">>> Resolving set1/my_plain_b64.txt")
        path_to_my_plain = os.path.dirname(os.path.realpath(__file__)) + "/set1/my_plain_b64.txt"
        my_key = bytearray("goodd", "ascii")
        plain_text = read_b64_file(path_to_my_plain)
        cipher_text = xor_key(plain_text, my_key)
        plain_text_back = decrypt_xor_text(cipher_text)
        self.assertEqual(plain_text, plain_text_back)


if __name__ == "__main__":
    unittest.main()
