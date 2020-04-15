#!/usr/bin/python3
# pylint: disable-msg=w0614
import unittest
from main import *
import os
import sys


class MyTests(unittest.TestCase):

    def test_b64(self):
        input_str = ("49276d206b696c6c696e6720796f757220627261696e206c696b6520"
                     "6120706f69736f6e6f7573206d757368726f6f6d")
        expected_str = ("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3Vz"
                        "IG11c2hyb29t")
        self.assertEqual(expected_str, hex_str_to_b64_str(input_str))

    def test_hex_str_to_bytearray(self):
        cipher_text_str = ("0x1b37373331363f78151b7f2b783431333d78397828372d36"
                           "3c78373e783a393b3736")
        cipher_text = hex_str_to_bytearray(cipher_text_str)
        self.assertEqual(bytearray(b'\x1b77316?x\x15\x1b\x7f+x413=x9x(7-6<x7>x:9;76'), cipher_text)

    def test_xor_buffer(self):
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
        # e is the most common char in english and we know the key is only one byte long.
        # Space is also very common.
        # Good candidates for keys are 'e', 'E' and ' '.
        cipher_text_str = "0x1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        cipher_text = hex_str_to_bytearray(cipher_text_str)
        res = count_byte_occurrence(cipher_text)
        # display_char_occurrences(res)
        self.assertEqual(res[255][0], 0x78)
        for i in range(1, 237):
            self.assertEqual(res[i][1], 0.0)

        def try_key(char):
            likely_key_int = res[255][0] ^ ord(char)
            likely_key = bytearray()
            likely_key.extend(likely_key_int.to_bytes(1, byteorder='big'))
            plain_text = xor_key(cipher_text, likely_key)
            if is_plain_text(plain_text):
                return plain_text
            else:
                return None

        self.assertEqual(try_key('e'), None)
        self.assertEqual(try_key('e'), None)
        solution = try_key(' ')
        solution_expected = bytearray(b"Cooking MC\'s like a pound of bacon")
        self.assertEqual(solution_expected, solution)

    def test_xor_encription(self):
        plain_text_str = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        key_str = "ICE"
        plain_text = bytearray(plain_text_str, "ascii")
        key = bytearray(key_str, "ascii")
        expected_result = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                           "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
        cipher_text = xor_key(plain_text, key).hex()
        self.assertEqual(expected_result, cipher_text)

    def test_hamming_distance(self):
        pattern1_str = "this is a test"
        pattern2_str = "wokka wokka!!!"
        pattern1 = bytearray(pattern1_str, "ascii")
        pattern2 = bytearray(pattern2_str, "ascii")
        expected_result = 37
        result = hamming_distance(pattern1, pattern2)
        self.assertEqual(expected_result, result)

    def test_read_b64_file(self):
        path_to_file = os.path.dirname(os.path.realpath(__file__)) + "/set1/testReadB64.txt"
        ba = read_b64_file(path_to_file)
        expectedRes = "abcdefhH87"
        self.assertEqual(expectedRes, ba.decode("ascii"))

    def test_split_bytearray(self):
        ba = hex_str_to_bytearray("0xffaabb11cc99ee88dd")
        expected_res_1 = [bytearray(b'\xff\xbb\xcc\xee\xdd'), bytearray(b'\xaa\x11\x99\x88')]
        expected_res_2 = [bytearray(b'\xff\x11\xee'), bytearray(b'\xaa\xcc\x88'), bytearray(b'\xbb\x99\xdd')]
        res1 = split_bytearray(ba, 2)
        res2 = split_bytearray(ba, 3)
        self.assertEqual(ba, split_bytearray(ba, 1)[0])
        self.assertEqual(expected_res_1, res1)
        self.assertEqual(expected_res_2, res2)

    # set 1 challenge 6
    def test_decrypt_xor_text(self):
        # Resolving set1/challenge6.txt
        path_to_challenge6 = os.path.dirname(os.path.realpath(__file__)) + "/set1/challenge6.txt"
        cipher_text = read_b64_file(path_to_challenge6)
        plain_text = decrypt_xor_text(cipher_text)
        self.assertEqual("I'm back and", plain_text[0:12].decode("utf-8"))

        # Resolving set1/my_plain_b64.txt
        path_to_my_plain = os.path.dirname(os.path.realpath(__file__)) + "/set1/my_plain_b64.txt"
        my_key = bytearray("goodd", "ascii")
        plain_text = read_b64_file(path_to_my_plain)
        cipher_text = xor_key(plain_text, my_key)
        plain_text_back = decrypt_xor_text(cipher_text)
        self.assertEqual(plain_text, plain_text_back)

    # set 1 challenge 7
    def test_decoding_aes(self):
        path_to_challenge7 = os.path.dirname(os.path.realpath(__file__)) + "/set1/challenge7.txt"
        cipher_text = read_b64_file(path_to_challenge7)
        key = "YELLOW SUBMARINE"
        obj = AES.new(key, AES.MODE_ECB)
        plain_text = obj.decrypt(cipher_text).decode("utf-8")
        self.assertEqual("I'm back and", plain_text[0:12])

    # set 1 challenge 8
    def test_spot_aes_128_ecb(self):
        path_to_challenge8 = (os.path.dirname(os.path.realpath(__file__))
                          + "/set1/challenge8.txt")
        with open(path_to_challenge8, 'r') as file:
            texts = list()
            for line in file:
                lineWithoutReturn = line.rstrip()
                texts.append(hex_str_to_bytearray(lineWithoutReturn))

        # print("There are " + str(len(texts)) + " texts.")
        min_patterns = 16
        min_patterns_rank = 0
        for i,text in enumerate(texts):
            patterns = pattern_inventory(text, 16)
            if len(patterns) < min_patterns:
                min_patterns = len(patterns)
                min_patterns_rank = i
        # print("The text with the minium of 16 bytes patterns among all"
        #     " is the text number "
        #     + str(min_patterns_rank) + " with " + str(min_patterns) + " patterns.")
        # print(hex(text[min_patterns_rank]))
        # print(pattern_inventory(texts[132], 16))
        self.assertEqual(7, min_patterns)
        self.assertEqual(132, min_patterns_rank)

    # set 2 Challenge 9
    def test_fill_PKCS7(self):
        block_fo_fill = bytearray("YELLOW SUBMARINE", "ascii")
        expected_result = bytearray("YELLOW SUBMARINE\x04\x04\x04\x04", "ascii")
        filled_block = padding_block(block_fo_fill, 20)
        self.assertEqual(expected_result, filled_block)
        self.assertEqual(padding_block(filled_block, 20), filled_block)
        self.assertEqual(clean_padding(expected_result,aes_block_size), block_fo_fill)

    # set 2 Challenge 10
    def test_aes_encrypt_ecb(self):
        # 16 bytes len key
        key = bytearray("0123456789ABCDEF", "ascii")
        # 16 bytes len text
        plain_text = bytearray("YELLOW SUMBAMINE", "ascii")
        cipher_text = aes_encrypt_ecb(plain_text, key)
        expected_result = bytearray(b'\x90\x8a\xa8\xbe\xd2\x75\x6a\x0d\x53\x1a\x81\x0e\x2d\xfe\x45\xc2')
        self.assertEqual(expected_result, cipher_text)

    def test_aes_decrypt_cbc(self):
        path_to_challenge10 = os.path.dirname(os.path.realpath(__file__)) + "/set2/challenge10.txt"
        cipher_text = read_b64_file(path_to_challenge10)
        init_vector = bytearray(aes_block_size)
        key = bytearray("YELLOW SUBMARINE", "ascii")
        plain_text = aes_decrypt_cbc(key, cipher_text, init_vector).decode("utf_8")
        self.assertEqual(plain_text.find("\nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are "), 1428)
        plain_text_ba = bytearray(plain_text, "utf_8")
        re_cipher = aes_encrypt_cbc(key, plain_text_ba, init_vector)
        self.assertEqual(cipher_text, re_cipher)

    # set 2 Challenge 11
    def test_rdm_aes_key(self):
        k1 = generate_random_aes_key()
        k2 = generate_random_aes_key()
        k3 = generate_random_aes_key()
        self.assertEqual(len(k1),16)
        self.assertEqual(len(k2),16)
        self.assertEqual(len(k3),16)
        self.assertFalse(k1 == k2, "this is very unlikely to happen")
        self.assertFalse(k1 == k3, "this is very unlikely to happen")
        self.assertFalse(k2 == k3, "this is very unlikely to happen")
    
    def test_ecb_oracle(self):
        plain_text = bytearray(b'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ')
        for i in range(0,100):
            cipher_text, mod = rdm_encrypt_aes_cbc_or_ecb(plain_text)
            prediction = oracle_aes_ecb_or_aes_cbc(cipher_text)
            self.assertEqual(prediction, mod)
    ########################################################

    # set 2 Challenge 12
    def test_ecb_cracking(self):
        path_to_challenge11 = os.path.dirname(os.path.realpath(__file__)) + "/set2/challenge12.txt"
        text_to_discover = read_b64_file(path_to_challenge11)

        def black_box_to_crack(plain_text):
            full_text = plain_text + text_to_discover
            unknown_secret_key = bytearray(b'this_is_a_secret')
            return aes_encrypt_ecb(full_text, unknown_secret_key)

        def discover_block_size():
            plain_text = bytearray()
            initial_len = len(black_box_to_crack(plain_text))
            for i in range(0,128):
                plain_text.extend(b"a")
                new_len = len(black_box_to_crack(plain_text))
                if new_len != initial_len:
                    return (new_len - initial_len), initial_len - i
            return -1, -1

        bb_output = black_box_to_crack(bytearray(b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"))
        mod = oracle_aes_ecb_or_aes_cbc(bb_output)
        self.assertEqual(mod, 0)
        block_size, unknown_text_size = discover_block_size()
        self.assertEqual(block_size, 16)
        self.assertEqual(unknown_text_size, 138)
        
        def find_text_to_discover(text_size, tester):
            secret_plain_text = bytearray()
            shifter = bytearray(b'aaaaaaaaaaaaaaa')
            secret_plain_text = shifter[:]
            for i in range(0, text_size):
                shift_len = 15 - (i % 16)
                shift_used = shifter[:shift_len]
                cipher_block_number = i // 16
                start_output = cipher_block_number * 16
                end_output = start_output + 15
                ciphered_block_to_guess = black_box_to_crack(shift_used)[start_output:end_output]
                len_spt = len(secret_plain_text)
                # 15 bytes of data we are sure
                data_to_test = secret_plain_text[len_spt-15:]
                # let s find the last byte
                byte_found = False
                for plain_byte in range(0,256):
                    complete_chunk_to_test = data_to_test[:]
                    complete_chunk_to_test.append(plain_byte)
                    candidate_ciphered_block = black_box_to_crack(complete_chunk_to_test)[0:15]
                    if candidate_ciphered_block == ciphered_block_to_guess:
                        secret_plain_text.append(plain_byte)
                        byte_found = True
                        break
                tester.assertTrue(byte_found)
            return secret_plain_text[15:]

        discovered_text = find_text_to_discover(unknown_text_size, self)
        self.assertEqual(discovered_text, text_to_discover)
        self.assertTrue
    ########################################################

    # set 2 Challenge 13
    def test_ecb_cut_and_past(self):
        def cookie_to_dict(input_cookie):
            parsed_cookie = {}
            list_k_v = input_cookie.split('&')
            for e in list_k_v:
                key_value = e.split('=')
                if len(key_value) != 2:
                    raise ValueError("Invalid cookie")
                key = key_value[0]
                value = key_value[1]
                parsed_cookie[key] = value
            return parsed_cookie

        def dict_to_cookie(dictionary):
            output = str()
            first_loop = True
            for k,v in dictionary.items():
                if first_loop:
                    first_loop = False
                else:
                    output += "&"
                output += k
                output += "="
                output += v
            return bytearray(output, "ascii")

        def profile_for(mail):
            prof = {}
            protected_mail = mail.replace('&', '')
            protected_mail = protected_mail.replace('=', '')
            prof["email"] = protected_mail
            prof["uid"] = "10"
            prof["role"] = "user"
            return prof

        def cipher_profile_for(mail):
            plain_profile = profile_for(mail)
            serialized_profile = dict_to_cookie(plain_profile)
            ciphered_profile = aes_encrypt_ecb(serialized_profile, aes_secret_key)
            return bytearray(ciphered_profile)

        def load_cipher_data(ciphered_data):
            plain_data = aes_decrypt_ecb(ciphered_data, aes_secret_key)
            plain_data = clean_padding(plain_data, aes_block_size)
            data = cookie_to_dict(plain_data.decode("ascii"))
            return data

        test_cookie = "foo=bar&baz=qux&zap=zazzle"
        test_profile_for = "foo=&&&&=@bar.com"
        aes_secret_key = generate_random_aes_key()

        # test functions defined for exercise
        cookie_dict = cookie_to_dict(test_cookie)
        cookie = dict_to_cookie(cookie_dict)
        self.assertEqual(cookie.decode("ascii"), test_cookie)
        data_ciphered = cipher_profile_for(test_profile_for)
        data = load_cipher_data(data_ciphered)
        print(data)
        self.assertEqual(data["email"], "foo@bar.com")
        self.assertEqual(data["uid"], "10")
        self.assertEqual(data["role"], "user")

        # find admin cipher value when isolated in a single block (need to pad)
        admin_cipher_input = bytearray(b'AAAAAAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b')
        cipher_output_admin = cipher_profile_for(admin_cipher_input.decode("ascii"))
        admin_block = cipher_output_admin[aes_block_size:2*aes_block_size]
        # isolate the role value in the last block
        attacker_email = "foo@barrr.com"
        input_isolate_role_block = attacker_email
        cipher_role_isolate = cipher_profile_for(input_isolate_role_block)
        # craft data admin data without aes key
        crafted_admin = cipher_role_isolate[:2*aes_block_size]
        crafted_admin.extend(admin_block)
        data_loaded = load_cipher_data(crafted_admin)
        self.assertEqual(data_loaded["email"], attacker_email)
        self.assertEqual(data_loaded["uid"], "10")
        self.assertEqual(data_loaded["role"], "admin")

    ########################################################
if __name__ == "__main__":
    sys.exit(unittest.main())
