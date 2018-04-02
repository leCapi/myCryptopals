#!/usr/bin/python3
# pylint: disable-msg=w0614
import unittest
from main import *
import os
  
class MyTests(unittest.TestCase) :
  
  def testB64(self) :
    print("Testing hexStrToB64Str()...")
    inputStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expectedStr = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    self.assertEqual(expectedStr, hexStrToB64Str(inputStr))


  def testHexStrToByteArray(self) :
    print("Testing hexStrToByteArray()...")
    cipherTextStr = "0x1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    cipheredText = hexStrToByteArray(cipherTextStr)
    self.assertEqual(bytearray(b'\x1b77316?x\x15\x1b\x7f+x413=x9x(7-6<x7>x:9;76'), cipheredText)
  

  def testXorBuffer(self) :
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
    self.assertEqual(b3, xorBuffer(b1,b2))


  def testFindingOneByteKey(self):
    print("Testing Xoring decription...")
    cipherTextStr = "0x1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    cipheredText = hexStrToByteArray(cipherTextStr)
    print("Cipher text is :", cipheredText.hex())
    res = countByteOccurence(cipheredText)
    displayCharOccurences(res)
    self.assertEqual(res[255][0], 0x78)
    for i in range(1, 237):
      self.assertEqual(res[i][1], 0.0)
    print("e is the most common char in english and we know the key is only one byte long.")
    print("Space is also very common.")
    print("Good candidates for keys are 'e', 'E' and ' '.")
    print("The most present char is :", hex(res[255][0]))

    def tryKey(ciphBa, char):
      likelyKeyInt = res[255][0] ^ ord(char)
      likelyKey = bytearray()
      likelyKey.extend(likelyKeyInt.to_bytes(1, byteorder='big'))
      print("trying key", hex(likelyKeyInt), "deduced assuming the most presnt char is", char + ".")
      print("xoring", hex(likelyKeyInt), "and cipheredText...")
      plainText = xorKey(cipheredText, likelyKey)
      if isPlainText(plainText) :
        print("The message seems readable. The key seems to be ", hex(likelyKeyInt) + ".")
        print("Plain Message : ", str(plainText))
      else :
        print("The message seems not readable. The key seems not to be ", hex(likelyKeyInt) + ".")
      return plainText

    tryKey(cipheredText, 'e')
    tryKey(cipheredText, 'E')
    solution = tryKey(cipheredText, ' ')

    solutionExpected = bytearray(b"Cooking MC\'s like a pound of bacon")
    self.assertEqual(solutionExpected, solution)


  def testXorEncription(self) :
    print("Testing Xoring Encription...")
    plainTextStr = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    keyStr = "ICE"
    plainText = bytearray(plainTextStr, "ascii")
    key = bytearray(keyStr, "ascii")
    expectedResult = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                      "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    print("Xoring plain text :\n" + plainTextStr +"\nwith key " + keyStr + ".")
    cipherText = xorKey(plainText, key).hex()
    print("output : " + cipherText)
    self.assertEqual(expectedResult, cipherText)


  def testHammingDistance(self):
    print("Testing Hamming distance computation...")
    pattern1Str = "this is a test"
    pattern2Str = "wokka wokka!!!"
    pattern1 = bytearray(pattern1Str, "ascii")
    pattern2 = bytearray(pattern2Str, "ascii")
    expectedResult = 37
    print("Computing hamming distance between", pattern1Str, "and", pattern2Str +":")
    result = hammingDistance(pattern1, pattern2)
    print("Hamming distance is " + str(result) +".")
    self.assertEqual(expectedResult, result)


  def testReadB64File(self):
    print("Testing readB64File()...")
    pathToFile = os.path.dirname(os.path.realpath(__file__)) + "/set1/testReadB64.txt"
    ba = readB64File(pathToFile)
    print(ba)
    expectedRes = "abcdefhH87"
    self.assertEqual(expectedRes, ba.decode("ascii"))


  def testSplitBytearray(self):
    print("Testing testSplitBytearray()...")
    ba = hexStrToByteArray("0xffaabb11cc99ee88dd")
    expectedRes1 = [bytearray(b'\xff\xbb\xcc\xee\xdd'), bytearray(b'\xaa\x11\x99\x88')]
    expectedRes2 = [bytearray(b'\xff\x11\xee'), bytearray(b'\xaa\xcc\x88'), bytearray(b'\xbb\x99\xdd')]
    res1 = splitByteArray(ba, 2)
    res2 = splitByteArray(ba, 3)
    self.assertEqual(ba, splitByteArray(ba,1)[0])
    self.assertEqual(expectedRes1, res1)
    self.assertEqual(expectedRes2, res2)

  def testDecryptXorText(self):
    print(">>> Resolving set1/challenge6.txt")
    path_to_challenge6 = os.path.dirname(os.path.realpath(__file__)) + "/set1/challenge6.txt"
    cipher_text = readB64File(path_to_challenge6)
    plain_text = decrypt_xor_text(cipher_text)
    self.assertEqual("I'm back and", plain_text[0:12].decode("utf-8"))

    print(">>> Resolving set1/my_plain_b64.txt")
    path_to_my_plain = os.path.dirname(os.path.realpath(__file__)) + "/set1/my_plain_b64.txt"
    my_key = bytearray("goodd", "ascii")
    plain_text = readB64File(path_to_my_plain)
    cipher_text = xorKey(plain_text, my_key)
    plain_text_back = decrypt_xor_text(cipher_text)
    self.assertEqual(plain_text, plain_text_back)


if __name__ == "__main__" :
  unittest.main()
