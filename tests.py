import unittest
from main import *
  
class MyTests(unittest.TestCase) :
  
  def testB64(self) :
    inputStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expectedStr = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    self.assertEqual(expectedStr, hexStrToB64Str(inputStr))
  
  def testXorByteArray(self) :
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
    cipherTextStr = "0x1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    cipheredText = hexStrToByteArray(cipherTextStr)
    print("Cipher text is :", cipheredText.hex())
    res = countByteOccurence(cipheredText)
    displayCharOccurences(res)
    print(res[0])
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

if __name__ == "__main__" :
  unittest.main()