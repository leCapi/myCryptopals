import unittest
import main
  
class MyTests(unittest.TestCase) :
  
  def testB64(self) :
    inputStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expectedStr = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    self.assertEqual(expectedStr, main.hexStrToB64Str(inputStr))
  
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
    self.assertEqual(b3, main.xorBuffer(b1,b2))

if __name__ == "__main__" :
  unittest.main()