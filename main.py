import base64
import codecs
import sys
import operator

def hexStrToB64Str(hexStr):
  decodedStr = codecs.decode(hexStr, 'hex')
  b64 = codecs.encode(decodedStr,'base64')
  
  return codecs.decode(b64).rstrip()


def xorBuffer(b1, b2):
  if len(b1) != len(b2) :
    raise ValueError("bytearrays are not the same length")
  
  b3 = bytearray(len(b1))
  
  for i in range(0, len(b1)) :
    b3[i] = b2[i] ^ b1[i]
  
  return b3

def xorKey(cipheredText, key):
  key_len = len(key)
  plainText = bytearray(len(cipheredText))
  for i in range(0, len(cipheredText)):
    plainText[i] = cipheredText[i] ^ key[i%key_len]
  return plainText


def countByteOccurence(ba):
  """
  Return sorted list of tuple

  :param ba: Ciphered text
  :return: a sorted list of 256 tuples (char, %presence)
  """
  tab = [0] * 256
  strlen = len(ba) - 1

  for i in ba:
    tab[i] = tab[i] + 1/strlen

  sortedBytes = list(zip(range(0, 256), tab))
  sortedBytes.sort(key=operator.itemgetter(1))
  
  return sortedBytes

def displayCharOccurences(sortedOcc) :
  for i in reversed(sortedOcc) :
    if i[1] == 0 :
      break
    print(hex(i[0]), ":", i[1])


if __name__ == "__main__" :
  cipheredText = bytearray()
  b1str = "0x1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
  nbBytes = len(b1str)//2 - 2 + 1
  b1int = int(b1str, 16) 
  print(hex(b1int))
  cipheredText.extend(b1int.to_bytes(nbBytes, byteorder='big'))
  print(cipheredText.hex())
  res = countByteOccurence(cipheredText)
  displayCharOccurences(res)
  print("e is the most common char in english and we know the key is only one byte long.")
  print("Space is also very common.")
  print("Good candidates for keys are 'e', 'E' and ' '.")
  print("The most present char is :", hex(res[255][0]))
  likelyKeyInt = res[255][0] ^ ord(' ')
  likelyKey = bytearray()
  likelyKey.extend(likelyKeyInt.to_bytes(1, byteorder='big'))
  print("key should be", hex(likelyKeyInt))
  print("xoring", hex(likelyKeyInt), "and cipheredText...")
  plainText = xorKey(cipheredText, likelyKey)
  print("Plain text :")
  print(plainText.hex())
  print(plainText)
 

  
