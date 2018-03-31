import base64
import codecs
import sys
import operator

def hexStrToByteArray(s):
  ba = bytearray()
  nbBytes = len(s)//2 - 2 + 1
  bInt = int(s, 16)
  ba.extend(bInt.to_bytes(nbBytes, byteorder='big'))
  return ba


def hexStrToB64Str(hexStr):
  decodedStr = codecs.decode(hexStr, 'hex')
  b64 = codecs.encode(decodedStr,'base64')

  return codecs.decode(b64).rstrip()


def isPlainText(ba, rate = 0.90):
  nbAlphaNumSpace = 0
  lenBa = len(ba)

  for i in ba :
    if i == 0x20 or (ord('a') <= i <= ord('z')) or (ord('A') <= i <= ord('Z')):
      nbAlphaNumSpace +=1

  rateAlphaNumSpace = nbAlphaNumSpace/lenBa

  if (rateAlphaNumSpace >= rate):
    return True
  return False


def xorBuffer(b1, b2):
  if len(b1) != len(b2) :
    raise ValueError("bytearrays are not the same length")
  
  b3 = bytearray(len(b1))
  
  for i in range(0, len(b1)) :
    b3[i] = b2[i] ^ b1[i]
  
  return b3


def xorKey(dataIn, key):
  """
  Return decoded data.

  Args:
    dataIn bytearay: data to decode
    key bytearray: key used to decode
  Returns:
    bytearray: dataIn ^ key
  """
  key_len = len(key)
  dataOut = bytearray(len(dataIn))
  for i in range(0, len(dataIn)):
    dataOut[i] = dataIn[i] ^ key[i%key_len]
  return dataOut


def countByteOccurence(ba):
  """
  Return sorted list of tuple.

  Args:
    ba bytearray: Ciphered text
  Returns:
    list: a sorted list of 256 tuples (char, %presence)
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
  pass