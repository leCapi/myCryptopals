#!/usr/bin/python3
import base64
import codecs
import sys
import operator
import os

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


def rateAlphaNumSpace(ba):
  nbAlphaNumSpace = 0
  lenBa = len(ba)

  for i in ba :
    if i == 0x20 or (ord('a') <= i <= ord('z')) or (ord('A') <= i <= ord('Z')):
      nbAlphaNumSpace +=1

  return nbAlphaNumSpace/lenBa

def isPlainText(ba, rate = 0.90):
  if (rateAlphaNumSpace(ba) >= rate):
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
  Return xored data.

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
  strlen = len(ba)

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


def hammingDistance(a,b):
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
  if (len(a)!=len(b) or len(a) == 0) :
    return -1
  p1XorP2 = xorBuffer(a, b)
  intP1XorP2 = int.from_bytes(p1XorP2, byteorder='big', signed=False)
  result = bin(intP1XorP2).count("1")
  return result


def readB64File(path):
  """
  Read file which encodes data in b64 on several lines.

  Args:
    path string: path to file
  Returns:
    bytearray: data decoded from message in the given file 
  """
  try :
    file = open(path, 'r')
  except:
    print("Can't open file " + path + ".")
    return None
  stringFile = str()
  for line in file:
    lineWithoutReturn = line.rstrip()
    stringFile += lineWithoutReturn
  res = base64.b64decode(stringFile)
  file.close()
  return res


def splitByteArray(ba, nbBa):
  """
  Split a bytearray into several bytearrays.
  The bytes are split in round robin between the output bytearrays.

  Args:
    ba bytearray: bytearray to split
    nbBa int: number of bytearray
  Returns:
    list: list of nbBa bytearray with all original bytes
  """
  tab = list()
  lenBa = len(ba)

  # create sub bytearray with appropirate len
  rest = lenBa % nbBa
  for i in range(0,nbBa):
    lenSubBa = lenBa//nbBa
    if rest - i > 0 :
      lenSubBa += 1
    tab.append(bytearray(lenSubBa))

  # dispatch bytes
  for i in range(0, len(ba)):
    baIndex = i % nbBa
    tab[baIndex][i//nbBa] = (ba[i])

  return tab

def guessKeyLenHD(ba, maxLen):
  hammingDistances = [0] * maxLen

  for i in range(1, maxLen+1):
    nb_hd = 20
    for j in range(0, nb_hd) :
      ba1 = ba[(2*j)*i:(2*j+1)*i]
      ba2 = ba[(2*j+1)*i:(2*j+2)*i]
      hammingDistances[i-1] += hammingDistance(ba1,ba2)/i
    hammingDistances[i-1] = hammingDistances[i-1] / nb_hd

  sortedHD = list(zip(range(1, maxLen+1), hammingDistances))
  sortedHD.sort(key=operator.itemgetter(1))
  return(sortedHD[0][0])

def decrypt_xor_text(cipher_text):
  secret_key = bytearray()

  key_len = guessKeyLenHD(cipher_text, 42)
  print("best key length using hamming distance method :", key_len)
  subText = splitByteArray(cipher_text, key_len)
 
  print("display of the most common bytes of each sets")
  listByteOcc = list()
  for i in subText:
    listByteOcc.append(countByteOccurence(i)[250:256])
  for index, i in enumerate(listByteOcc):
    print("###", index)
    displayCharOccurences(i)

  for i in listByteOcc:
    most_present_byte = i[-1][0]
    char_key = most_present_byte^0x20
    secret_key.append(char_key)
    print("xoring " + hex(most_present_byte) + " and 0x20 : " , chr(char_key), hex(char_key))

  print("The secrekt key is : " + 'secret_key.decode("ascii")')
  print("The plain text is :")
  plain_text = xorKey(cipher_text, secret_key)
  print(plain_text.decode("utf-8"))
  return plain_text

if __name__ == "__main__" :
  pass
