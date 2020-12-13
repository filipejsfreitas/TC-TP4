#!/usr/bin/python

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os, sys

# Gerar dois arrays (diferentes!!) de bytes de tamanhos adequados, a utilizar
# como chave para a cifra e para o mac. Estes valores deverão estar hardcoded em
# ambos ficheiros enc.py e dec.py.
key = bytes.fromhex('634a7e6cbafe0096c40b9cfe956b433766e4fe9fdb3173416144b66f2aba6593')
# hmackey = None # SHA256 doesn't use an HMAC Key

# Em todas as funções foram utilizadas variáveis com nomes descritivos, e o código
# foi escrito de forma a ser evidente o que é feito em cada passo.
# Deste modo, os comentários estão reduzidos ao mínimo necessário.

def rff(nomeficheiro):
  with open(nomeficheiro, 'rb') as f:
    return f.read()

def etm():
  data = rff("dados-etm.dat")

  # Devido aos tamanhos fixos do nonce e da tag, é fácil decompor a mensagem nos seus componentes
  nonce = data[:16]
  tag = data[-32:]
  ciphertext = data[16:-32]

  sha256 = hashes.Hash(hashes.SHA256())
  sha256.update(ciphertext)
  computed_tag = sha256.finalize()

  if computed_tag != tag:
      raise ValueError('The HMAC of the messages doesn\'t match')

  cipher = Cipher(algorithms.ChaCha20(key, nonce), mode = None)
  decryptor = cipher.decryptor()
  msg = decryptor.update(ciphertext) + decryptor.finalize()
  
  print(str(msg, encoding='utf-8'))

def eam():
  data = rff("dados-eam.dat")

  # Devido aos tamanhos fixos do nonce e da tag, é fácil decompor a mensagem nos seus componentes
  nonce = data[:16]
  tag = data[-32:]
  ciphertext = data[16:-32]

  cipher = Cipher(algorithms.ChaCha20(key, nonce), mode = None)

  decryptor = cipher.decryptor()
  msg = decryptor.update(ciphertext) + decryptor.finalize()

  sha256 = hashes.Hash(hashes.SHA256())
  sha256.update(msg)
  computed_tag = sha256.finalize()

  if computed_tag != tag:
      raise ValueError('The HMAC of the message doesn\'t match')

  print(str(msg, encoding='utf-8'))

def mte():
  data = rff("dados-mte.dat")

  # Devido tamanho fixo do nonce, é fácil decompor a mensagem nos seus componentes
  nonce = data[:16]
  ciphertext = data[16:]

  cipher = Cipher(algorithms.ChaCha20(key, nonce), mode = None)

  decryptor = cipher.decryptor()
  msg = decryptor.update(ciphertext)

  tag = msg[-32:]
  msg = msg[:-32]

  sha256 = hashes.Hash(hashes.SHA256())
  sha256.update(msg)
  computed_tag = sha256.finalize()

  if computed_tag != tag:
      raise ValueError('The HMAC of the messages doesn\'t match')

  print(str(msg, encoding='utf-8'))

def main():

  if len(sys.argv) != 2:
    print("Please provide one of: eam, etm, mte")
  elif sys.argv[1] == "eam":
    eam()
  elif sys.argv[1] == "etm":
    etm()
  elif sys.argv[1] == "mte":
    mte()
  else:
    print("Please provide one of: eam, etm, mte")

if __name__ == '__main__':
  main()
