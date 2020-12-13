#!/usr/bin/python

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os, sys

# Gerar dois arrays (diferentes!!) de bytes de tamanhos adequados, a utilizar
# como chave para a cifra e para o mac. Estes valores deverão estar hardcoded em
# ambos ficheiros enc.py e dec.py.
key = bytes.fromhex('634a7e6cbafe0096c40b9cfe956b433766e4fe9fdb3173416144b66f2aba6593')
# hmackey = None # SHA256 doesn't use an HMAC Key

msg = "Isto é uma mensagem não muito secreta!"

# Em todas as funções foram utilizadas variáveis com nomes descritivos, e o código
# foi escrito de forma a ser evidente o que é feito em cada passo.
# Deste modo, os comentários estão reduzidos ao mínimo necessário.

def etm():
  global msg

  msg = bytes(msg, encoding='UTF-8')
  nonce = os.urandom(16)

  cipher = Cipher(algorithms.ChaCha20(key, nonce), mode = None)

  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(msg) + encryptor.finalize()

  sha256 = hashes.Hash(hashes.SHA256())
  sha256.update(ciphertext)
  tag = sha256.finalize()

  # O nonce e a tag têm sempre o mesmo tamanho, logo não é necessário incluir esses tamanhos nos dados a guardar
  dados = nonce + ciphertext + tag

  w2f("dados-etm.dat", dados)

def eam():
  global msg

  msg = bytes(msg, encoding='UTF-8')
  nonce = os.urandom(16)

  cipher = Cipher(algorithms.ChaCha20(key, nonce), mode = None)

  sha256 = hashes.Hash(hashes.SHA256())
  sha256.update(msg)
  tag = sha256.finalize()

  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(msg) + encryptor.finalize()

  # O nonce e a tag têm sempre o mesmo tamanho, logo não é necessário incluir esses tamanhos nos dados a guardar
  dados = nonce + ciphertext + tag

  w2f("dados-eam.dat", dados)

def mte():
  global msg

  msg = bytes(msg, encoding='UTF-8')
  nonce = os.urandom(16)

  cipher = Cipher(algorithms.ChaCha20(key, nonce), mode = None)

  sha256 = hashes.Hash(hashes.SHA256())
  sha256.update(msg)
  tag = sha256.finalize()

  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(msg + tag) + encryptor.finalize()
  
  # O nonce tem sempre o mesmo tamanho, logo não é necessário incluir ess tamanho nos dados a guardar
  dados = nonce + ciphertext

  w2f("dados-mte.dat", dados)

def w2f(nomeficheiro, data):
  with open(nomeficheiro, 'wb') as f:
    f.write(data)

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
