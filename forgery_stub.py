#!/usr/bin/python

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# import relevant cryptographic primitives

AES_BLOCK_LENGTH = 16 # bytes
AES_KEY_LENGTH = 32 # bytes

# Insecure CBCMAC.
# Implement CBCMAC with a random IV

def cbcmac(key, msg):
  if not _validate_key_and_msg(key, msg): return False

  # Gerar um IV aleatório
  iv = os.urandom(16)

  # Cifrar com AES
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
  encry = cipher.encryptor()
  ct = encry.update(msg) + encry.finalize()

  tag = ct[-16: ] # Retorna o ultimo bloco como sendo a tag

  # A tag agora é composta pelo último bloco e também pelo IV
  # Seria fácil modificar isto para que estes dados fossem enviados pela rede (bastava concatenar o IV no final da tag),
  # mas como neste caso isso não é necessário, iremos recorrer apenas a pares do Python para simplificar o código
  return tag, iv


def verify(key, msg, tag):
  if not _validate_key_and_msg(key, msg): return False
  
  # If parameters are valid, then recalculate the mac.
  # Implement this recalculation.

  else:
    cipher = Cipher(algorithms.AES(key), modes.CBC(tag[1]))
    encry = cipher.encryptor()
    ct = encry.update(msg) + encry.finalize()

    new_tag = ct[-16: ]

    return new_tag == tag[0] # Vulnerable to timing attacks, bull will do for our purposes


## Realiza o xor de dois 
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

# Receives a pair consisting of a message, and a valid tag.
# Outputs a forged pair (message, tag), where message must be different from the
# received message (msg).

def produce_forgery(msg, tag):
    
    new_m1 = os.urandom(16) # Geramos um novo bloco inicial
    
    iv = tag[1] # IV original
    tag_original = tag[0] # Tag original

    m1 = msg[:16] # Primeiro bloco original
    other_blocks = msg[16:] # Restantes blocos da mensagem

    # Gerar uma nova tag compatível
    # Para tal, é preciso gerar um IV' = (new_m1 xor m1) xor iv, pois,
    # para cada bit modificado em new_m1 em relação a m1, temos de fazer flip do
    # mesmo bit no iv original
    # (new_m1 xor m1) dá 1 em todas as posições modificadas, e portanto, ao fazer xor
    # disso com o iv original, temos um novo iv' que corresponde ao flip dos bits nas
    # mesmas posições onde new_m1 é diferente de m1
    new_iv = byte_xor(byte_xor(new_m1, m1), iv)

    # A nova mensagem é igual a new_m1 || m2 || m3 || ...
    new_msg = new_m1 + other_blocks
    new_tag = (tag_original, new_iv) # A tag é (tag_original, new_iv)

    return (new_msg, new_tag)


def check_forgery(key, new_msg, new_tag, original_msg):
  if new_msg == original_msg:
    print("Having the \"forged\" message equal to the original " +
        "one is not allowed...")
    return False

  if verify(key, new_msg, new_tag) == True:
    print("MAC successfully forged!")
    return True
  else:
    print("MAC forgery attempt failed!")
    return False

def _validate_key_and_msg(key, msg):
  if type(key) is not bytes:
    print("Key must be array of bytes!")
    return False
  elif len(key) != AES_KEY_LENGTH:
    print("Key must be have %d bytes!" % AES_KEY_LENGTH)
    return False
  if type(msg) is not bytes:
    print("Msg must be array of bytes!")
    return False
  elif len(msg) != 2*AES_BLOCK_LENGTH:
    print("Msg must be have %d bytes!" % (2*AES_BLOCK_LENGTH))
    return False
  return True

def main():
  key = os.urandom(32)
  msg = os.urandom(32)

  tag = cbcmac(key, msg)

  # Should print "True".
  print(verify(key, msg, tag))

  (mprime, tprime) = produce_forgery(msg, tag)

  # GOAL: produce a (message, tag) that fools the verifier.
  check_forgery(key, mprime, tprime, msg)

if __name__ == '__main__':
  main()
