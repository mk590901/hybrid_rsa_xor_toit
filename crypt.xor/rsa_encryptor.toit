import math
import .crypto_utils

class RSAEncryptor :
  publicKey/RSAPublicKey? := null

  setKey publicKey_/RSAPublicKey :
    this.publicKey = publicKey_

// Message encryption
  encrypt message/string -> List :
    cipher := []
    message.size.repeat :
      m := message[it].to_int
      cipher.add (mod_pow m publicKey.exponent publicKey.modulus)
    return cipher
