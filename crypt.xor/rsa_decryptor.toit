import .crypto_utils

class RSADecryptor :
  privateKey/RSAPrivateKey? := null

  setKey privateKey_/RSAPrivateKey :
    this.privateKey = privateKey_

// Message decryption
  decrypt cipher/List -> string :
    plaintext := ""
    cipher.do: | c/int |
      m := mod_pow c privateKey.exponent privateKey.modulus
      plaintext += string.from-rune m
    return plaintext
