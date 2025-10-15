import .rsa_encryptor
import .crypto_utils
import .xor_packet
import .xor_helper

class XorClient :

  encryptor/RSAEncryptor ::= RSAEncryptor
  xor_helper/XorHelper ::= XorHelper

  setKey public_key/RSAPublicKey -> none :
    encryptor.setKey public_key

  encrypt text/string -> XorPacket :
    keystr := xor_helper.key
    encrypted_key := encryptor.encrypt keystr
    return XorPacket encrypted_key (xor_helper.encrypt text keystr) encryptor.publicKey.keyId