import .rsa_decryptor
import .crypto_utils
import .xor_packet
import .xor_helper

class XorServer:
  decryptor/RSADecryptor ::= RSADecryptor
  xor_helper/XorHelper ::= XorHelper

  setKey private_key/RSAPrivateKey -> none :
    decryptor.setKey private_key

  decrypt data_packet/XorPacket -> string :
    decrypted_key := decryptor.decrypt data_packet.encrypted_key
    return xor_helper.decrypt data_packet.encrypted_text decrypted_key