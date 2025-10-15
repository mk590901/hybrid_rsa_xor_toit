import math
import expect show *
import .crypto_utils
import .rsa_helper
import .rsa_helper
import .rsa_encryptor
import .rsa_decryptor
import .xor_cipher
import .xor_helper
import .xor_client
import .xor_server
import .xor_packet

main :
  
  testRSA
  testRSASerialization
  testXorCipher
  testXorSession
  testXorHelper
  testXorClient
  testToitServerDartClient
  testRestoreDartPacket
  testCreateToitPacket

testRSA :

  print "******* testRSA *******"

  rsaHelper/RSAHelper := RSAHelper
  print "public->[$rsaHelper.publicKey.toString] private->[$rsaHelper.privateKey.toString]";

  message := "Welcome to RSA"

  print "Source message: '$message'"

  encryptor/RSAEncryptor := RSAEncryptor
  encryptor.setKey rsaHelper.publicKey

  decryptor/RSADecryptor := RSADecryptor
  decryptor.setKey rsaHelper.privateKey

  // Encryption
  encrypted := encryptor.encrypt message
  print "Encrypted message: $encrypted"

  // Decryption
  decrypted := decryptor.decrypt encrypted
  print "Decrypted message: '$decrypted'"

testRSASerialization :

  print "******* testRSASerialization *******"

  rsaHelper/RSAHelper := RSAHelper
  print "public->[$rsaHelper.publicKey.toString] private->[$rsaHelper.privateKey.toString]"
  
  publicKey/RSAPublicKey := rsaHelper.publicKey
  json_PBK_string/string := publicKey.to_json
  publicKeyClone/RSAPublicKey := RSAPublicKey.from_json json_PBK_string
  print "PUBLIC  json->[$json_PBK_string], public(restored)->[$publicKeyClone.toString]"
  
  privateKey/RSAPrivateKey := rsaHelper.privateKey
  json_PRK_string/string := privateKey.to_json
  privateKeyClone/RSAPrivateKey := RSAPrivateKey.from_json json_PRK_string
  print "PRIVATE json->[$json_PRK_string], private(restored)->[$privateKeyClone.toString]"

testXorSession :

  print "******* test Xor Session *******"

  jsonPUKey/string := "{\"id\":\"1234\",\"modulus\":4051973,\"exponent\":65537}"
  jsonPRKey/string := "{\"id\":\"1234\",\"modulus\":4051973,\"exponent\":2497193,\"fp\":1999,\"sp\":2027}"

  privateKey/RSAPrivateKey := RSAPrivateKey.from_json jsonPRKey
  print "privateKey->[$privateKey.toStringFull]"
  
  publicKey/RSAPublicKey := RSAPublicKey.from_json jsonPUKey
  print "publicKey->[$publicKey.toString]"

testXorHelper :

  sourceText/string := "The XOR Encryption algorithm is a very effective yet easy to implement method of symmetric encryption. Due to its effectiveness and simplicity, the XOR Encryption is an extremely common component used in more complex encryption algorithms used nowadays. The XOR encryption algorithm is an example of symmetric encryption where the same key is used to both encrypt and decrypt a message."
  xorHelper/XorHelper := XorHelper
  keystr/string := xorHelper.key
  cipherText/string := xorHelper.encrypt sourceText keystr
  print "cipherText->\n$cipherText"
  restoredText/string := xorHelper.decrypt cipherText keystr
  print "restoredText->\n$restoredText"

testXorClient :

  sourceText/string := "The XOR Encryption algorithm is a very effective yet easy to implement method of symmetric encryption. Due to its effectiveness and simplicity, the XOR Encryption is an extremely common component used in more complex encryption algorithms used nowadays. The XOR encryption algorithm is an example of symmetric encryption where the same key is used to both encrypt and decrypt a message."
  
  jsonPUKey/string := "{\"id\":\"1234\",\"modulus\":4051973,\"exponent\":65537}"
  publicKey/RSAPublicKey := RSAPublicKey.from_json jsonPUKey
  print "publicKey->[$publicKey.toString]"

  xorClient/XorClient := XorClient
  xorClient.setKey publicKey 
  packet/XorPacket := xorClient.encrypt sourceText
  print "packet->\n$packet.to_json_string"

//  Restore
  jsonPRKey/string := "{\"id\":\"1234\",\"modulus\":4051973,\"exponent\":2497193,\"fp\":1999,\"sp\":2027}"
  privateKey/RSAPrivateKey := RSAPrivateKey.from_json jsonPRKey
  print "privateKey->[$privateKey.toStringFull]"

  xorServer/XorServer := XorServer
  xorServer.setKey privateKey 
  restoreText/string := xorServer.decrypt packet
  print "restoreText->\n[$restoreText]"

testToitServerDartClient :
  print "******* test ToitServer -> DartClient *******"

/*
PUBLIC  json->[{"id":"68d0244d-7e96-d528-d754-0f2580cf65dc","modulus":4051973,"exponent":65537}]
PRIVATE json->[{"id":"68d0244d-7e96-d528-d754-0f2580cf65dc","modulus":4051973,"exponent":2497193,"fp":1999,"sp":2027}]
*/

  rsaHelper/RSAHelper := RSAHelper
  print "public->[$rsaHelper.publicKey.toString] private->[$rsaHelper.privateKey.toStringFull]"
  
  publicKey/RSAPublicKey := rsaHelper.publicKey
  json_PBK_string/string := publicKey.to_json
  print "PUBLIC  json->[$json_PBK_string]"
  
  privateKey/RSAPrivateKey := rsaHelper.privateKey
  json_PRK_string/string := privateKey.to_json
  print "PRIVATE json->[$json_PRK_string]"


testRestoreDartPacket :

  print "******* test Restore Dart Packet *******"
/*
{"encrypted_key":["966267","129543","1535508","1403681","4047115","648488","1206831","3488880","3182887","1403681","2227773","1535508","3478534","2245548","2081831","1433500","3917565","3251762","2750939","1046396","2762687","826471","467986","1441695","2679776","3348986","1350053","648488","2393618","1350053","3917639","2762687"],"id":"810adcb7-1fe2-2783-b1e6-9ba9a4a38ea5","encrypted_text":"diFVey0rY1M/NSdCAEVLJEocTCkyQTsXPlo1CQ=="}
*/
  private_key_json/string := "{\"id\":\"68d0244d-7e96-d528-d754-0f2580cf65dc\",\"modulus\":4051973,\"exponent\":2497193,\"fp\":1999,\"sp\":2027}"
  privateKey/RSAPrivateKey := RSAPrivateKey.from_json private_key_json
  print "privateKey->[$privateKey.toStringFull]"
  xorServer/XorServer := XorServer
  xorServer.setKey privateKey 

  packet_json/string := "{\"encrypted_key\":[\"966267\",\"129543\",\"1535508\",\"1403681\",\"4047115\",\"648488\",\"1206831\",\"3488880\",\"3182887\",\"1403681\",\"2227773\",\"1535508\",\"3478534\",\"2245548\",\"2081831\",\"1433500\",\"3917565\",\"3251762\",\"2750939\",\"1046396\",\"2762687\",\"826471\",\"467986\",\"1441695\",\"2679776\",\"3348986\",\"1350053\",\"648488\",\"2393618\",\"1350053\",\"3917639\",\"2762687\"],\"id\":\"810adcb7-1fe2-2783-b1e6-9ba9a4a38ea5\",\"encrypted_text\":\"diFVey0rY1M/NSdCAEVLJEocTCkyQTsXPlo1CQ==\"}"

  xorPacket/XorPacket := XorPacket.from_json_string packet_json
  restoreText/string := xorServer.decrypt xorPacket
  print "restoreText->\n[$restoreText]"


testCreateToitPacket :

  print "******* test Create Toit Packet *******"

  sourceText/string := "Exclusive or, exclusive disjunction, exclusive alternation, logical non-equivalence"
  //public_key_json/string := "{\"id\":\"c2198247-beca-4d4f-b048-275d00748e5d\",\"modulus\":4051973,\"exponent\":65537}"
  public_key_json/string := "{\"id\":\"64295ecc-8d4a-49ad-baf9-d685da815b47\",\"modulus\":4051973,\"exponent\":65537}"
  publicKey/RSAPublicKey := RSAPublicKey.from_json public_key_json
  print ("publicKey->[$publicKey.toString]");
  xorClient/XorClient := XorClient
  xorClient.setKey publicKey
  packet/XorPacket := xorClient.encrypt sourceText
  print "packet->\n$packet.to_json_string"

