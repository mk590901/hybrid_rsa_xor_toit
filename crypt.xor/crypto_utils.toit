import encoding.json    //  Toit module for JSON encoding/decoding
import encoding.base64  //  Assumed Toit crypto module for base64 encoding/decoding
import uuid show *

class RSAPrivateKey :
  modulus/int   // n
  exponent/int  // d
  p/int         // First prime
  q/int         // Second prime
  keyId/string  // uuid 

  constructor .modulus .exponent .p .q .keyId :

  toString -> string :
    return "[$keyId] $modulus,$exponent"

  toStringFull -> string :
    return "[$keyId] $modulus,$exponent,$p,$q"

  to_json -> string :
    return "{\"id\":\"$keyId\",\"modulus\":$modulus,\"exponent\":$exponent,\"fp\":$p,\"sp\":$q}"
  
  //  Construct RSAPublicKey from JSON string
  constructor.from_json json_string/string :
    parsed    := json.parse json_string
    modulus   := parsed["modulus"]
    exponent  := parsed["exponent"]
    p         := parsed["fp"]
    q         := parsed["sp"]
    keyId     := parsed["id"]

    return RSAPrivateKey modulus exponent p q keyId

class RSAPublicKey :
  modulus/int   // n
  exponent/int  // e
  keyId/string  // uuid 

  constructor .modulus .exponent .keyId :

  //  Convert RSAPublicKey to JSON string
  to_json -> string :
    return "{\"id\":\"$keyId\",\"modulus\":$modulus,\"exponent\":$exponent}"
  
  //  Construct RSAPublicKey from JSON string
  constructor.from_json json_string/string :
    parsed    := json.parse json_string
    modulus   := parsed["modulus"]
    exponent  := parsed["exponent"]
    keyId     := parsed["id"]

    return RSAPublicKey modulus exponent keyId

  toString -> string :
    return "[$keyId] $modulus,$exponent"

class RSAKeyPair :
  
  publicKey/RSAPublicKey
  privateKey/RSAPrivateKey

  constructor .publicKey .privateKey :

// Modular exponentiation
mod_pow base/int exp/int mod/int -> int :
  result := 1
  base = base % mod
  while exp > 0:
    if exp & 1 == 1:
      result = (result * base) % mod
    exp = exp >> 1
    base = (base * base) % mod
  return result

// Random string generation
generate_random_string length/int -> string :
  chars := "~`!@#\$%^&*()_-=+<>?/,.\"{}[]|abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  result := ""
  
  length.repeat :
    result += string.from-rune chars[random_ chars.size]
  
  return result

// Random number generator
random_ max/int -> int :
  return (random max).to_int

// String to ByteArray
uint8 text/string -> ByteArray :
  return text.to_byte_array
