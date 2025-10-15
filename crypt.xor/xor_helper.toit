import .crypto_utils
import .xor_cipher

class XorHelper :
  cipher/XorCipher := XorCipher

  encrypt text/string key/string -> string? :
    result/string? := null
    try :
      e := catch --trace=false :  
        result = XorCipher.encrypt text key
      if e :
        print "Exception: $e"    
    finally :
    return result

  decrypt text/string key/string -> string? :
    result/string? := null
    try :
      e := catch --trace=false :  
        result = XorCipher.decrypt text key
      if e :
        print "Exception: $e"    
    finally :
    return result

  key -> string :
    return generate_random_string 32