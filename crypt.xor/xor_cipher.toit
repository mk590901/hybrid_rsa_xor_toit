import encoding.base64  // Assumed Toit crypto module for base64 encoding/decoding

class XorCipher :
  // Encrypts or decrypts the input using the provided key
  static process_ input/ByteArray key/ByteArray -> ByteArray :
    output := ByteArray input.size
    for i := 0; i < input.size; i++:
      // XOR each byte of input with the corresponding byte of the key
      output[i] = input[i] ^ key[i % key.size]
    return output

  // Encrypts the plaintext string using the key
  static encrypt plaintext/string key/string -> string :
    // Convert plaintext and key to byte arrays
    plain_bytes := plaintext.to_byte_array
    key_bytes := key.to_byte_array

    // Ensure key is not empty
    if key_bytes.size == 0:
      throw "Key cannot be empty"

    // Process encryption
    encrypted_bytes := process_ plain_bytes key_bytes
    
    // Encode to base64 for readable output
    return base64.encode encrypted_bytes //encrypted_bytes.to_base64

  // Decrypts the base64-encoded ciphertext using the key
  static decrypt ciphertext/string key/string -> string :
    // Decode base64 ciphertext
    cipher_bytes := base64.decode ciphertext //ByteArray.from_base64 ciphertext
    key_bytes := key.to_byte_array

    // Ensure key is not empty
    if key_bytes.size == 0:
      throw "Key cannot be empty"

    // Process decryption (same as encryption due to XOR properties)
    decrypted_bytes := process_ cipher_bytes key_bytes
    
    // Convert back to string
    return decrypted_bytes.to_string

testXorCipher :
  // Example usage
  plaintext := "Hello, this is a secret message!"
  key := "12345678901234567890123456789012"

  try:
    e := catch --trace=false :
    // Encrypt
      encrypted := XorCipher.encrypt plaintext key
      print "Encrypted (base64): $encrypted"

    // Decrypt
      decrypted := XorCipher.decrypt encrypted key
      print "Decrypted: $decrypted"
    if e :
      print "Exception: $e"    
  finally :
    print "final"