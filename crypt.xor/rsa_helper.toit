import math
import uuid show *
import .crypto_utils
import .primes_generator

class RSAHelper :
  p_/int := 1999  // Prime number
  q_/int := 2027  // Prime number
  
  keyPair/RSAKeyPair? := null

  constructor :

    list/List := get_two_random_distinct_numbers
    p_ = list[0]
    q_ = list[1]
    
    keyPair = generateKeyPair p_ q_

  publicKey -> RSAPublicKey :
    return keyPair.publicKey

  privateKey -> RSAPrivateKey :
    return keyPair.privateKey

  // Generating a key pair
  generateKeyPair p/int q/int -> RSAKeyPair :
    if not is_prime p or not is_prime q :
      throw "p and q must be prime"

    n := p * q
    phi := (p - 1) * (q - 1)

  // Choosing e (usually 65537, as it is simple and efficient)
    e := 65537
    if (gcd e phi) != 1 :
      throw "e and phi must be coprime"

  // Calculating d (the modular inverse of e with respect to phi)
    d := mod_inverse e phi

    keyId/string            := Uuid.random.to_string
    publicKey/RSAPublicKey  := RSAPublicKey n e keyId
    privateKey/RSAPrivateKey:= RSAPrivateKey n d p q keyId

    return RSAKeyPair publicKey privateKey

// Checking if a number is prime (simplified)
  is_prime n/int -> bool :
    if n < 2: return false
    for i := 2; i <= (math.sqrt n); i++:
      if n % i == 0: return false
    return true

// Finding the GCD (to check mutual primality)
  gcd a/int b/int -> int :
    while b != 0 :
      temp := b
      b = a % b
      a = temp
    return a

// Modular inverse implementation
  mod_inverse a/int m/int -> int :
    m0 := m
    y := 0
    x := 1

    if m == 1 :
      return 0

    while a > 1:
      q := a / m
      t := m
      m = a % m
      a = t
      t = y
      y = x - q * y
      x = t

    if x < 0 :
      x += m0
    return x


