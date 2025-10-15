# HYBRID-RSA-XOR-TOIT
Below is a set of classes for implementing a hybrid message encryption method.

## Introduction
Represented message encryption uses a combination of asymmetric and symmetric encryption methods:

• The server generates public and private keys using the __RSA__ algorithm. The public key is sent to the client.

• On the client, the message is encrypted using an __XOR cipher__ with a random key. The random key is then encrypted with the open __RSA public key__, and a packet containing the encrypted key and the text is sent to the server.

• The server decodes the random key using the secret __RSA private key__ and uses it to recover the text sent by the client.

## Note:
The __TOIT__ crypt library currently does not implement asymmetric encryption algorithms such as __RSA (Rivest-Shamir-Adleman)__, __DSA (Digital Signature Algorithm)__ or __ECC (Elliptic Curve Cryptography)__ although this is planned. So I implemented __RSA method__ from scratch, at least partially: it lacks __OAEP-padding__, so calling this implementation compatible with libraries like __pointycastle__ (https://pub.dev/packages/pointycastle) for __Dart__ is too bold, and really simply impossible. It's simply a some basic implementation. A primitive __xor method__ was chosen for symmetric encoding. These same algorithms were implemented in the https://github.com/mk590901/hybrid_rsa_xor_dart/ project in the __Dart__ language. This mirror solution allows for a relatively secure __dart-to-toit__, __toit-to-dart__, __dart-to-dart__, __toit-to-toit__ communication channel. In reality, of course, standard, fully compatible, and platform-independent, complete and secure __asymmetric__ encoding algorithms like __RSA__ and __ECC__, and __symmetric__ encoding algorithms like __Salsa__, __ChaCha__, etc. should be used. But this is by no means a trivial task (I mean __multi-platform__ and __multi-language compatibility__), and I don't expect it to be solved anytime soon, although miracles are possible.

## Project goal
It was important for me to create an environment and develop a method for encoding and decoding hybrid messages for future apps.

## Run app
```
micrcx@micrcx-desktop:~/toit/crypt.xor$ jag -d midi run runner.toit
Scanning for device with name: 'midi'
Running 'runner.toit' on 'midi' ...
Success: Sent 53KB code to 'midi' in 1.54s
micrcx@micrcx-desktop:~/toit/crypt.xor$ 
```
## Output (monitoring)
```
[jaguar] INFO: program 07fa4a00-79e7-b4ea-f67c-01077416f89f started
******* testRSA *******
public->[[06dbf8e7-0de0-aa0b-ed11-0a1862f1714f] 5459969,65537] private->[[06dbf8e7-0de0-aa0b-ed11-0a1862f1714f] 5459969,3936833]
Source message: 'Welcome to RSA'
Encrypted message: [2848411, 4061281, 904860, 4439571, 2081374, 234793, 4061281, 4947183, 151589, 2081374, 4947183, 4134058, 1680769, 1345956]
Decrypted message: 'Welcome to RSA'
******* testRSASerialization *******
public->[[ff209e93-1604-7aa9-d7ac-8c85a8d005f2] 5387287,65537] private->[[ff209e93-1604-7aa9-d7ac-8c85a8d005f2] 5387287,827473]
PUBLIC  json->[{"id":"ff209e93-1604-7aa9-d7ac-8c85a8d005f2","modulus":5387287,"exponent":65537}], public(restored)->[[ff209e93-1604-7aa9-d7ac-8c85a8d005f2] 5387287,65537]
PRIVATE json->[{"id":"ff209e93-1604-7aa9-d7ac-8c85a8d005f2","modulus":5387287,"exponent":827473,"fp":2441,"sp":2207}], private(restored)->[[ff209e93-1604-7aa9-d7ac-8c85a8d005f2] 5387287,827473]
Encrypted (base64): eVdfWFoaF0xRWUISWkcVVxdLXFNDV0cUWFNES1hXVBM=
Decrypted: Hello, this is a secret message!
final
******* test Xor Session *******
privateKey->[[1234] 4051973,2497193,1999,2027]
publicKey->[[1234] 4051973,65537]
cipherText->
P1EUWSIROVcvRk43NlZBGR1aVyY4ITgIJEcAXUo6H3QKGQccCCdLEgxOSCY7T0MVUk0SM3QjNgk0ExxfSjoBJAdcHBwUKksaD1xFKisGWhZSRw4qOSMjCCRQSFUEMB4tG00YFhRwSzMfTQ0xIAZcBAEUEiEyIzQOJEUNXg8gH3QKVxVZCTcGBwZBTiw7XxlQBlwSZwwJBVoIXQtCEyMYPQRXURAJfgoZSk1VMT1DWBUeTVckOys6FSMTC18HIwM6DlcFWQ8tDhNKQUNlIklHFVJXGCokKjICbVYGUxgqHCACVh9ZGzIMGBhBWS0iVRUFAVETZzopIBspUhFDRHM4PA4ZKTYofg4ZCVpUNTtPWh5SVRsgOzQ+DiVeSFkZcw06S1wJGBcuBxJKR0tlPF9YHRdABS43ZjIULkERQB46AzpLThkcCDtLAwJNDTYuS1BQGVEOZz01dw8+VgwQHjxMNgRNGVkfMAgFE1hZZS5IUVAWURQ1LTYjWiwTBVUZIA0zDhc=
restoredText->
The XOR Encryption algorithm is a very effective yet easy to implement method of symmetric encryption. Due to its effectiveness and simplicity, the XOR Encryption is an extremely common component used in more complex encryption algorithms used nowadays. The XOR encryption algorithm is an example of symmetric encryption where the same key is used to both encrypt and decrypt a message.
publicKey->[[1234] 4051973,65537]
packet->
{"encrypted_key":["2646326","826471","1898852","1535508","3348986","1206831","2640337","1312166","482117","1400819","2037648","1535508","1898852","648488","3348986","3693877","3876797","3235540","1258541","2236889","1898852","2640337","2219939","3917639","3488880","129543","2457218","2679776","1400819","1144420","3441342","3348986"],"id":"1234","encrypted_text":"fU4uEHZ+NAMKPi9CMhRaPxgOYFUnAQgaGj0LOnAuHg5IBj1VXEhGRik2KVM/DVgzVxklQGsDBhsKaRc4cC4AXkVDJlVARUZOKiQkXy9EQTBXEzlZJgMTGhoqQzI+JB9XWVIiX0AfRmc6NWxEJERHIgRAJVItAwQcGj8GOTU0Hg5ISC8QXVgLUyM5L1k/HQJ2AwglFBMpNUg2JwAlKTcZR0ZIa1ldEQdNbzU0RDkBQzMbGWBXJAsKBx1pADg9NwJATEg/EFtCA0dvOSIQJgtcM1cDL1k7CgIQUywNNCI+HVpASSUQT10BTD05OFgmFw4jBAUkFCUJEAkXKBokfmc5RkwGE398EQNNLCI1QD8NQThXASxTJBQOHBskQz4jZwxACUMzUUNBCkZvPyoQOB1DOxIUMl0oRgIGEDsaJyQuAkAJUSNVXFRGVyc1bEMqCUt2HAU5FCIVRx0ALAd3JChNTEZSIxBLXwVRNiA4ECoKSnYTBSNGMhYTSBJpDjIjNAxJTAg="}
privateKey->[[1234] 4051973,2497193,1999,2027]
restoreText->
[The XOR Encryption algorithm is a very effective yet easy to implement method of symmetric encryption. Due to its effectiveness and simplicity, the XOR Encryption is an extremely common component used in more complex encryption algorithms used nowadays. The XOR encryption algorithm is an example of symmetric encryption where the same key is used to both encrypt and decrypt a message.]
******* test ToitServer -> DartClient *******
public->[[b08d57f2-3e64-0069-4e34-e4d5377a1e44] 5318153,65537] private->[[b08d57f2-3e64-0069-4e34-e4d5377a1e44] 5318153,2173673,2371,2243]
PUBLIC  json->[{"id":"b08d57f2-3e64-0069-4e34-e4d5377a1e44","modulus":5318153,"exponent":65537}]
PRIVATE json->[{"id":"b08d57f2-3e64-0069-4e34-e4d5377a1e44","modulus":5318153,"exponent":2173673,"fp":2371,"sp":2243}]
******* test Restore Dart Packet *******
privateKey->[[68d0244d-7e96-d528-d754-0f2580cf65dc] 4051973,2497193,1999,2027]
before->diFVey0rY1M/NSdCAEVLJEocTCkyQTsXPlo1CQ==
restoreText->
[The XOR Encryption algorithm]
******* test Create Toit Packet *******
publicKey->[[64295ecc-8d4a-49ad-baf9-d685da815b47] 4051973,65537]
packet->
{"encrypted_key":["1934683","1046396","1144420","2245548","2081831","1898852","3671365","3087997","2197565","1898852","602866","2393618","1350053","602866","2457218","1338607","691187","1615810","329301","40368","2993555","1400819","1419559","3870663","1403681","482117","1898852","2640337","1350053","3087997","1206831","2081831"],"id":"64295ecc-8d4a-49ad-baf9-d685da815b47","encrypted_text":"ZDAkWUo4QQYra0QncQsGPjovBEs7JhtKPyY4DCgeUktIJykZHy5QEyI+WDwrTkMnNTcUSjwxCgM0IWdGMR9WVkIpKxVRJEZdKzpePCtKDyM3IBQ="}
[jaguar] INFO: program 07fa4a00-79e7-b4ea-f67c-01077416f89f stopped

```
