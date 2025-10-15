import encoding.json    //  Toit module for JSON encoding/decoding
import encoding.base64  //  Assumed Toit crypto module for base64 encoding/decoding

class XorPacket :
  encrypted_key/List ::= ?
  encrypted_key_id/string ::= ?
  encrypted_text/string ::= ?

  constructor .encrypted_key/List .encrypted_text/string .encrypted_key_id/string :

  to_json_string -> string :
    json_map := {
      "encrypted_key": encrypted_key.map: it.stringify,
      "id": encrypted_key_id,
      "encrypted_text": encrypted_text
    }
    return (json.encode json_map).to_string

  constructor.from_json_string json_string/string :

    decoded := json.decode json_string.to_byte_array

    before/string := decoded.get "encrypted_text"
    print "before->$before"
    
    encrypted_key = (decoded.get "encrypted_key").map : int.parse it
    encrypted_text = before //(decoded.get "encrypted_text")
    encrypted_key_id = decoded.get "id"