require "json"
require "base64"
require "./crypto/rsa"

module Acme
  class JWS
    def initialize(@key : Crypto::RSA)
    end

    def sign(payload : String | Nil, url : String, nonce : String, kid : String? = nil)
      # Header
      header = Hash(String, String | NamedTuple(kty: String, n: String, e: String)).new
      header["alg"] = "RS256"
      header["nonce"] = nonce
      header["url"] = url

      if kid
        header["kid"] = kid
      else
        header["jwk"] = @key.to_jwk
      end

      protected_header = Base64.urlsafe_encode(header.to_json, padding: false)
      
      # Payload
      payload_b64 = if payload
                      Base64.urlsafe_encode(payload, padding: false)
                    else
                      ""
                    end

      # Signature Input
      signing_input = "#{protected_header}.#{payload_b64}"
      
      # Sign
      signature = @key.sign(signing_input)
      signature_b64 = Base64.urlsafe_encode(signature, padding: false)

      {
        "protected" => protected_header,
        "payload" => payload_b64,
        "signature" => signature_b64
      }
    end
  end
end
