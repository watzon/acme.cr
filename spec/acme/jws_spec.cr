require "spec"
require "../../src/acme/jws"
require "../../src/acme/crypto/rsa"

describe Acme::JWS do
  it "signs a payload" do
    key = Acme::Crypto::RSA.new(2048)
    jws = Acme::JWS.new(key)
    
    result = jws.sign("{}", "https://example.com/acme/new-order", "nonce123")
    
    result["protected"].should_not be_empty
    result["payload"].should eq("e30") # Base64Url("{}")
    result["signature"].should_not be_empty
    
    # Verify header contains JWK (since no kid provided)
    header_json = Base64.decode_string(result["protected"])
    header = JSON.parse(header_json)
    header["jwk"].should_not be_nil
    header["alg"].should eq("RS256")
  end

  it "signs with kid" do
    key = Acme::Crypto::RSA.new(2048)
    jws = Acme::JWS.new(key)
    
    result = jws.sign("{}", "https://example.com", "nonce", kid: "my-account-url")
    
    header_json = Base64.decode_string(result["protected"])
    header = JSON.parse(header_json)
    header["jwk"]?.should be_nil
    header["kid"].should eq("my-account-url")
  end

  it "signs nil payload" do
    key = Acme::Crypto::RSA.new(2048)
    jws = Acme::JWS.new(key)
    
    result = jws.sign(nil, "https://example.com", "nonce")
    
    result["payload"].should eq("")
  end

  it "produces valid JWS structure" do
    key = Acme::Crypto::RSA.new(2048)
    jws = Acme::JWS.new(key)
    
    result = jws.sign("test", "https://example.com", "nonce")
    
    # Verify structure
    result.keys.should contain("protected")
    result.keys.should contain("payload")
    result.keys.should contain("signature")
    
    # Verify Base64Url encoding
    Base64.decode_string(result["payload"]).should eq("test")
  end
end
