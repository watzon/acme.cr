require "spec"
require "../../../src/acme/crypto/rsa"

describe Acme::Crypto::RSA do
  it "generates a new RSA key" do
    key = Acme::Crypto::RSA.new(2048)
    key.should_not be_nil
  end

  it "exports private key to PEM" do
    key = Acme::Crypto::RSA.new(2048)
    pem = key.to_pem
    pem.should start_with("-----BEGIN RSA PRIVATE KEY-----")
    pem.should end_with("-----END RSA PRIVATE KEY-----\n")
  end

  it "exports public key to PEM" do
    key = Acme::Crypto::RSA.new(2048)
    pem = key.public_to_pem
    pem.should start_with("-----BEGIN PUBLIC KEY-----")
    pem.should end_with("-----END PUBLIC KEY-----\n")
  end

  it "exports to JWK" do
    key = Acme::Crypto::RSA.new(2048)
    jwk = key.to_jwk
    jwk[:kty].should eq("RSA")
    jwk[:n].should_not be_empty
    jwk[:e].should eq("AQAB")
  end

  it "calculates thumbprint" do
    key = Acme::Crypto::RSA.new(2048)
    tp = key.thumbprint
    tp.should_not be_empty
  end

  it "signs data" do
    key = Acme::Crypto::RSA.new(2048)
    data = "Hello World"
    sig = key.sign(data)
    sig.size.should eq(256) # 2048 bits = 256 bytes
  end

  it "produces consistent signatures" do
    key = Acme::Crypto::RSA.new(2048)
    data = "Hello World"
    sig1 = key.sign(data)
    sig2 = key.sign(data)
    sig1.should eq(sig2)
  end

  it "produces different signatures for different data" do
    key = Acme::Crypto::RSA.new(2048)
    sig1 = key.sign("Hello World")
    sig2 = key.sign("Goodbye World")
    sig1.should_not eq(sig2)
  end
end
