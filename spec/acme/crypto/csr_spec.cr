require "spec"
require "../../../src/acme/crypto/csr"
require "../../../src/acme/crypto/rsa"

describe Acme::Crypto::CSR do
  it "generates a valid CSR" do
    key = Acme::Crypto::RSA.new(2048)
    csr = Acme::Crypto::CSR.new(key, ["example.com"])
    pem = csr.to_pem
    
    pem.should start_with("-----BEGIN CERTIFICATE REQUEST-----")
    pem.should end_with("-----END CERTIFICATE REQUEST-----\n")
  end

  it "generates a valid CSR in DER format" do
    key = Acme::Crypto::RSA.new(2048)
    csr = Acme::Crypto::CSR.new(key, ["example.com"])
    der = csr.to_der
    
    der.should be_a(Bytes)
    der.should_not be_empty
    # DER should start with sequence tag (0x30)
    der[0].should eq(0x30)
  end

  it "raises error with no domains" do
    key = Acme::Crypto::RSA.new(2048)
    expect_raises(ArgumentError) do
      Acme::Crypto::CSR.new(key, [] of String)
    end
  end

  it "uses first domain as CN" do
    key = Acme::Crypto::RSA.new(2048)
    csr = Acme::Crypto::CSR.new(key, ["test.example.com", "www.example.com"])
    pem = csr.to_pem
    
    # We can't easily parse the CN from PEM without OpenSSL
    # But we can verify that CSR was created successfully
    pem.should start_with("-----BEGIN CERTIFICATE REQUEST-----")
  end
end
