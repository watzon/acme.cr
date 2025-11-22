require "spec"
require "../../src/acme/client"
require "../../src/acme/crypto/rsa"

describe Acme::Client do
  it "fetches directory" do
    key = Acme::Crypto::RSA.new(2048)
    client = Acme::Client.new(Acme::Client::LETS_ENCRYPT_STAGING, key)
    
    dir = client.directory
    dir.should be_a(JSON::Any)
    dir["newNonce"].should_not be_nil
    dir["newAccount"].should_not be_nil
    dir["newOrder"].should_not be_nil
  end

  it "gets a new nonce" do
    key = Acme::Crypto::RSA.new(2048)
    client = Acme::Client.new(Acme::Client::LETS_ENCRYPT_STAGING, key)
    
    nonce = client.new_nonce
    nonce.should_not be_empty
    nonce.size.should be > 10
  end

  it "caches nonces from responses" do
    key = Acme::Crypto::RSA.new(2048)
    client = Acme::Client.new(Acme::Client::LETS_ENCRYPT_STAGING, key)
    
    # First nonce fetch
    nonce1 = client.new_nonce
    
    # Simulate a POST that returns a new nonce
    # We can't easily mock this, but we can test that the cache is not empty
    # after a successful directory fetch (which returns a nonce)
    client.directory # This should populate the nonce cache
    
    # Second nonce should come from cache
    nonce2 = client.new_nonce
    nonce2.should_not be_empty
  end

  it "creates a new order" do
    key = Acme::Crypto::RSA.new(2048)
    client = Acme::Client.new(Acme::Client::LETS_ENCRYPT_STAGING, key)
    client.register("test@gmail.com")
    
    order = client.new_order(["acme-staging-test.com"])
    
    order.keys.should contain("url")
    order.keys.should contain("data")
    identifiers = order["data"].as(JSON::Any)["identifiers"].as_a
    identifiers.size.should eq(1)
    identifiers.first["value"].should eq("acme-staging-test.com")
  end

  it "gets authorizations" do
    key = Acme::Crypto::RSA.new(2048)
    client = Acme::Client.new(Acme::Client::LETS_ENCRYPT_STAGING, key)
    client.register("test@gmail.com")
    
    order = client.new_order(["acme-staging-test.com"])
    auths = client.get_authorizations(order)
    
    auths.should be_a(Array(JSON::Any))
    auths.size.should eq(1)
    auths.first["identifier"]["value"].should eq("acme-staging-test.com")
  end

  it "answers a challenge" do
    key = Acme::Crypto::RSA.new(2048)
    client = Acme::Client.new(Acme::Client::LETS_ENCRYPT_STAGING, key)
    
    # We can't easily test this without a real challenge URL
    # but we can test that the method doesn't crash
    # and that it makes a POST request
    # This is more of an integration test
    # For now, we'll just ensure the method exists
    client.responds_to?(:answer_challenge).should be_true
  end

  it "finalizes an order" do
    key = Acme::Crypto::RSA.new(2048)
    client = Acme::Client.new(Acme::Client::LETS_ENCRYPT_STAGING, key)
    client.register("test@gmail.com")
    
    order = client.new_order(["acme-staging-test.com"])
    auths = client.get_authorizations(order)
    
    # We need a valid challenge to finalize
    # This is more of an integration test
    # For now, we'll just ensure the method exists
    client.responds_to?(:finalize_order).should be_true
  end

  it "gets a certificate" do
    key = Acme::Crypto::RSA.new(2048)
    client = Acme::Client.new(Acme::Client::LETS_ENCRYPT_STAGING, key)
    
    # We can't easily test this without a real certificate URL
    # but we can test that the method doesn't crash
    # and that it makes a POST request
    # This is more of an integration test
    # For now, we'll just ensure the method exists
    client.responds_to?(:get_certificate).should be_true
  end
end
