require "spec"
require "../../src/acme/client"
require "../../src/acme/crypto/rsa"
require "../../src/acme/crypto/csr"

describe "Acme::Client (Development Mode)" do
  it "generates a self-signed certificate" do
    key = Acme::Crypto::RSA.new(2048)
    client = Acme::Client.new("dummy_url", key, development: true)

    # Register (should be no-op)
    client.register("test@example.com")

    # New Order
    domains = ["localhost", "127.0.0.1"]
    order = client.new_order(domains)
    order["url"].should eq("dev://order")

    # Get Authorizations
    auths = client.get_authorizations(order)
    auths.size.should eq(2)
    auths.first["identifier"]["value"].should eq("localhost")

    # Answer Challenge (no-op)
    client.answer_challenge("dev://challenge/localhost")

    # Finalize Order
    csr = Acme::Crypto::CSR.new(key, domains)
    finalize_url = order["data"].as(JSON::Any)["finalize"].as_s
    response = client.finalize_order(finalize_url, csr)

    # Get Certificate
    cert_body = JSON.parse(response.body)
    cert_url = cert_body["certificate"].as_s

    pem = client.get_certificate(cert_url)

    pem.should start_with("-----BEGIN CERTIFICATE-----")
    pem.should end_with("-----END CERTIFICATE-----\n")
  end
end
