require "spec"
require "../../src/acme/manager"

describe Acme::Manager do
  it "obtains a certificate in development mode" do
    manager = Acme::Manager.new(
      Acme::Client::LETS_ENCRYPT_STAGING,
      "test@example.com",
      ["example.com"],
      development: true
    )

    cert, key = manager.obtain_certificate

    cert.should contain("BEGIN CERTIFICATE")
    key.should contain("BEGIN RSA PRIVATE KEY")
  end
end
