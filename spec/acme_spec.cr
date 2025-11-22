require "spec"
require "../src/acme"

describe Acme do
  it "has a version" do
    # This test ensures the module can be required
    # and basic constants are accessible
    Acme::Client::LETS_ENCRYPT_STAGING.should_not be_empty
    Acme::Client::LETS_ENCRYPT_PROD.should_not be_empty
  end
end
