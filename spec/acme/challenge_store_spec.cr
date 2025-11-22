require "spec"
require "../../src/acme/challenge_store"

describe Acme::ChallengeStore do
  it "stores and retrieves challenges" do
    store = Acme::ChallengeStore.new
    store.add("token1", "auth1")
    
    store.get("token1").should eq("auth1")
    store.get("token2").should be_nil
  end

  it "removes challenges" do
    store = Acme::ChallengeStore.new
    store.add("token1", "auth1")
    store.remove("token1")
    
    store.get("token1").should be_nil
  end
end
