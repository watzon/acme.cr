module Acme
  class ChallengeStore
    def initialize
      @challenges = {} of String => String
    end

    def add(token : String, key_authorization : String)
      @challenges[token] = key_authorization
    end

    def get(token : String)
      @challenges[token]?
    end
    
    def remove(token : String)
      @challenges.delete(token)
    end
  end
end
