require "http/server/handler"
require "./challenge_store"

module Acme
  class Handler
    include HTTP::Handler

    def initialize(@store : ChallengeStore)
    end

    def call(context)
      path = context.request.path
      if path.starts_with?("/.well-known/acme-challenge/")
        token = path.split("/").last
        if key_auth = @store.get(token)
          context.response.content_type = "application/octet-stream"
          context.response.print key_auth
          return
        end
      end
      call_next(context)
    end
  end
end
