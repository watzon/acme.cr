require "spec"
require "http"
require "../../src/acme/handler"
require "../../src/acme/challenge_store"

class ProcHandler
  include HTTP::Handler
  def initialize(&block : HTTP::Server::Context ->)
    @proc = block
  end
  def call(context)
    @proc.call(context)
  end
end

describe Acme::Handler do


  it "intercepts challenge requests" do
    store = Acme::ChallengeStore.new
    store.add("mytoken", "key-auth-value")
    
    handler = Acme::Handler.new(store)
    handler.next = ProcHandler.new { |ctx| ctx.response.print "Not intercepted" }
    
    request = HTTP::Request.new("GET", "/.well-known/acme-challenge/mytoken")
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    context = HTTP::Server::Context.new(request, response)
    
    handler.call(context)
    response.close
    
    io.rewind
    output = HTTP::Client::Response.from_io(io)
    
    output.body.should eq("key-auth-value")
    output.content_type.should eq("application/octet-stream")
  end

  it "passes through other requests" do
    store = Acme::ChallengeStore.new
    
    handler = Acme::Handler.new(store)
    handler.next = ProcHandler.new { |ctx| ctx.response.print "Passed through" }
    
    request = HTTP::Request.new("GET", "/other/path")
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    context = HTTP::Server::Context.new(request, response)
    
    handler.call(context)
    response.close
    
    io.rewind
    output = HTTP::Client::Response.from_io(io)
    
    output.body.should eq("Passed through")
  end

  it "passes through unknown tokens" do
    store = Acme::ChallengeStore.new
    
    handler = Acme::Handler.new(store)
    handler.next = ProcHandler.new { |ctx| ctx.response.print "Passed through" }
    
    request = HTTP::Request.new("GET", "/.well-known/acme-challenge/unknown")
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    context = HTTP::Server::Context.new(request, response)
    
    handler.call(context)
    response.close
    
    io.rewind
    output = HTTP::Client::Response.from_io(io)
    
    output.body.should eq("Passed through")
  end
end
