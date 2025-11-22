require "openssl"

begin
  puts "Testing RSA Generation..."
  rsa = OpenSSL::PKey::RSA.new(2048)
  puts "RSA Generated: #{rsa.private_key?}"
rescue e
  puts "RSA Gen Failed: #{e}"
end

begin
  puts "Testing EC Generation..."
  # Crystal stdlib might not have a nice wrapper for EC generation
  ec = OpenSSL::PKey::EC.new("prime256v1")
  ec.generate_key
  puts "EC Generated: #{ec.private_key?}"
rescue e
  puts "EC Gen Failed: #{e}"
end

begin
  puts "Testing CSR Generation..."
  # This is usually the missing part in high-level wrappers
  # There is no OpenSSL::X509::Request in standard docs usually
  req = OpenSSL::X509::Request.new
  puts "CSR Class exists"
rescue e
  puts "CSR Class missing: #{e}"
end
