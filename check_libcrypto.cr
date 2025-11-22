require "openssl"

# Check if LibCrypto is defined
puts "LibCrypto defined: #{defined?(LibCrypto)}"

# Try to access a common function to see if it's bound
# We'll try to define a missing one to see if it compiles
lib LibCrypto
  fun evp_pkey_new = EVP_PKEY_new : Void*
end

puts "LibCrypto extended successfully"
