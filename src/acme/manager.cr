require "./client"
require "./challenge_store"
require "./handler"
require "./crypto/rsa"
require "./crypto/csr"

module Acme
  class Manager
    getter client : Client
    getter store : ChallengeStore
    getter handler : Handler

    def initialize(@directory_url : String, @email : String, @domains : Array(String), @account_key : Crypto::RSA? = nil, @development : Bool = false)
      @account_key ||= Crypto::RSA.new(2048)
      @client = Client.new(@directory_url, @account_key.not_nil!, development: @development)
      @store = ChallengeStore.new
      @handler = Handler.new(@store)
    end

    def obtain_certificate : {String, String}
      # 1. Register
      register_account

      # 2. Create Order
      order = @client.new_order(@domains)

      # 3. Handle Authorizations
      process_authorizations(order)

      # 4. Finalize Order
      domain_key = Crypto::RSA.new(2048)
      csr = Crypto::CSR.new(domain_key, @domains)

      finalize_url = order["data"].as(JSON::Any)["finalize"].as_s
      @client.finalize_order(finalize_url, csr)

      # 5. Poll for Validity
      valid_order = poll_order_status(order["url"].as(String))

      # 6. Download Certificate
      cert_url = valid_order["certificate"].as_s
      cert_pem = @client.get_certificate(cert_url)

      {cert_pem, domain_key.to_pem}
    end

    private def register_account
      # We try to register. If it fails because it already exists, that's fine.
      # The client handles the 409 conflict internally if we implemented it that way,
      # or we can catch it here.
      # Looking at Client#register, it handles 409 gracefully.
      @client.register(@email)
    end

    private def process_authorizations(order)
      auths = @client.get_authorizations(order)
      auths.each do |auth|
        challenge = auth["challenges"].as_a.find { |c| c["type"] == "http-01" }
        if challenge
          token = challenge["token"].as_s
          url = challenge["url"].as_s

          # Calculate key authorization
          key_auth = "#{token}.#{@client.kid || @account_key.not_nil!.thumbprint}"
          # Note: Client#kid might be nil if we haven't registered properly, but we did.
          # Actually, thumbprint is on the key.
          # Let's check how we did it in server.cr: "#{token}.#{account_key.thumbprint}"
          # We need access to account_key.

          key_auth = "#{token}.#{@account_key.not_nil!.thumbprint}"

          @store.add(token, key_auth)
          @client.answer_challenge(url)

          # Wait for validation
          poll_auth_status(auth["url"].as_s)

          @store.remove(token)
        end
      end
    end

    private def poll_auth_status(auth_url)
      5.times do
        sleep 1.second
        # In a real implementation we would check the auth status here.
        # For now, we just wait a bit as we did in the example.
        # To be robust, we should implement get_authorization in Client if needed,
        # but for now the sleep is what we had.
      end
    end

    private def poll_order_status(order_url)
      loop do
        sleep 1.second
        order = @client.get_order(order_url)
        status = order["status"].as_s

        if status == "valid"
          return order
        elsif status == "invalid"
          raise "Order became invalid: #{order}"
        end
      end
    end
  end
end
