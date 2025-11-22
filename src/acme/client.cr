require "http/client"
require "json"
require "./jws"
require "./crypto/rsa"
require "./crypto/self_signed"

module Acme
  class Client
    LETS_ENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
    LETS_ENCRYPT_PROD    = "https://acme-v02.api.letsencrypt.org/directory"

    getter kid : String?

    def initialize(@directory_url : String, @account_key : Crypto::RSA, @development : Bool = false)
      @jws = JWS.new(@account_key)
      @directory = nil
      @nonces = [] of String
    end

    def directory
      return JSON.parse(%({"newNonce": "dev", "newAccount": "dev", "newOrder": "dev"})) if @development

      @directory ||= begin
        response = HTTP::Client.get(@directory_url)
        raise "Failed to fetch directory: #{response.status_code}" unless response.success?
        JSON.parse(response.body)
      end
    end

    def new_nonce
      return "dev-nonce" if @development
      return @nonces.pop if @nonces.any?

      url = directory["newNonce"].as_s
      response = HTTP::Client.head(url)
      nonce = response.headers["Replay-Nonce"]?
      raise "Failed to get nonce" unless nonce
      nonce
    end

    def post(url : String, payload : Hash | Nil)
      return HTTP::Client::Response.new(200, "{}") if @development && url.starts_with?("dev")

      # Retry loop for badNonce
      3.times do
        nonce = new_nonce
        jws_data = @jws.sign(payload ? payload.to_json : nil, url, nonce, @kid)

        response = HTTP::Client.post(
          url,
          headers: HTTP::Headers{"Content-Type" => "application/jose+json"},
          body: jws_data.to_json
        )

        # Save nonce for next time
        if new_nonce = response.headers["Replay-Nonce"]?
          @nonces << new_nonce
        end

        if response.status_code == 400
          begin
            body = JSON.parse(response.body)
            if body["type"]? == "urn:ietf:params:acme:error:badNonce"
              # Retry
              next
            end
          rescue
            # Not JSON or other error
          end
        end

        return response
      end
      raise "Failed to post after retries (badNonce)"
    end

    def register(email : String)
      if @development
        @kid = "dev-kid"
        return JSON.parse("{}")
      end

      payload = {
        "termsOfServiceAgreed" => true,
        "contact"              => ["mailto:#{email}"],
      }

      url = directory["newAccount"].as_s
      response = post(url, payload)

      if response.success? || response.status_code == 409 # 409 = already exists
        @kid = response.headers["Location"]
        return JSON.parse(response.body)
      else
        raise "Registration failed: #{response.body}"
      end
    end

    def new_order(domains : Array(String))
      if @development
        return {
          "url"  => "dev://order",
          "data" => JSON.parse({
            "identifiers"    => domains.map { |d| {"type" => "dns", "value" => d} },
            "authorizations" => domains.map { |d| "dev://auth/#{d}" },
            "finalize"       => "dev://finalize?domains=#{domains.join(",")}",
          }.to_json),
        }
      end

      payload = {
        "identifiers" => domains.map { |d| {"type" => "dns", "value" => d} },
      }

      url = directory["newOrder"].as_s
      response = post(url, payload)

      if response.success?
        order = JSON.parse(response.body)
        {
          "url"  => response.headers["Location"],
          "data" => order,
        }
      else
        raise "New Order failed: #{response.body}"
      end
    end

    def get_order(order_url : String)
      if @development
        # In dev mode, we assume it's always valid for simplicity,
        # or we could track state. For now, return a valid order with a dummy cert URL.
        # We need to try to extract domains if possible, but for dev mode
        # the cert URL generation in finalize_order is what matters.
        # Here we just return a state that lets the client proceed.
        return JSON.parse({
          "status"      => "valid",
          "certificate" => "dev://cert?domains=example.com",
        }.to_json)
      end

      response = post(order_url, nil) # POST-as-GET
      raise "Failed to get order" unless response.success?
      JSON.parse(response.body)
    end

    def get_authorizations(order)
      if @development
        return order["data"].as(JSON::Any)["authorizations"].as_a.map do |auth_url|
          domain = auth_url.as_s.split("/").last
          JSON.parse({
            "url"        => auth_url.as_s,
            "identifier" => {"type" => "dns", "value" => domain},
            "status"     => "pending",
            "challenges" => [
              {"type" => "http-01", "url" => "dev://challenge/#{domain}", "token" => "dev-token"},
            ],
          }.to_json)
        end
      end

      auth_urls = order["data"].as(JSON::Any)["authorizations"].as_a.map(&.as_s)
      auth_urls.map do |url|
        response = post(url, nil) # POST-as-GET
        raise "Failed to fetch authz" unless response.success?

        # We need to inject the URL into the response so the manager can use it for polling
        auth = JSON.parse(response.body)
        if auth.as_h?
          auth.as_h["url"] = JSON::Any.new(url)
        end
        auth
      end
    end

    def answer_challenge(challenge_url : String)
      return if @development
      post(challenge_url, {} of String => String)
    end

    def finalize_order(finalize_url : String, csr : Crypto::CSR)
      if @development
        # Extract domains from finalize_url
        if finalize_url =~ /domains=(.+)/
          domains = $1
          # Return a dummy response that points to a certificate URL containing the domains
          return HTTP::Client::Response.new(200, {
            "certificate" => "dev://cert?domains=#{domains}",
          }.to_json)
        end
      end

      der = csr.to_der
      payload = {
        "csr" => Base64.urlsafe_encode(der, padding: false),
      }

      post(finalize_url, payload)
    end

    def get_certificate(cert_url : String)
      if @development
        if cert_url =~ /domains=(.+)/
          domains = $1.split(",")
          # Generate self-signed cert
          generator = Crypto::SelfSigned.new(@account_key, domains)
          return generator.to_pem
        end
      end

      response = post(cert_url, nil) # POST-as-GET
      raise "Failed to get cert" unless response.success?
      response.body
    end
  end
end
