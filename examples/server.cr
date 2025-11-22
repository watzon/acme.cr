require "../src/acme"
require "http/server"
require "option_parser"

# Configuration
domain = "example.com"
email = "admin@example.com"
staging = true

OptionParser.parse do |parser|
  parser.banner = "Usage: server [arguments]"
  parser.on("-d DOMAIN", "--domain=DOMAIN", "Domain to provision") { |d| domain = d }
  parser.on("-e EMAIL", "--email=EMAIL", "Email for registration") { |e| email = e }
  parser.on("--prod", "Use Let's Encrypt Production") { staging = false }
  parser.on("-h", "--help", "Show this help") { puts parser; exit }
end

puts "--- ACME Example Server ---"
puts "Domain: #{domain}"
puts "Email:  #{email}"
puts "Env:    #{staging ? "Staging" : "Production"}"
puts "---------------------------"

# 1. Setup Challenge Store and Handler
store = Acme::ChallengeStore.new
acme_handler = Acme::Handler.new(store)

# 2. Start HTTP Server for Challenges (Port 80)
# We run this in a fiber so it doesn't block the ACME process
spawn do
  http_server = HTTP::Server.new([acme_handler]) do |context|
    # Redirect all other traffic to HTTPS if we were a real app
    # For now, just say hello
    context.response.content_type = "text/plain"
    context.response.print "Listening on HTTP (Port 80). Waiting for certificate..."
  end

  puts "Starting HTTP server on port 80..."
  begin
    http_server.bind_tcp "0.0.0.0", 80
    http_server.listen
  rescue ex
    puts "Error starting HTTP server: #{ex.message}"
    puts "Do you have permission to bind to port 80? (Try sudo)"
    exit 1
  end
end

# Give the server a moment to start
sleep 1.second

# 3. Run ACME Logic
begin
  puts "Generating account key..."
  account_key = Acme::Crypto::RSA.new(2048)

  puts "Initializing client..."
  directory = staging ? Acme::Client::LETS_ENCRYPT_STAGING : Acme::Client::LETS_ENCRYPT_PROD
  client = Acme::Client.new(directory, account_key)

  puts "Registering account..."
  client.register(email)

  puts "Creating order for #{domain}..."
  order = client.new_order([domain])

  puts "Fetching authorizations..."
  auths = client.get_authorizations(order)

  auths.each do |auth|
    challenge = auth["challenges"].as_a.find { |c| c["type"] == "http-01" }
    if challenge
      token = challenge["token"].as_s
      url = challenge["url"].as_s
      puts "Solving challenge for #{token}..."

      # Calculate key authorization
      key_auth = "#{token}.#{account_key.thumbprint}"

      # Add to store so the HTTP server can answer
      store.add(token, key_auth)

      # Tell ACME to verify
      client.answer_challenge(url)

      # Wait for validation
      puts "Waiting for validation..."
      5.times do |i|
        sleep 2.seconds
        # In a real app, you'd poll the auth status here.
        # For simplicity, we just wait a bit.
      end

      store.remove(token)
    end
  end

  puts "Finalizing order..."
  domain_key = Acme::Crypto::RSA.new(2048)
  csr = Acme::Crypto::CSR.new(domain_key, [domain])
  client.finalize_order(order["data"].as(JSON::Any)["finalize"].as_s, csr)

  puts "Waiting for order to be valid..."
  order_url = order["url"].as(String)
  loop do
    sleep 2.seconds
    current_order = client.get_order(order_url)
    status = current_order["status"].as_s
    puts "Order status: #{status}"

    if status == "valid"
      order["data"] = current_order
      break
    elsif status == "invalid"
      raise "Order became invalid: #{current_order}"
    end
  end

  puts "Downloading certificate..."
  cert_pem = client.get_certificate(order["data"].as(JSON::Any)["certificate"].as_s)
  key_pem = domain_key.to_pem

  puts "Certificate obtained successfully!"

  # Save to disk (optional, but good for checking)
  File.write("cert.pem", cert_pem)
  File.write("key.pem", key_pem)

  # 4. Start HTTPS Server (Port 443)
  puts "Starting HTTPS server on port 443..."

  ssl_context = OpenSSL::SSL::Context::Server.new
  ssl_context.certificate_chain = "cert.pem"
  ssl_context.private_key = "key.pem"

  https_server = HTTP::Server.new do |context|
    context.response.content_type = "text/html"
    context.response.print <<-HTML
      <html>
        <head><title>ACME Example</title></head>
        <body>
          <h1>It Works!</h1>
          <p>Served securely over HTTPS using a certificate from Let's Encrypt.</p>
          <p>Domain: #{domain}</p>
        </body>
      </html>
    HTML
  end

  https_server.bind_tls "0.0.0.0", 443, ssl_context
  https_server.listen
rescue ex
  puts "ACME Error: #{ex.message}"
  ex.backtrace.each { |l| puts l }
  exit 1
end
