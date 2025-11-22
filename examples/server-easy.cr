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

puts "--- ACME Example Server (Easy Mode) ---"
puts "Domain: #{domain}"
puts "Email:  #{email}"
puts "Env:    #{staging ? "Staging" : "Production"}"
puts "---------------------------"

# 1. Initialize Manager
directory = staging ? Acme::Client::LETS_ENCRYPT_STAGING : Acme::Client::LETS_ENCRYPT_PROD
manager = Acme::Manager.new(directory, email, [domain])

# 2. Start HTTP Server for Challenges (Port 80)
spawn do
  http_server = HTTP::Server.new([manager.handler]) do |context|
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

# 3. Obtain Certificate
begin
  puts "Obtaining certificate..."
  cert_pem, key_pem = manager.obtain_certificate
  puts "Certificate obtained successfully!"

  # Save to disk
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
