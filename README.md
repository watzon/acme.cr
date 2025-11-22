# acme.cr

[![Crystal shard](https://img.shields.io/badge/shard-acme-black.svg)](https://github.com/watzon/acme.cr)
[![Crystal](https://img.shields.io/badge/Crystal-1.0+-black?logo=crystal&labelColor=white)](https://crystal-lang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/watzon/acme.cr.svg)](https://github.com/watzon/acme.cr/releases)

> A native Crystal library for ACME v2 (Let's Encrypt), designed for programmatic usage and direct integration into web servers.

**acme.cr** is a pure Crystal implementation of the ACME v2 protocol (RFC 8555) that enables Crystal applications to programmatically request, renew, and manage SSL/TLS certificates from ACME providers like Let's Encrypt. Unlike CLI tools such as Certbot or Lego, `acme.cr` is designed to run *inside* your application process, enabling "on-the-fly" certificate generation and renewal without external dependencies.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
  - [Usage](#usage)
  - [Easy Mode (Recommended)](#easy-mode-recommended)
  - [Advanced Usage](#advanced-usage)
  - [Development Mode](#development-mode)
  - [Examples](#examples)
- [API Reference](#api-reference)
  - [Acme::Manager](#acmemanager)
  - [Acme::Client](#acmeclient)
  - [Acme::Crypto::RSA](#acmecryptorsa)
  - [Acme::Crypto::CSR](#acmecryptocsr)
  - [Acme::ChallengeStore](#acmechallengestore)
  - [Acme::Handler](#acmehandler)
- [Security](#security)
- [Contributing](#contributing)
- [Maintainers](#maintainers)
- [License](#license)

## Background

This library allows Crystal applications to programmatically request certificates from ACME providers like Let's Encrypt. It's particularly useful for:

- **Web servers** that want to automatically provision certificates
- **Containerized applications** that need to manage certificates without external dependencies
- **Development environments** that need self-signed certificates
- **Multi-domain applications** that require dynamic certificate management

The library includes:

- **Native Crypto:** RSA key generation and CSR creation using OpenSSL bindings (no external CLI deps)
- **ACME Client:** Full implementation of RFC 8555 (Account, Order, Challenge, Certificate)
- **HTTP Middleware:** `Acme::Handler` to automatically answer HTTP-01 challenges
- **Development Mode:** Built-in support for testing without hitting real ACME servers

## Install

Add this to your application's `shard.yml`:

```yaml
dependencies:
  acme:
    github: watzon/acme.cr
```

Then run:

```bash
shards install
```

## Usage

### Easy Mode (Recommended)

The easiest way to use `acme.cr` is via the `Acme::Manager` class, which handles the entire flow for you.

```crystal
require "acme"

# 1. Initialize Manager
manager = Acme::Manager.new(
  Acme::Client::LETS_ENCRYPT_STAGING, 
  "admin@example.com", 
  ["example.com"]
)

# 2. Add the handler to your HTTP server
server = HTTP::Server.new([manager.handler])

# 3. Obtain Certificate (blocks until done)
cert_pem, key_pem = manager.obtain_certificate

# 4. Use the certificate
puts "Got certificate!"
```

### Advanced Usage

For more control, you can use the low-level `Acme::Client` directly.

#### Basic Certificate Request

Here's a minimal example of requesting a certificate for a single domain:

```crystal
require "acme"

# 1. Generate an Account Key
account_key = Acme::Crypto::RSA.new(2048)

# 2. Initialize Client (using Let's Encrypt staging for testing)
client = Acme::Client.new(
  Acme::Client::LETS_ENCRYPT_STAGING,
  account_key
)

# 3. Register Account
client.register("admin@example.com")

# 4. Create Order for your domain
order = client.new_order(["example.com"])

# 5. Handle challenges (see HTTP-01 section below)
auths = client.get_authorizations(order)
# ... solve challenges ...

# 6. Generate CSR and finalize order
domain_key = Acme::Crypto::RSA.new(2048)
csr = Acme::Crypto::CSR.new(domain_key, ["example.com"])
client.finalize_order(order["data"]["finalize"].as_s, csr)

# 7. Download Certificate
cert_pem = client.get_certificate(order["data"]["certificate"].as_s)
```

#### HTTP-01 Challenge Handling

To automatically solve HTTP-01 challenges, use the `Acme::Handler` in your HTTP stack:

```crystal
require "acme"

# Create challenge store and handler
store = Acme::ChallengeStore.new
acme_handler = Acme::Handler.new(store)

# Add to your HTTP server
server = HTTP::Server.new([
  acme_handler,
  # ... your other handlers ...
])

server.bind_tcp 80
server.listen

# Later, when processing authorizations:
challenge = auths.first["challenges"].as_a.find { |c| c["type"] == "http-01" }
token = challenge["token"].as_s
key_authorization = "#{token}.#{account_key.thumbprint}"

# Store the challenge response
store.add_challenge(token, key_authorization)

# Notify ACME that the challenge is ready
client.answer_challenge(challenge["url"].as_s)

# Wait for validation...
sleep 5

# Clean up the challenge
store.remove_challenge(token)
```

### Development Mode

For testing without hitting real ACME servers, use development mode:

```crystal
# Enable development mode
client = Acme::Client.new(
  "https://acme-staging-v02.api.letsencrypt.org/directory",
  account_key,
  development: true
)

# In development mode, all HTTP calls are mocked
# and self-signed certificates are generated locally.
# Useful for unit tests and development.
```

### Examples

Check out the `examples/` directory for complete, runnable applications:

- **[server-easy.cr](examples/server-easy.cr)**: Uses `Acme::Manager` (Recommended)
- **[server-full.cr](examples/server-full.cr)**: Uses `Acme::Client` (Low-level)

### Complete Example (Low-level)

Here's a complete example showing the full certificate lifecycle:

```crystal
require "acme"

class CertificateManager
  def initialize
    @account_key = load_or_create_account_key
    @client = Acme::Client.new(
      ENV["ACME_ENV"] == "production" ?
        Acme::Client::LETS_ENCRYPT_PROD :
        Acme::Client::LETS_ENCRYPT_STAGING,
      @account_key
    )
    @challenge_store = Acme::ChallengeStore.new
  end

  def request_certificate(domain : String)
    # Register/retrieve account
    @client.register("admin@#{domain}") unless @client.kid

    # Create order
    order = @client.new_order([domain])

    # Handle authorizations
    auths = @client.get_authorizations(order)
    auths.each do |auth|
      handle_authorization(auth, domain)
    end

    # Generate CSR and finalize
    domain_key = Acme::Crypto::RSA.new(2048)
    csr = Acme::Crypto::CSR.new(domain_key, [domain])
    @client.finalize_order(order["data"]["finalize"].as_s, csr)

    # Download certificate
    cert_pem = @client.get_certificate(order["data"]["certificate"].as_s)

    # Save certificate and private key
    save_certificate(domain, cert_pem, domain_key.to_pem)
  end

  private def handle_authorization(auth, domain)
    challenge = auth["challenges"].as_a.find { |c| c["type"] == "http-01" }
    return unless challenge

    token = challenge["token"].as_s
    key_authorization = "#{token}.#{@account_key.thumbprint}"

    # Store challenge for HTTP validation
    @challenge_store.add_challenge(token, key_authorization)

    # Notify ACME
    @client.answer_challenge(challenge["url"].as_s)

    # Wait for validation
    sleep 5

    # Clean up
    @challenge_store.remove_challenge(token)
  end

  private def load_or_create_account_key
    # In a real app, you'd load this from storage
    Acme::Crypto::RSA.new(4096)
  end

  private def save_certificate(domain, cert_pem, key_pem)
    # Save to your preferred storage
    File.write("#{domain}.crt", cert_pem)
    File.write("#{domain}.key", key_pem)
  end
end

# Usage
manager = CertificateManager.new
manager.request_certificate("example.com")
```

## API Reference

### Acme::Manager

High-level manager for orchestrating certificate acquisition.

```crystal
manager = Acme::Manager.new(directory_url, email, domains)
```

**Methods:**
- `handler` - Returns an `Acme::Handler` for serving challenges
- `obtain_certificate` - Blocks until certificate is obtained, returns `{cert_pem, key_pem}`

### Acme::Client

The main ACME protocol client.

```crystal
client = Acme::Client.new(directory_url, account_key, development: false)
```

**Constants:**
- `LETS_ENCRYPT_STAGING` - Let's Encrypt staging environment
- `LETS_ENCRYPT_PROD` - Let's Encrypt production environment

**Methods:**
- `register(email : String)` - Register ACME account
- `new_order(domains : Array(String))` - Create new certificate order
- `get_authorizations(order)` - Get authorizations for an order
- `answer_challenge(challenge_url : String)` - Trigger challenge validation
- `finalize_order(finalize_url : String, csr : CSR)` - Submit CSR for certificate
- `get_certificate(certificate_url : String)` - Download issued certificate

### Acme::Crypto::RSA

RSA key generation and management.

```crystal
key = Acme::Crypto::RSA.new(bits : Int32 = 2048)
```

**Methods:**
- `to_pem` - Export key as PEM string
- `thumbprint` - Get key thumbprint for ACME challenges
- `sign(data : String)` - Sign data with private key

### Acme::Crypto::CSR

Certificate Signing Request generation.

```crystal
csr = Acme::Crypto::CSR.new(private_key, domains)
```

**Methods:**
- `to_pem` - Export CSR as PEM string

### Acme::ChallengeStore

In-memory store for HTTP-01 challenge responses.

```crystal
store = Acme::ChallengeStore.new
store.add_challenge(token, key_authorization)
store.get_challenge(token) # Returns key authorization
store.remove_challenge(token)
```

### Acme::Handler

HTTP handler for automatically serving HTTP-01 challenge responses.

```crystal
handler = Acme::Handler.new(challenge_store)

# Add to HTTP::Server
server = HTTP::Server.new([handler])
```

## Security

When implementing certificate management in production, consider these security practices:

1. **Key Storage:** Store account keys securely using proper encryption at rest
2. **Rate Limiting:** Implement client-side rate limiting to avoid ACME server limits
3. **Validation:** Always validate challenge responses before serving
4. **Renewal:** Implement automated renewal at least 30 days before expiration
5. **Monitoring:** Monitor certificate expiration and ACME API responses

### Security Best Practices

```crystal
# Use secure key storage
account_key = load_secure_key_from_vault()

# Implement rate limiting
if @last_request_time && Time.utc - @last_request_time < 1.second
  sleep 1 # Avoid rate limiting
end

# Validate domains before requesting certificates
unless valid_domain?(domain)
  raise "Invalid domain: #{domain}"
end

# Store certificates securely
save_certificate_with_proper_permissions(cert, key)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development

1. Fork the repository
2. Create your feature branch (`git checkout -b my-amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin my-amazing-feature`)
5. Open a Pull Request

### Testing

Run the test suite:

```bash
crystal spec
```

### Code Style

- Follow Crystal's official style guide
- Use meaningful variable and method names
- Add comments for complex logic
- Include examples in documentation

## Maintainers

- **[@watzon](https://github.com/watzon)** - creator and maintainer

## License

MIT © [Christopher Watson](https://github.com/watzon)

See [LICENSE](LICENSE) for the full license text.