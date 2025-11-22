require "./lib_crypto"
require "./rsa"

module Acme
  module Crypto
    class SelfSigned
      def initialize(@key : RSA, @domains : Array(String))
        raise ArgumentError.new("Must provide at least one domain") if @domains.empty?
      end

      def to_pem
        x509 = generate_x509
        
        bio = LibCrypto.BIO_new(LibCrypto.bio_s_mem)
        if LibCrypto.pem_write_bio_x509(bio, x509) != 1
          LibCrypto.bio_free_all(bio)
          LibCrypto.x509_free(x509)
          raise "Failed to write Certificate to PEM"
        end

        LibCrypto.x509_free(x509)
        to_string(bio)
      end

      private def generate_x509
        x509 = LibCrypto.x509_new

        # Set Version (2 = v3)
        LibCrypto.x509_set_version(x509, 2)

        # Set Serial Number (random)
        LibCrypto.asn1_integer_set(LibCrypto.x509_get_serial_number(x509), Random.rand(1..1000000))

        # Set Validity (1 year)
        LibCrypto.x509_gmtime_adj(LibCrypto.x509_get_not_before(x509), 0)
        LibCrypto.x509_gmtime_adj(LibCrypto.x509_get_not_after(x509), 31536000) # 365 days

        # Set Subject and Issuer (Self-signed, so they are the same)
        name = LibCrypto.x509_get_subject_name(x509)
        cn = @domains.first
        LibCrypto.x509_name_add_entry_by_txt(name, "CN", LibCrypto::MBSTRING_UTF8, cn, -1, -1, 0)
        LibCrypto.x509_set_issuer_name(x509, name)

        # Set Public Key
        pkey = LibCrypto.evp_pkey_new
        LibCrypto.evp_pkey_set1_rsa(pkey, @key.rsa)
        LibCrypto.x509_set_pubkey(x509, pkey)

        # Sign
        digest = LibCrypto.evp_sha256
        if LibCrypto.x509_sign(x509, pkey, digest) == 0
          LibCrypto.evp_pkey_free(pkey)
          LibCrypto.x509_free(x509)
          raise "Failed to sign certificate"
        end

        LibCrypto.evp_pkey_free(pkey)
        x509
      end

      private def to_string(bio)
        len = LibCrypto.bio_ctrl_ex(bio, LibCrypto::BIO_CTRL_PENDING, 0, nil)
        str = String.new(len.to_i) do |buffer|
          LibCrypto.bio_read_ex(bio, buffer, len.to_i32)
          {len.to_i, 0}
        end
        LibCrypto.bio_free_all(bio)
        str
      end
    end
  end
end
