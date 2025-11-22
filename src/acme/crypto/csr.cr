require "./lib_crypto"
require "./rsa"

module Acme
  module Crypto
    class CSR
      def initialize(@key : RSA, @domains : Array(String))
        raise ArgumentError.new("Must provide at least one domain") if @domains.empty?
      end

      def to_pem
        req = generate_req
        
        bio = LibCrypto.BIO_new(LibCrypto.bio_s_mem)
        if LibCrypto.pem_write_bio_x509_req(bio, req) != 1
          LibCrypto.bio_free_all(bio)
          LibCrypto.x509_req_free(req)
          raise "Failed to write CSR to PEM"
        end

        LibCrypto.x509_req_free(req)
        to_string(bio)
      end

      def to_der
        req = generate_req
        
        bio = LibCrypto.BIO_new(LibCrypto.bio_s_mem)
        if LibCrypto.i2d_x509_req_bio(bio, req) != 1
          LibCrypto.bio_free_all(bio)
          LibCrypto.x509_req_free(req)
          raise "Failed to write CSR to DER"
        end
        
        LibCrypto.x509_req_free(req)
        
        len = LibCrypto.bio_ctrl_ex(bio, LibCrypto::BIO_CTRL_PENDING, 0, nil)
        slice = Bytes.new(len)
        LibCrypto.bio_read_ex(bio, slice, len.to_i32)
        LibCrypto.bio_free_all(bio)
        slice
      end

      private def generate_req
        req = LibCrypto.x509_req_new
        
        # Set Version (0 = v1)
        LibCrypto.x509_req_set_version(req, 0)

        # Set Subject (CN)
        name = LibCrypto.x509_req_get_subject_name(req)
        cn = @domains.first
        if !LibCrypto.x509_name_add_entry_by_txt(
             name, "CN", LibCrypto::MBSTRING_UTF8, cn, -1, -1, 0
           )
           LibCrypto.x509_req_free(req)
           raise "Failed to set CN"
        end

        # Set Public Key
        pkey = LibCrypto.evp_pkey_new
        if LibCrypto.evp_pkey_set1_rsa(pkey, @key.rsa) != 1
          LibCrypto.evp_pkey_free(pkey)
          LibCrypto.x509_req_free(req)
          raise "Failed to assign RSA to EVP_PKEY"
        end
        
        if LibCrypto.x509_req_set_pubkey(req, pkey) != 1
          LibCrypto.evp_pkey_free(pkey)
          LibCrypto.x509_req_free(req)
          raise "Failed to set public key on CSR"
        end

        # Sign
        digest = LibCrypto.evp_sha256
        if LibCrypto.x509_req_sign(req, pkey, digest) == 0
          LibCrypto.evp_pkey_free(pkey)
          LibCrypto.x509_req_free(req)
          raise "Failed to sign CSR"
        end
        
        LibCrypto.evp_pkey_free(pkey)
        req
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
