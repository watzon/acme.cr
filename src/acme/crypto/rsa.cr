require "./lib_crypto"
require "base64"
require "openssl/digest"

module Acme
  module Crypto
    class RSA
      getter rsa : LibCrypto::RSA

      def initialize(bits : Int32 = 2048)
        @rsa = generate_rsa(bits)
      end

      def finalize
        LibCrypto.rsa_free(@rsa)
      end

      def to_jwk
        n = Pointer(Void).null.as(LibCrypto::BN)
        e = Pointer(Void).null.as(LibCrypto::BN)
        d = Pointer(Void).null.as(LibCrypto::BN)
        
        # RSA_get0_key returns internal pointers, we must not free them.
        LibCrypto.rsa_get0_key(@rsa, pointerof(n), pointerof(e), pointerof(d))
        
        {
          kty: "RSA",
          n: bn_to_b64(n),
          e: bn_to_b64(e)
        }
      end

      def thumbprint
        # RFC 7638
        # JSON canonicalization is simple for this subset: keys sorted lexicographically, no whitespace.
        jwk = to_jwk
        json = %({"e":"#{jwk[:e]}","kty":"RSA","n":"#{jwk[:n]}"})
        digest = OpenSSL::Digest.new("SHA256")
        digest.update(json)
        Base64.urlsafe_encode(digest.final, padding: false)
      end

      def sign(data : String)
        pkey = LibCrypto.evp_pkey_new
        if LibCrypto.evp_pkey_set1_rsa(pkey, @rsa) != 1
          LibCrypto.evp_pkey_free(pkey)
          raise "Failed to assign RSA to EVP_PKEY"
        end

        ctx = LibCrypto.evp_md_ctx_new
        digest = LibCrypto.evp_sha256
        
        if LibCrypto.evp_digest_sign_init(ctx, nil, digest, nil, pkey) != 1
          LibCrypto.evp_md_ctx_free(ctx)
          LibCrypto.evp_pkey_free(pkey)
          raise "Failed to init sign"
        end

        if LibCrypto.evp_digest_sign_update(ctx, data, data.bytesize) != 1
          LibCrypto.evp_md_ctx_free(ctx)
          LibCrypto.evp_pkey_free(pkey)
          raise "Failed to update sign"
        end

        siglen = 0
        # First call to get length
        if LibCrypto.evp_digest_sign_final(ctx, nil, pointerof(siglen)) != 1
          LibCrypto.evp_md_ctx_free(ctx)
          LibCrypto.evp_pkey_free(pkey)
          raise "Failed to get sign length"
        end

        sig = Bytes.new(siglen)
        if LibCrypto.evp_digest_sign_final(ctx, sig, pointerof(siglen)) != 1
          LibCrypto.evp_md_ctx_free(ctx)
          LibCrypto.evp_pkey_free(pkey)
          raise "Failed to sign"
        end

        LibCrypto.evp_md_ctx_free(ctx)
        LibCrypto.evp_pkey_free(pkey)
        
        sig
      end

      def to_pem
        bio = LibCrypto.BIO_new(LibCrypto.bio_s_mem)
        if LibCrypto.pem_write_bio_rsaprivatekey(bio, @rsa, nil, nil, 0, nil, nil) != 1
          LibCrypto.bio_free_all(bio)
          raise "Failed to write RSA private key to PEM"
        end
        to_string(bio)
      end

      def public_to_pem
        pkey = LibCrypto.evp_pkey_new
        if LibCrypto.evp_pkey_set1_rsa(pkey, @rsa) != 1
          LibCrypto.evp_pkey_free(pkey)
          raise "Failed to assign RSA to EVP_PKEY"
        end

        bio = LibCrypto.BIO_new(LibCrypto.bio_s_mem)
        if LibCrypto.pem_write_bio_pubkey(bio, pkey) != 1
          LibCrypto.bio_free_all(bio)
          LibCrypto.evp_pkey_free(pkey)
          raise "Failed to write public key to PEM"
        end

        LibCrypto.evp_pkey_free(pkey)
        to_string(bio)
      end

      private def generate_rsa(bits)
        rsa = LibCrypto.rsa_new
        bn = LibCrypto.bn_new
        
        LibCrypto.bn_set_word(bn, 65537)

        if LibCrypto.rsa_generate_key_ex(rsa, bits, bn, nil) != 1
          LibCrypto.bn_free(bn)
          LibCrypto.rsa_free(rsa)
          raise "Failed to generate RSA key"
        end

        LibCrypto.bn_free(bn)
        rsa
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

      private def bn_to_b64(bn : LibCrypto::BN)
        return "" if bn.null?
        bits = LibCrypto.bn_num_bits(bn)
        len = (bits + 7) // 8
        slice = Bytes.new(len)
        LibCrypto.bn_bn2bin(bn, slice)
        Base64.urlsafe_encode(slice, padding: false)
      end
    end
  end
end
