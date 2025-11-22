require "openssl"

# Linked in the standard library already
# @[Link("crypto")]
lib LibCrypto
  type RSA = Void*
  type BN = Void*
  type EVP_PKEY = Void*
  type EVP_PKEY_CTX = Void*

  # RSA
  fun rsa_new = RSA_new : RSA
  fun rsa_free = RSA_free(rsa : RSA)
  fun rsa_generate_key_ex = RSA_generate_key_ex(rsa : RSA, bits : Int32, e : BN, cb : Void*) : Int32
  fun rsa_get0_key = RSA_get0_key(rsa : RSA, n : BN*, e : BN*, d : BN*) : Void

  # BN
  fun bn_new = BN_new : BN
  fun bn_free = BN_free(bn : BN)
  fun bn_set_word = BN_set_word(bn : BN, w : UInt64) : Int32
  fun bn_num_bits = BN_num_bits(bn : BN) : Int32
  fun bn_bn2bin = BN_bn2bin(bn : BN, to : UInt8*) : Int32

  # BIO
  # BIO_new is already defined in stdlib (as BIO_new).
  fun bio_s_mem = BIO_s_mem : BioMethod*
  fun bio_free_all = BIO_free_all(bio : Bio*)

  fun bio_read_ex = BIO_read(bio : Bio*, buf : UInt8*, len : Int32) : Int32
  fun bio_ctrl_ex = BIO_ctrl(bio : Bio*, cmd : Int32, larg : Int64, parg : Void*) : Int64

  # PEM
  # We use Bio* here to match BIO_new return type
  fun pem_write_bio_rsaprivatekey = PEM_write_bio_RSAPrivateKey(
    bp : Bio*, x : RSA, enc : Void*, kstr : UInt8*, klen : Int32, cb : Void*, u : Void*,
  ) : Int32

  fun pem_write_bio_pubkey = PEM_write_bio_PUBKEY(bp : Bio*, x : EVP_PKEY) : Int32

  # EVP
  fun evp_pkey_new = EVP_PKEY_new : EVP_PKEY
  fun evp_pkey_free = EVP_PKEY_free(pkey : EVP_PKEY) : Void
  fun evp_pkey_assign = EVP_PKEY_assign(pkey : EVP_PKEY, type : Int32, key : Void*) : Int32
  fun evp_pkey_set1_rsa = EVP_PKEY_set1_RSA(pkey : EVP_PKEY, key : RSA) : Int32
  fun evp_pkey_get1_rsa = EVP_PKEY_get1_RSA(pkey : EVP_PKEY) : RSA

  # Constants
  EVP_PKEY_RSA     =  6
  BIO_CTRL_PENDING = 10
  # MBSTRING_UTF8 is already defined in stdlib

  type X509_REQ = Void*
  # X509_NAME and EVP_MD are already defined in stdlib

  # X509 REQ
  fun x509_req_new = X509_REQ_new : X509_REQ
  fun x509_req_free = X509_REQ_free(req : X509_REQ) : Void
  fun x509_req_set_version = X509_REQ_set_version(req : X509_REQ, version : Int64) : Int32
  fun x509_req_set_pubkey = X509_REQ_set_pubkey(req : X509_REQ, pkey : EVP_PKEY) : Int32
  fun x509_req_get_subject_name = X509_REQ_get_subject_name(req : X509_REQ) : X509_NAME
  fun x509_req_sign = X509_REQ_sign(req : X509_REQ, pkey : EVP_PKEY, md : EVP_MD) : Int32

  # X509_NAME_add_entry_by_txt is already defined in stdlib
  # EVP_sha256 is already defined in stdlib (as evp_sha256)

  # EVP MD CTX
  # EVP_MD_CTX is already defined in stdlib

  fun evp_md_ctx_new = EVP_MD_CTX_new : EVP_MD_CTX
  fun evp_md_ctx_free = EVP_MD_CTX_free(ctx : EVP_MD_CTX) : Void

  fun evp_digest_sign_init = EVP_DigestSignInit(
    ctx : EVP_MD_CTX, pctx : EVP_PKEY_CTX*, type : EVP_MD, e : Void*, pkey : EVP_PKEY,
  ) : Int32

  fun evp_digest_sign_update = EVP_DigestSignUpdate(
    ctx : EVP_MD_CTX, data : Void*, count : Int32,
  ) : Int32

  fun evp_digest_sign_final = EVP_DigestSignFinal(
    ctx : EVP_MD_CTX, sig : UInt8*, siglen : Int32*,
  ) : Int32

  # PEM X509 REQ
  fun pem_write_bio_x509_req = PEM_write_bio_X509_REQ(bp : Bio*, req : X509_REQ) : Int32
  fun i2d_x509_req_bio = i2d_X509_REQ_bio(bp : Bio*, req : X509_REQ) : Int32

  # X509
  type ASN1_INTEGER = Void*
  type ASN1_TIME = Void*

  fun x509_new = X509_new : X509
  fun x509_free = X509_free(x : X509) : Void
  fun x509_set_version = X509_set_version(x : X509, version : Int64) : Int32
  fun x509_get_serial_number = X509_get_serialNumber(x : X509) : ASN1_INTEGER
  fun x509_get_not_before = X509_get0_notBefore(x : X509) : ASN1_TIME
  fun x509_get_not_after = X509_get0_notAfter(x : X509) : ASN1_TIME
  fun x509_get_subject_name = X509_get_subject_name(x : X509) : X509_NAME
  fun x509_set_issuer_name = X509_set_issuer_name(x : X509, name : X509_NAME) : Int32
  fun x509_set_pubkey = X509_set_pubkey(x : X509, pkey : EVP_PKEY) : Int32
  fun x509_sign = X509_sign(x : X509, pkey : EVP_PKEY, md : EVP_MD) : Int32

  # ASN1
  fun asn1_integer_set = ASN1_INTEGER_set(a : ASN1_INTEGER, v : Int64) : Int32

  # X509 Time
  fun x509_gmtime_adj = X509_gmtime_adj(s : ASN1_TIME, adj : Int64) : ASN1_TIME

  # PEM X509
  fun pem_write_bio_x509 = PEM_write_bio_X509(bp : Bio*, x : X509) : Int32
end
