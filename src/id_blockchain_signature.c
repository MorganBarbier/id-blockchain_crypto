#include "id_blockchain_signature.h"


ID_BLOCKCHAIN_EC_KEY *id_blockchain_ecdsa256_keygen(void)
{
	ID_BLOCKCHAIN_EC_KEY * eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (eckey == NULL)
	{
  	printf("Error during the instantiation of the keypair");
  	exit(EXIT_FAILURE);
  }
  if (EC_KEY_generate_key(eckey) == 0)
  {
  	printf("Error during the generation of the keypair");
  	exit(EXIT_FAILURE);
  }
  return eckey;
}

ID_BLOCKCHAIN_EC_KEY *id_blockchain_ecdsa521_keygen(void)
{
	ID_BLOCKCHAIN_EC_KEY * eckey = EC_KEY_new_by_curve_name(NID_secp521r1);
	if (eckey == NULL)
	{
  	printf("Error during the instantiation of the keypair");
  	exit(EXIT_FAILURE);
  }
  if (EC_KEY_generate_key(eckey) == 0)
  {
  	printf("Error during the generation of the keypair");
  	exit(EXIT_FAILURE);
  }
  return eckey;
}

void id_blockchain_eckey_free(ID_BLOCKCHAIN_EC_KEY *eckey)
{
	EC_KEY_free(eckey);
}

const ID_BLOCKCHAIN_BIGNUM *id_blockchain_ec_get_private_key
														(const ID_BLOCKCHAIN_EC_KEY *eckey)
{
	return EC_KEY_get0_private_key(eckey);													
}

const ID_BLOCKCHAIN_EC_POINT *id_blockchain_ec_get_public_key
														(const ID_BLOCKCHAIN_EC_KEY *eckey)
{
	return EC_KEY_get0_public_key(eckey);													
}

int id_blockchain_ec_set_private_key(ID_BLOCKCHAIN_EC_KEY *eckey, 
																		 const ID_BLOCKCHAIN_BIGNUM *prv)
{
	return EC_KEY_set_private_key(eckey, prv);
}

int id_blockchain_ec_set_public_key(ID_BLOCKCHAIN_EC_KEY *eckey, 
																		const ID_BLOCKCHAIN_EC_POINT *pub)
{
	return EC_KEY_set_public_key(eckey, pub);
}

ID_BLOCKCHAIN_ECDSA_SIG* id_blockchain_ecdsa256_do_sign(const unsigned char *msg,
                                                        ID_BLOCKCHAIN_EC_KEY *eckey)
{
	unsigned char digest[SHA256_DIGEST_LENGTH]; 
	id_blockchain_sha256(msg, len, digest);
	ID_BLOCKCHAIN_ECDSA_SIG *sig = ECDSA_do_sign(digest, 
																						   SHA256_DIGEST_LENGTH, 
																						   eckey);
	return sig;
}

ID_BLOCKCHAIN_ECDSA_SIG* id_blockchain_ecdsa521_do_sign
												 (const unsigned char *msg, 
												  size_t len,
                          ID_BLOCKCHAIN_EC_KEY *eckey)
{
	unsigned char digest[SHA512_DIGEST_LENGTH]; 
	id_blockchain_sha512(msg, len, digest);
	ID_BLOCKCHAIN_ECDSA_SIG *sig = ECDSA_do_sign(digest, 
																							 SHA512_DIGEST_LENGTH, 
																							 eckey);
	return sig;
}

void id_blockchain_ecdsa_sig_free(ID_BLOCKCHAIN_ECDSA_SIG *sig)
{
	ECDSA_SIG_free(sig);
}

int id_blockchain_ecdsa256_do_verify(const unsigned char *msg,
				     size_t len,
				     const ID_BLOCKCHAIN_ECDSA_SIG *sig,
				     ID_BLOCKCHAIN_EC_KEY* eckey)
{
	unsigned char digest[SHA256_DIGEST_LENGTH]; 
	id_blockchain_sha256(msg, len, digest);
	int ret = ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, sig, eckey); 
	return ret; 
}

int id_blockchain_ecdsa521_do_verify(const unsigned char *msg, size_t len,
                    								 const ID_BLOCKCHAIN_ECDSA_SIG *sig, 
                    								 ID_BLOCKCHAIN_EC_KEY* eckey)
{
	unsigned char digest[SHA512_DIGEST_LENGTH]; 
	id_blockchain_sha512(msg, len, digest);
	int ret = ECDSA_do_verify(digest, SHA512_DIGEST_LENGTH, sig, eckey); 
	return ret; 
}
