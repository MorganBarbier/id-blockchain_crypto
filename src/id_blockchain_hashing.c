#include "id_blockchain_hashing.h"

void id_blockchain_sha256(const unsigned char *byte_string,
			  size_t len,
			  unsigned char digest[SHA256_DIGEST_LENGTH])
{
  SHA256(byte_string, len, digest);
}

void id_blockchain_sha512(const unsigned char *byte_string,
			  size_t len,
			  unsigned char digest[SHA512_DIGEST_LENGTH])
{
  SHA512(byte_string, len, digest);
}

