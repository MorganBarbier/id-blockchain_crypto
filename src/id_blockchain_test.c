#include "id_blockchain_crypto.h"
#include <string.h>

int main()
{
  /* ---- 3 tests pour le hachage ---- */
  printf("-------- Vecteurs de tests FIPS 180 --------\n\n");
  char *chaine1 = "abc";
  unsigned char digest_sha256_vec1[32] = 	{0xba, 0x78, 0x16, 0xbf, 
						 0x8f, 0x01, 0xcf, 0xea, 
						 0x41, 0x41, 0x40, 0xde, 
						 0x5d, 0xae, 0x22, 0x23, 
						 0xb0, 0x03, 0x61, 0xa3, 
						 0x96, 0x17, 0x7a, 0x9c,
						 0xb4, 0x10, 0xff, 0x61, 
						 0xf2, 0x00, 0x15, 0xad}; 
  unsigned char digest_sha512_vec1[64] = 	{0xdd, 0xaf, 0x35, 0xa1,
						 0x93, 0x61, 0x7a, 0xba, 
						 0xcc, 0x41, 0x73, 0x49,
						 0xae, 0x20, 0x41, 0x31, 
						 0x12, 0xe6, 0xfa, 0x4e,
						 0x89, 0xa9, 0x7e, 0xa2,
						 0x0a, 0x9e, 0xee, 0xe6,
						 0x4b, 0x55, 0xd3, 0x9a,
						 0x21, 0x92, 0x99, 0x2a, 
						 0x27, 0x4f, 0xc1, 0xa8,
						 0x36, 0xba, 0x3c, 0x23, 
						 0xa3, 0xfe, 0xeb, 0xbd,
						 0x45, 0x4d, 0x44, 0x23,
						 0x64, 0x3c, 0xe8, 0x0e,
						 0x2a, 0x9a, 0xc9, 0x4f,
						 0xa5, 0x4c, 0xa4, 0x9f};
																						 
  char *chaine2 = "";
  unsigned char digest_sha256_vec2[32] = 	{0xe3, 0xb0, 0xc4, 0x42,
						 0x98, 0xfc, 0x1c, 0x14,
						 0x9a, 0xfb, 0xf4, 0xc8,
						 0x99, 0x6f, 0xb9, 0x24,
						 0x27, 0xae, 0x41, 0xe4, 
						 0x64, 0x9b, 0x93, 0x4c,
						 0xa4, 0x95, 0x99, 0x1b,
						 0x78, 0x52, 0xb8, 0x55}; 	
  unsigned char digest_sha512_vec2[64] = 	{0xcf, 0x83, 0xe1, 0x35,
						 0x7e, 0xef, 0xb8, 0xbd,
						 0xf1, 0x54, 0x28, 0x50,
						 0xd6, 0x6d, 0x80, 0x07, 
						 0xd6, 0x20, 0xe4, 0x05, 
						 0x0b, 0x57, 0x15, 0xdc,  
						 0x83, 0xf4, 0xa9, 0x21, 
						 0xd3, 0x6c, 0xe9, 0xce, 
						 0x47, 0xd0, 0xd1, 0x3c,
						 0x5d, 0x85, 0xf2, 0xb0, 
						 0xff, 0x83, 0x18, 0xd2,
						 0x87, 0x7e, 0xec, 0x2f, 
						 0x63, 0xb9, 0x31, 0xbd,
						 0x47, 0x41, 0x7a, 0x81, 
						 0xa5, 0x38, 0x32, 0x7a, 
						 0xf9, 0x27, 0xda, 0x3e};
						 													 
  char *chaine3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  unsigned char digest_sha256_vec3[32] = 	{0x24, 0x8d, 0x6a, 0x61,
						 0xd2, 0x06, 0x38, 0xb8,
						 0xe5, 0xc0, 0x26, 0x93,
						 0x0c, 0x3e, 0x60, 0x39, 
						 0xa3, 0x3c, 0xe4, 0x59, 
						 0x64, 0xff, 0x21, 0x67, 
						 0xf6, 0xec, 0xed, 0xd4, 
						 0x19, 0xdb, 0x06, 0xc1}; 
  unsigned char digest_sha512_vec3[64] = 	{0x20, 0x4a, 0x8f, 0xc6, 
						 0xdd, 0xa8, 0x2f, 0x0a, 
						 0x0c, 0xed, 0x7b, 0xeb,
						 0x8e, 0x08, 0xa4, 0x16,
						 0x57, 0xc1, 0x6e, 0xf4,
						 0x68, 0xb2, 0x28, 0xa8, 
						 0x27, 0x9b, 0xe3, 0x31,
						 0xa7, 0x03, 0xc3, 0x35,
						 0x96, 0xfd, 0x15, 0xc1,
						 0x3b, 0x1b, 0x07, 0xf9, 
						 0xaa, 0x1d, 0x3b, 0xea,
						 0x57, 0x78, 0x9c, 0xa0, 
						 0x31, 0xad, 0x85, 0xc7,
						 0xa7, 0x1d, 0xd7, 0x03, 
						 0x54, 0xec, 0x63, 0x12,
						 0x38, 0xca, 0x34, 0x45};																				 
	
  unsigned char digest[SHA512_DIGEST_LENGTH]; 
  printf("Test message \"abc\" \n");
  id_blockchain_sha256((unsigned char *) chaine1, strlen(chaine1), digest);
  if(!memcmp(digest, digest_sha256_vec1, SHA256_DIGEST_LENGTH))
    printf("SHA256 OK\n");
  else
    printf("SHA256 non OK\n");	
  id_blockchain_sha512((unsigned char *) chaine1, strlen(chaine1), digest);
  if(!memcmp(digest, digest_sha512_vec1, SHA512_DIGEST_LENGTH))
    printf("SHA512 OK\n");
  else
    printf("SHA512 non OK\n");
		
  printf("Test message \"\" \n");
  id_blockchain_sha256((unsigned char *) chaine2, strlen(chaine2), digest);
  if(!memcmp(digest, digest_sha256_vec2, SHA256_DIGEST_LENGTH))
    printf("SHA256 OK\n");
  else
    printf("SHA256 non OK\n");
  id_blockchain_sha512((unsigned char *) chaine2, strlen(chaine2), digest);
  if(!memcmp(digest, digest_sha512_vec2, SHA512_DIGEST_LENGTH))
    printf("SHA512 OK\n");
  else
    printf("SHA512 non OK\n");
	
  printf("Test message \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\" \n");
  id_blockchain_sha256((unsigned char *) chaine3, strlen(chaine3), digest);
  if(!memcmp(digest, digest_sha256_vec3, SHA256_DIGEST_LENGTH))
    printf("SHA256 OK\n");
  else
    printf("SHA256 non OK\n");
  id_blockchain_sha512((unsigned char *) chaine3, strlen(chaine3), digest);
  if(!memcmp(digest, digest_sha512_vec3, SHA512_DIGEST_LENGTH))
    printf("SHA512 OK\n");
  else
    printf("SHA512 non OK\n");
  printf("-------- Fin tests hachage --------\n\n");
	
  /* ---- tests signatures : niveau de sécurité 128 bits ---- */
  /* Génération d'une paire de clés pour une courbe de 256 bits */
  ID_BLOCKCHAIN_EC_KEY *keypair1 = id_blockchain_ecdsa256_keygen();
  /* Génération d'une signature sur le message "test1" */
  ID_BLOCKCHAIN_ECDSA_SIG *signature1 = id_blockchain_ecdsa256_do_sign
    ((unsigned char *) chaine1, 5, keypair1);
  /* Vérification de cette signature sur le message "test1" */
  printf("Vérification de la signature sur le bon message.\n");
  if(id_blockchain_ecdsa256_do_verify((unsigned char *) chaine1, 
				      5, signature1, keypair1) == 1)
    printf("Résultat : signature correcte\n");
  else
    printf("Résultat : signature incorrecte\n");		
  /* Vérification de cette signature sur le mauvais message "test2" */
  printf("Vérification de la signature sur le mauvais message.\n");
  if(id_blockchain_ecdsa256_do_verify((unsigned char *) chaine2, 
				      5, signature1, keypair1) == 1)
    printf("Résultat : signature correcte\n");
  else
    printf("Résultat : signature incorrecte\n");
  printf("-------- Fin tests signature sur courbe 256 bits --------\n\n");
  /* Effacement de la clé 1 */
  id_blockchain_eckey_free(keypair1);
  /* Effacement signature 1 */
  id_blockchain_ecdsa_sig_free(signature1);
		
  /* ---- tests signatures : niveau de sécurité 256 bits ---- */
  /* Génération d'une paire de clés pour une courbe de 521 bits */
  ID_BLOCKCHAIN_EC_KEY *keypair2 = id_blockchain_ecdsa521_keygen();
  /* Génération d'une signature sur le message "test1" */
  ID_BLOCKCHAIN_ECDSA_SIG *signature2 = id_blockchain_ecdsa521_do_sign
    ((unsigned char *) chaine2, 5, keypair2);
  /* Vérification de cette signature sur le message "test2" */
  printf("Vérification de la signature sur le bon message.\n");
  if(id_blockchain_ecdsa521_do_verify((unsigned char *) chaine2, 
				      5, signature2, keypair2) == 1)
    printf("Résultat : signature correcte\n");
  else
    printf("Résultat : signature incorrecte\n");		
  /* Vérification de cette signature sur le mauvais message "test1" */
  printf("Vérification de la signature sur le mauvais message.\n");
  if(id_blockchain_ecdsa521_do_verify((unsigned char *) chaine1, 
				      5, signature2, keypair2) == 1)
    printf("Résultat : signature correcte\n");
  else
    printf("Résultat : signature incorrecte\n");
  printf("-------- Fin tests signature sur courbe 521 bits --------\n\n");
  /* Effacement de la clé 2 */
  id_blockchain_eckey_free(keypair2);
  /* Effacement signature 2 */
  id_blockchain_ecdsa_sig_free(signature2);
  return 0;
}

