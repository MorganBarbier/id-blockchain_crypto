/**
 * \file id_blockchain_signature.h
 *
 * \brief Header file for containing the definition of
 *        signature, althought user friendly functions
 *        to create the private and public keys, sign
 *        and verify a signature.
 *
 * \auhtors Kevin Atighehchi <kevin.atighehchi@unicaen.fr>
 *          Morgan Barbier <morgan.barbier@ensicaen.fr>
 *
 * \version 1.0
 *
 * \date 2018-06-29
 */
#ifndef __ID_BLOCKCHAIN_SIGNATURE_H__
#define __ID_BLOCKCHAIN_SIGNATURE_H__

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "id_blockchain_hashing.h"

/**
 * \typedef ID_BLOCKCHAIN_EC_KEY
 * 
 * Type definition of couple of key for ECDSA
 */
typedef EC_KEY ID_BLOCKCHAIN_EC_KEY;

/**
 * \typedef ID_BLOCKCHAIN_EC_POINT
 *
 * Type definition for a point on an elliptic curve
 * e.g. for a public key
 */
typedef EC_POINT ID_BLOCKCHAIN_EC_POINT;

/**
 * \typedef ID_BLOCKCHAIN_BIGNUM
 *
 * Type definition for a scalar for an elliptic curve
 * e.g. for a private key
 */
typedef BIGNUM ID_BLOCKCHAIN_BIGNUM;

/**
 * \typedef ECDSA_SIG ID_BLOCKCHAIN_ECDSA_SIG
 *
 * Type definition for a signature with ECDSA
 */
typedef ECDSA_SIG ID_BLOCKCHAIN_ECDSA_SIG;


/**
 * \fn ID_BLOCKCHAIN_EC_KEY *id_blockchain_ecdsa256_keygen(void)
 *
 * \brief Generation of private and public keys for a a signature ECDSA.
 *        The choice of the curve has set up to have a 256 bits of 
 *        level of security.
 *
 * \param[out] the couple of keys
*/
ID_BLOCKCHAIN_EC_KEY *id_blockchain_ecdsa256_keygen(void);


/**
 * \fn ID_BLOCKCHAIN_EC_KEY *id_blockchain_ecdsa521_keygen(void)
 *
 * \brief Generation of private and public keys for a a signature ECDSA.
 *        The choice of the curve has set up to have a 512 bits of 
 *        level of security.
 *
 * \param[out] the couple of keys
*/
ID_BLOCKCHAIN_EC_KEY *id_blockchain_ecdsa521_keygen(void);

/**
 * \fn void id_blockchain_eckey_free(ID_BLOCKCHAIN_EC_KEY *eckey)
 *
 * \brief Free the memory for the couple of key
 *
 * \param[in] eckey couple of key to remove from the memory
*/
void id_blockchain_eckey_free(ID_BLOCKCHAIN_EC_KEY *eckey);

/**
 * \fn const ID_BLOCKCHAIN_BIGNUM *id_blockchain_ec_get_private_key(const ID_BLOCKCHAIN_EC_KEY *eckey)
 *
 * \brief Return the private key from the couple of keys
 *
 * \param[out] private key
 * \param[in] couple of keys
*/
const ID_BLOCKCHAIN_BIGNUM *id_blockchain_ec_get_private_key(const ID_BLOCKCHAIN_EC_KEY *eckey);

/**
 * \fn const ID_BLOCKCHAIN_EC_POINT *id_blockchain_ec_get_public_key(const ID_BLOCKCHAIN_EC_KEY *eckey)
 *
 * \brief Return the public key from the couple of keys
 *
 * \param[out] public key
 * \param[in] couple of keys
*/
const ID_BLOCKCHAIN_EC_POINT *id_blockchain_ec_get_public_key(const ID_BLOCKCHAIN_EC_KEY *eckey);

/**
 * \fn int id_blockchain_ec_set_private_key(ID_BLOCKCHAIN_EC_KEY *eckey,
				     const ID_BLOCKCHAIN_BIGNUM *prv)
 *
 * \brief Setting up the private key into the couple of keys
 *
 * \param[out] 1 if successfull, 0 otherwise
 * \param[in] eckey the couple of key to setting up
 * \param[in] prv new value for the private key
*/
int id_blockchain_ec_set_private_key(ID_BLOCKCHAIN_EC_KEY *eckey,
				     const ID_BLOCKCHAIN_BIGNUM *prv);

/**
 * \fn int id_blockchain_ec_set_public_key(ID_BLOCKCHAIN_EC_KEY *eckey,
 *                                         const ID_BLOCKCHAIN_EC_POINT *pub);
 *
 * \brief Setting up the public key into the couple of keys
 *
 * \param[out] 1 if successfull, 0 otherwise
 * \param[in] eckey the couple of key to setting up
 * \param[in] pub new value for the public key
*/
int id_blockchain_ec_set_public_key(ID_BLOCKCHAIN_EC_KEY *eckey,
				    const ID_BLOCKCHAIN_EC_POINT *pub);

/**
 * \fn ID_BLOCKCHAIN_ECDSA_SIG* id_blockchain_ecdsa256_do_sign(const unsigned char *msg,
 *			  size_t len,
 *                        ID_BLOCKCHAIN_EC_KEY *eckey)
 *
 * \brief Compute the ECDSA signature for a 128 bits of security level
 *
 * \param[out] signature
 * \param[in] msg the message to sign
 * \param[in] len lenght of the message msg
 * \param[in] eckey couple of keys containing an initialized private one
*/
ID_BLOCKCHAIN_ECDSA_SIG* id_blockchain_ecdsa256_do_sign(const unsigned char *msg,
			  size_t len,
                          ID_BLOCKCHAIN_EC_KEY *eckey);
                          
/**
 * \fn ID_BLOCKCHAIN_ECDSA_SIG* id_blockchain_ecdsa521_do_sign(const unsigned char *msg,
 *			  size_t len,
 *                        ID_BLOCKCHAIN_EC_KEY *eckey)
 *
 * \brief Compute the ECDSA signature for a 256 bits of security level
 *
 * \param[out] signature
 * \param[in] msg the message to sign
 * \param[in] len lenght of the message msg
 * \param[in] eckey couple of keys containing an initialized private one
*/
ID_BLOCKCHAIN_ECDSA_SIG* id_blockchain_ecdsa521_do_sign(const unsigned char *msg,
			  size_t len,
                          ID_BLOCKCHAIN_EC_KEY *eckey);

/**
 * \fn int id_blockchain_ecdsa256_do_verify(const unsigned char *msg,
 *				     size_t len,
 *				     const ID_BLOCKCHAIN_ECDSA_SIG *sig,
 *				     ID_BLOCKCHAIN_EC_KEY* eckey);
 *
 * \brief Verify if a 128 bits security level signature is valid
 *
 * \param[out] -1 if an error occurs, 0 if the signature is invalid
 *             and 1 if it is valid
 * \param[in] msg message to check the signature
 * \param[in] len length of the message msg
 * \param[in] sig signature to check
 * \param[in] eckey couple of keys with an initialized public one
*/
int id_blockchain_ecdsa256_do_verify(const unsigned char *msg,
				     size_t len,
				     const ID_BLOCKCHAIN_ECDSA_SIG *sig,
				     ID_BLOCKCHAIN_EC_KEY* eckey);
                    								 
/**
 * \fn int id_blockchain_ecdsa521_do_verify(const unsigned char *msg,
 *				     size_t len,
 *				     const ID_BLOCKCHAIN_ECDSA_SIG *sig,
 *				     ID_BLOCKCHAIN_EC_KEY* eckey)
 *
 * \brief Verify if a 256 bits security level signature is valid
 *
 * \param[out] -1 if an error occurs, 0 if the signature is invalid
 *             and 1 if it is valid
 * \param[in] msg message to check the signature
 * \param[in] len length of the message msg
 * \param[in] sig signature to check
 * \param[in] eckey couple of keys with an initialized public one
*/
int id_blockchain_ecdsa521_do_verify(const unsigned char *msg,
				     size_t len,
				     const ID_BLOCKCHAIN_ECDSA_SIG *sig,
				     ID_BLOCKCHAIN_EC_KEY* eckey);

/**
 * \fn void id_blockchain_ecdsa_sig_free(ID_BLOCKCHAIN_ECDSA_SIG *sig)
 *
 * \brief Desallocate the memory of an ECDSA signature
 *
 * \param[in] sign signature to desallocate
 */
void id_blockchain_ecdsa_sig_free(ID_BLOCKCHAIN_ECDSA_SIG *sig);

#endif /* __ID_BLOCKCHAIN_SIGNATURE_H__ */
