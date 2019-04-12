/** \file hmac_drbg.c
  *
  * \brief Implements HMAC_DRBG using HMAC_SHA-256.
  *
  * This file implements a deterministic random bit generator (DRBG) based
  * on a HMAC based on SHA-256. Here are two uses for such a generator:
  * - As the foundation of a RFC 6979-based deterministic signature scheme
  *   for ECDSA. This is possible since RFC 6979 explicitly references
  *   the HMAC_DRBG operations defined here.
  * - As part of a random number generation system, used in order to hedge
  *   against undetected faults in the hardware random number
  *   generator (HWRNG). For some justification of this, here is an excerpt
  *   from the last paragraph of page 22 of NIST SP 800-90A: "if there is an
  *   undetected failure in the source of entropy input of an already properly
  *   seeded DRBG instantiation, the DRBG instantiation will still retain any
  *   previous entropy when the reseed operation fails to introduce new
  *   entropy."
  *
  * Here is how to use a DRBG:
  * - Define a variable of type #HMACDRBGState somewhere and instantiate it
  *   using drbgInstantiate().
  * - Use drbgGenerate() to generate bits using that state.
  * - Call drbgReseed() to mix entropy into that state, when appropriate.
  *
  * The DRBG implemented here roughly follow the HMAC_DRBG specification in
  * NIST SP 800-90A, except there are some simplifying shortcuts:
  * - The "prediction resistance flag" is always false; it is the
  *   responsibility of the consuming application to reseed when appropriate.
  * - "Security strength" is fixed at 256 bits (security strength of SHA-256).
  * - "Reseed interval" is infinity; the DRBG never explicitly asks the
  *   consuming application for reseeding. This avoids the need to store a
  *   reseed counter in the state.
  *
  * All references to "NIST SP 800-90A" refer to "Recommendation for Random
  * Number Generation Using Deterministic Random Bit Generators" (Rev 1, dated
  * January 2012), obtained from
  * http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf
  * on 4 April 2015.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifdef TEST_HMAC_DRBG
#include <stdio.h>
#endif // #ifdef TEST_HMAC_DRBG

#include <stdlib.h> // for definition of NULL
#include <string.h>
#include "common.h"
#include "sha256.h"
#include "hmac_drbg.h"

#ifdef TEST_HMAC_DRBG
#include "test_helpers.h"
#endif // #ifdef TEST_HMAC_DRBG

/** Calculate a 32 byte HMAC of an arbitrary message and key using SHA-256 as
  * the hash function.
  * The code in here is based on the description in section 5
  * ("HMAC SPECIFICATION") of FIPS PUB 198.
  *
  * The message can be split up into two separate parts, (denoted by the
  * parameters text1 and text2). This is done because the HMAC_DRBG update
  * function uses a message which is concatenated from two pieces of data.
  * Allowing the message to be split into two parts absolves the caller of
  * the responsibility of concatenating those pieces into a separate,
  * contiguous buffer.
  * \param out A byte array where the HMAC-SHA256 hash value will be written.
  *            This must have space for #SHA256_HASH_LENGTH bytes.
  * \param key A byte array containing the key to use in the HMAC-SHA256
  *            calculation. The key can be of any length.
  * \param key_length The length, in bytes, of the key.
  * \param text1 A byte array containing the first part of the message to use
  *              in the HMAC-SHA256 calculation. The message can be of any
  *              length.
  * \param text1_length The length, in bytes, of the first part of the
  *                     message.
  * \param text2 A byte array containing the second part of the message to use
  *              in the HMAC-SHA256 calculation. This part will be appended to
  *              the first part of the message. This parameter is optional; it
  *              can be NULL.
  * \param text2_length The length, in bytes, of the second part of the
  *                     message.
  */
static void hmacSha256(uint8_t *out, const uint8_t *key, const unsigned int key_length, const uint8_t *text1, const unsigned int text1_length, const uint8_t *text2, const unsigned int text2_length)
{
	unsigned int i;
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t padded_key[64];
	HashState hs;

	// Determine key.
	memset(padded_key, 0, sizeof(padded_key));
	if (key_length <= sizeof(padded_key))
	{
		memcpy(padded_key, key, key_length);
	}
	else
	{
		sha256Begin(&hs);
		for (i = 0; i < key_length; i++)
		{
			sha256WriteByte(&hs, key[i]);
		}
		sha256Finish(&hs);
		writeHashToByteArray(padded_key, &hs, true);
	}
	// Calculate hash = H((K_0 XOR ipad) || text).
	sha256Begin(&hs);
	for (i = 0; i < sizeof(padded_key); i++)
	{
		sha256WriteByte(&hs, (uint8_t)(padded_key[i] ^ 0x36));
	}
	// Note that text = text1 || text2.
	if (text1 != NULL)
	{
		for (i = 0; i < text1_length; i++)
		{
			sha256WriteByte(&hs, text1[i]);
		}
	}
	if (text2 != NULL)
	{
		for (i = 0; i < text2_length; i++)
		{
			sha256WriteByte(&hs, text2[i]);
		}
	}
	sha256Finish(&hs);
	writeHashToByteArray(hash, &hs, true);
	// Calculate H((K_0 XOR opad) || hash).
	sha256Begin(&hs);
	for (i = 0; i < sizeof(padded_key); i++)
	{
		sha256WriteByte(&hs, (uint8_t)(padded_key[i] ^ 0x5c));
	}
	for (i = 0; i < sizeof(hash); i++)
	{
		sha256WriteByte(&hs, hash[i]);
	}
	sha256Finish(&hs);
	writeHashToByteArray(out, &hs, true);
}

/** HMAC_DRBG update function. This is a function common to all HMAC_DRBG
  * operations. This function updates the internal state of the DRBG, mixing
  * in some (optional) provided data.
  * \param state The HMAC_DRBG state to update.
  * \param provided_data Optional data to mix into internal state. This may be
  *                      NULL to indicate that there is no provided data.
  *                      Note that there is a difference between "no provided
  *                      data" (specified by passing NULL for this parameter)
  *                      and a zero length string (specified by passing a
  *                      pointer to a zero length byte array for this
  *                      parameter, and passing provided_data_length = 0).
  * \param provided_data_length Length of provided data, in bytes.
  */
static void drbgUpdate(HMACDRBGState *state, const uint8_t *provided_data, const unsigned int provided_data_length)
{
	uint8_t temp[SHA256_HASH_LENGTH + 1];

	// This algorithm is described in pages 45-46 of NIST SP 800-90A.
	// 1. K = HMAC (K, V || 0x00 || provided_data).
	memcpy(temp, state->v, sizeof(state->v));
	temp[SHA256_HASH_LENGTH] = 0x00;
	hmacSha256(state->key, state->key, sizeof(state->key), temp, sizeof(temp), provided_data, provided_data_length);
	// 2. V = HMAC (K, V).
	hmacSha256(state->v, state->key, sizeof(state->key), state->v, sizeof(state->v), NULL, 0);
	// 3. If (provided_data = Null), then return K and V.
	if (provided_data != NULL)
	{
		// 4. K = HMAC (K, V || 0x01 || provided_data).
		memcpy(temp, state->v, sizeof(state->v));
		temp[SHA256_HASH_LENGTH] = 0x01;
		hmacSha256(state->key, state->key, sizeof(state->key), temp, sizeof(temp), provided_data, provided_data_length);
		// 5. V = HMAC (K, V).
		hmacSha256(state->v, state->key, sizeof(state->key), state->v, sizeof(state->v), NULL, 0);
		// 6. Return K and V.
	}
}

/** Instantiate a HMAC_DRBG state using some seed material.
  * In the terminology of NIST SP 800-90A, the seed material consists of
  * entropy_input, nonce and personalization_string concatenated together.
  * It is the responsibility of the caller to perform this concatenation.
  * This function doesn't do the concatenation because that would require
  * dynamic memory allocation.
  * \param state The HMAC_DRBG state to instantiate.
  * \param seed_material The seed material to seed the HMAC_DRBG state with.
  *                      This may be of arbitrary length and will usually
  *                      consist of several entropy sources concatenated
  *                      together.
  * \param seed_material_length Length of seed material in bytes.
  */
void drbgInstantiate(HMACDRBGState *state, const uint8_t *seed_material, const unsigned int seed_material_length)
{
	memset(state->key, 0x00, sizeof(state->key));
	memset(state->v, 0x01, sizeof(state->v));
	drbgUpdate(state, seed_material, seed_material_length);
}

/** Mix in some more entropy into a HMAC_DRBG state.
  * In the terminology of NIST SP 800-90A, the reseed material consists of
  * entropy_input and additional_input concatenated together.
  * It is the responsibility of the caller to perform this concatenation.
  * This function doesn't do the concatenation because that would require
  * dynamic memory allocation.
  * \param state The HMAC_DRBG state to reseed and update. The state must
  *              have been previously instantiated using drbgInstantiate().
  * \param reseed_material The material to reseed the HMAC_DRBG state with.
  *                        This may be of arbitrary length and will usually
  *                        consist of several entropy sources concatenated
  *                        together.
  * \param reseed_material_length Length of reseed material in bytes.
  */
void drbgReseed(HMACDRBGState *state, const uint8_t *reseed_material, const unsigned int reseed_material_length)
{
	drbgUpdate(state, reseed_material, reseed_material_length);
}

/** Generate some (deterministic) random bytes from a HMAC_DRBG state.
  * \param out Byte array which will receive the random bytes. This must be
  *            large enough to store requested_bytes bytes.
  * \param state The HMAC_DRBG state to get bytes from. The state must
  *              have been previously instantiated using drbgInstantiate().
  * \param requested_bytes Number of bytes to generate.
  * \param additional_input Optional additional data to mix into HMAC_DRBG
  *                         state. This may be NULL to indicate that there is
  *                         no additional input.
  * \param additional_input_length Length of additional input, in number of
  *                                bytes.
  */
void drbgGenerate(uint8_t *out, HMACDRBGState *state, const unsigned int requested_bytes, const uint8_t *additional_input, const unsigned int additional_input_length)
{
	unsigned int bytes;
	unsigned int copy_size;

	if (additional_input != NULL)
	{
		drbgUpdate(state, additional_input, additional_input_length);
	}
	bytes = 0;
	while (bytes < requested_bytes)
	{
		// V = HMAC (Key, V).
		hmacSha256(state->v, state->key, sizeof(state->key), state->v, sizeof(state->v), NULL, 0);
		copy_size = MIN(requested_bytes - bytes, sizeof(state->v));
		memcpy(&(out[bytes]), state->v, copy_size);
		bytes += copy_size;
	}
	drbgUpdate(state, additional_input, additional_input_length);
}