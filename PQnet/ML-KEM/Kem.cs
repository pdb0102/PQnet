// MIT License
// 
// Copyright (c) 2024 Peter Dennis Bartok 
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

using PQnet.Digest;

namespace PQnet {
	public abstract partial class MlKemBase {

		/*************************************************
		* Name:        crypto_kem_keypair_derand
		*
		* Description: Generates public and private key
		*              for CCA-secure Kyber key encapsulation mechanism
		*
		* Arguments:   - uint8_t *pk: pointer to output public key
		*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
		*              - uint8_t *sk: pointer to output private key
		*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
		*              - uint8_t *coins: pointer to input randomness
		*                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes)
		**
		* Returns 0 (success)
		**************************************************/
		internal int crypto_kem_keypair_derand(out byte[] pk, out byte[] sk, byte[] coins) {
			byte[] hash;

			pk = new byte[KYBER_PUBLICKEYBYTES];
			sk = new byte[KYBER_SECRETKEYBYTES];

			indcpa_keypair_derand(pk, sk, coins);
			Array.Copy(pk, 0, sk, KYBER_INDCPA_SECRETKEYBYTES, KYBER_PUBLICKEYBYTES);

			Shake.sha3_256(out hash, pk, KYBER_PUBLICKEYBYTES); // hash_h(sk + KYBER_SECRETKEYBYTES - (2 * KYBER_SYMBYTES), pk, KYBER_PUBLICKEYBYTES);
			Array.Copy(hash, 0, sk, KYBER_SECRETKEYBYTES - (2 * KYBER_SYMBYTES), hash.Length);

			/* Value z for pseudo-random output on reject */
			Array.Copy(coins, KYBER_SYMBYTES, sk, KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);

			return 0;
		}

		/*************************************************
		* Name:        crypto_kem_keypair
		*
		* Description: Generates public and private key
		*              for CCA-secure Kyber key encapsulation mechanism
		*
		* Arguments:   - uint8_t *pk: pointer to output public key
		*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
		*              - uint8_t *sk: pointer to output private key
		*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
		*
		* Returns 0 (success)
		**************************************************/
		/// <summary>
		/// 
		/// </summary>
		/// <param name="pk"></param>
		/// <param name="sk"></param>
		/// <returns></returns>
		public int crypto_kem_keypair(out byte[] pk, out byte[] sk) {
			byte[] coins;

			Rng.randombytes(out coins, 2 * KYBER_SYMBYTES);
			crypto_kem_keypair_derand(out pk, out sk, coins);
			return 0;
		}

		/*************************************************
		* Name:        crypto_kem_enc_derand
		*
		* Description: Generates cipher text and shared
		*              secret for given public key
		*
		* Arguments:   - uint8_t *ct: pointer to output cipher text
		*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
		*              - uint8_t *ss: pointer to output shared secret
		*                (an already allocated array of KYBER_SSBYTES bytes)
		*              - const uint8_t *pk: pointer to input public key
		*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
		*              - const uint8_t *coins: pointer to input randomness
		*                (an already allocated array filled with KYBER_SYMBYTES random bytes)
		**
		* Returns 0 (success)
		**************************************************/
		internal int crypto_kem_enc_derand(out byte[] ct, out byte[] ss, byte[] pk, byte[] coins) {
			byte[] buf;
			byte[] kr;
			byte[] hash;

			buf = new byte[2 * KYBER_SYMBYTES];


			/* Will contain key, coins */
			Array.Copy(coins, buf, KYBER_SYMBYTES);

			/* Multitarget countermeasure for coins + contributory KEM */
			Shake.sha3_256(out hash, pk, KYBER_PUBLICKEYBYTES); //(hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
			Array.Copy(hash, 0, buf, KYBER_SYMBYTES, KYBER_SYMBYTES);
			Shake.sha3_512(out kr, buf, 2 * KYBER_SYMBYTES); //hash_g(kr, buf, 2 * KYBER_SYMBYTES);

			/* coins are in kr+KYBER_SYMBYTES */
			ct = new byte[KYBER_CIPHERTEXTBYTES];
			indcpa_enc(ct, buf, new Span<byte>(pk), new Span<byte>(kr).Slice(KYBER_SYMBYTES));

			ss = new byte[KYBER_SSBYTES];
			Array.Copy(kr, ss, KYBER_SYMBYTES);
			return 0;
		}

		/*************************************************
		* Name:        crypto_kem_enc
		*
		* Description: Generates cipher text and shared
		*              secret for given public key
		*
		* Arguments:   - uint8_t *ct: pointer to output cipher text
		*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
		*              - uint8_t *ss: pointer to output shared secret
		*                (an already allocated array of KYBER_SSBYTES bytes)
		*              - const uint8_t *pk: pointer to input public key
		*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
		*
		* Returns 0 (success)
		**************************************************/
		/// <summary>
		/// 
		/// </summary>
		/// <param name="ct"></param>
		/// <param name="ss"></param>
		/// <param name="pk"></param>
		/// <returns></returns>
		public int crypto_kem_enc(out byte[] ct, out byte[] ss, byte[] pk) {
			byte[] coins;

			Rng.randombytes(out coins, KYBER_SYMBYTES);
			crypto_kem_enc_derand(out ct, out ss, pk, coins);
			return 0;
		}

		/*************************************************
		* Name:        crypto_kem_dec
		*
		* Description: Generates shared secret for given
		*              cipher text and private key
		*
		* Arguments:   - uint8_t *ss: pointer to output shared secret
		*                (an already allocated array of KYBER_SSBYTES bytes)
		*              - const uint8_t *ct: pointer to input cipher text
		*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
		*              - const uint8_t *sk: pointer to input private key
		*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
		*
		* Returns 0.
		*
		* On failure, ss will contain a pseudo-random value.
		**************************************************/
		/// <summary>
		/// 
		/// </summary>
		/// <param name="ss"></param>
		/// <param name="ct"></param>
		/// <param name="sk"></param>
		/// <returns></returns>
		public int crypto_kem_dec(out byte[] ss, byte[] ct, byte[] sk) {
			int fail;
			byte[] buf;
			byte[] kr; /* Will contain key, coins */
			byte[] cmp;

			// pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

			buf = new byte[2 * KYBER_SYMBYTES];
			cmp = new byte[KYBER_CIPHERTEXTBYTES + KYBER_SYMBYTES];


			indcpa_dec(buf, ct, sk);

			/* Multitarget countermeasure for coins + contributory KEM */
			Array.Copy(sk, KYBER_SECRETKEYBYTES - (2 * KYBER_SYMBYTES), buf, KYBER_SYMBYTES, KYBER_SYMBYTES);
			Shake.sha3_512(out kr, buf, 2 * KYBER_SYMBYTES); // hash_g(kr, buf, 2 * KYBER_SYMBYTES);

			/* coins are in kr+KYBER_SYMBYTES */
			indcpa_enc(cmp, buf, new Span<byte>(sk).Slice(KYBER_INDCPA_SECRETKEYBYTES), new Span<byte>(kr).Slice(KYBER_SYMBYTES));

			fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

			/* Compute rejection key */
			ss = new byte[KYBER_SSBYTES];
			kyber_shake256_rkprf(ss, new Span<byte>(sk).Slice(KYBER_SECRETKEYBYTES - KYBER_SYMBYTES), ct); //rkprf(ss, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, ct);

			/* Copy true key to return buffer if fail is false */
			cmov(ss, kr, KYBER_SYMBYTES, fail == 0 ? (byte)1 : (byte)0);

			return 0;
		}
	}
}