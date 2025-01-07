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
		* Name:        kyber_shake128_absorb
		*
		* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
		*
		* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
		*              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be absorbed into state
		*              - uint8_t i: additional byte of input
		*              - uint8_t j: additional byte of input
		**************************************************/

		private void kyber_shake128_absorb(Shake128 shake128, byte[] seed, byte x, byte y) {
			byte[] extseed;

			extseed = new byte[KYBER_SYMBYTES + 2];
			Array.Copy(seed, extseed, KYBER_SYMBYTES);

			extseed[KYBER_SYMBYTES + 0] = x;
			extseed[KYBER_SYMBYTES + 1] = y;

			shake128.AbsorbOnce(extseed, extseed.Length);
		}

		/*************************************************
		* Name:        kyber_shake256_prf
		*
		* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
		*              and then generates outlen bytes of SHAKE256 output
		*
		* Arguments:   - uint8_t *out: pointer to output
		*              - size_t outlen: number of requested output bytes
		*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
		*              - uint8_t nonce: single-byte nonce (public PRF input)
		**************************************************/
		private byte[] kyber_shake256_prf(int outlen, Span<byte> key, byte nonce) {
			byte[] extkey;

			extkey = new byte[KYBER_SYMBYTES + 1];

			key.Slice(0, KYBER_SYMBYTES).CopyTo(extkey);
			extkey[KYBER_SYMBYTES] = nonce;

			return Shake256.HashData(extkey, outlen);
		}

		/*************************************************
		* Name:        kyber_shake256_prf
		*
		* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
		*              and then generates outlen bytes of SHAKE256 output
		*
		* Arguments:   - uint8_t *out: pointer to output
		*              - size_t outlen: number of requested output bytes
		*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
		*              - uint8_t nonce: single-byte nonce (public PRF input)
		**************************************************/
		private void kyber_shake256_rkprf(byte[] out_buf, Span<byte> key, byte[] input) {
			Shake256 shake256;

			shake256 = new Shake256();

			shake256.Absorb(key.ToArray(), KYBER_SYMBYTES);
			shake256.Absorb(input, KYBER_CIPHERTEXTBYTES);
			shake256.FinalizeAbsorb();
			shake256.Squeeze(out_buf, 0, KYBER_SSBYTES);
		}
	}
}