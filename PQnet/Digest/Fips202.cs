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

namespace PQnet.Digest {
	/// <summary>
	/// Implements the SHA-3 and SHAKE hash functions.
	/// </summary>
	public static class Shake {
		/* Based on the public domain implementation in crypto_hash/keccakc512/simple/ from
		 * http://bench.cr.yp.to/supercop.html by Ronny Van Keer and the public domain "TweetFips202"
		 * implementation from https://twitter.com/tweetfips202 by Gilles Van Assche, Daniel J. Bernstein,
		 * and Peter Schwabe */

		internal const int SHAKE128_RATE = 168;
		internal const int SHAKE256_RATE = 136;
		internal const int SHA3_256_RATE = 136;
		internal const int SHA3_512_RATE = 72;

		private const int NROUNDS = 24;

		/* Keccak round constants */
		private static readonly ulong[] KeccakF_RoundConstants = new ulong[]{
			0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
			0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
			0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
			0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
			0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
			0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
		};

		/// <summary>
		/// The state of the Keccak sponge function.
		/// </summary>
		public class KeccakState {
			/// <summary>
			/// Initializes a new instance of the <see cref="KeccakState"/> class.
			/// </summary>
			public KeccakState() {
				s = new ulong[25];
			}
			/// <summary>
			/// The state of the Keccak sponge function.
			/// </summary>
			public ulong[] s;
			/// <summary>
			/// The position in the current block.
			/// </summary>
			public int pos;
		}


		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static ulong ROL(ulong a, int offset) {
			return (a << offset) ^ (a >> (64 - offset));
		}

		/*************************************************
		* Name:        load64
		*
		* Description: Load 8 bytes into ulong in little-endian order
		*
		* Arguments:   - const uint8_t *x: pointer to input byte array
		*
		* Returns the loaded 64-bit unsigned integer
		**************************************************/
		private static ulong load64(byte[] x, int offset) {
			ulong r;

			Debug.Assert(offset + 8 <= x.Length);

			r = 0;

			for (int i = 0; i < 8; i++) {
				r |= (ulong)x[offset + i] << (8 * i);
			}

			return r;
		}

		/*************************************************
		* Name:        store64
		*
		* Description: Store a 64-bit integer to array of 8 bytes in little-endian order
		*
		* Arguments:   - uint8_t *x: pointer to the output byte array (allocated)
		*              - ulong u: input 64-bit unsigned integer
		**************************************************/
		private static void store64(byte[] x, int offset, ulong u) {
			Debug.Assert(offset + 8 <= x.Length);

			for (int i = 0; i < 8; i++) {
				x[offset + i] = (byte)(u >> (8 * i));
			}
		}

		/*************************************************
		* Name:        KeccakF1600_StatePermute
		*
		* Description: The Keccak F1600 Permutation
		*
		* Arguments:   - ulong *state: pointer to input/output Keccak state
		**************************************************/
		private static void KeccakF1600_StatePermute(ulong[] state) {
			int round;

			Debug.Assert(state.Length == 25);

			ulong Aba, Abe, Abi, Abo, Abu;
			ulong Aga, Age, Agi, Ago, Agu;
			ulong Aka, Ake, Aki, Ako, Aku;
			ulong Ama, Ame, Ami, Amo, Amu;
			ulong Asa, Ase, Asi, Aso, Asu;
			ulong BCa, BCe, BCi, BCo, BCu;
			ulong Da, De, Di, Do, Du;
			ulong Eba, Ebe, Ebi, Ebo, Ebu;
			ulong Ega, Ege, Egi, Ego, Egu;
			ulong Eka, Eke, Eki, Eko, Eku;
			ulong Ema, Eme, Emi, Emo, Emu;
			ulong Esa, Ese, Esi, Eso, Esu;

			//copyFromState(A, state)
			Aba = state[0];
			Abe = state[1];
			Abi = state[2];
			Abo = state[3];
			Abu = state[4];
			Aga = state[5];
			Age = state[6];
			Agi = state[7];
			Ago = state[8];
			Agu = state[9];
			Aka = state[10];
			Ake = state[11];
			Aki = state[12];
			Ako = state[13];
			Aku = state[14];
			Ama = state[15];
			Ame = state[16];
			Ami = state[17];
			Amo = state[18];
			Amu = state[19];
			Asa = state[20];
			Ase = state[21];
			Asi = state[22];
			Aso = state[23];
			Asu = state[24];

			for (round = 0; round < NROUNDS; round += 2) {
				//    prepareTheta
				BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
				BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
				BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
				BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
				BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

				//thetaRhoPiChiIotaPrepareTheta(round, A, E)
				Da = BCu ^ ROL(BCe, 1);
				De = BCa ^ ROL(BCi, 1);
				Di = BCe ^ ROL(BCo, 1);
				Do = BCi ^ ROL(BCu, 1);
				Du = BCo ^ ROL(BCa, 1);

				Aba ^= Da;
				BCa = Aba;
				Age ^= De;
				BCe = ROL(Age, 44);
				Aki ^= Di;
				BCi = ROL(Aki, 43);
				Amo ^= Do;
				BCo = ROL(Amo, 21);
				Asu ^= Du;
				BCu = ROL(Asu, 14);
				Eba = BCa ^ ((~BCe) & BCi);
				Eba ^= KeccakF_RoundConstants[round];
				Ebe = BCe ^ ((~BCi) & BCo);
				Ebi = BCi ^ ((~BCo) & BCu);
				Ebo = BCo ^ ((~BCu) & BCa);
				Ebu = BCu ^ ((~BCa) & BCe);

				Abo ^= Do;
				BCa = ROL(Abo, 28);
				Agu ^= Du;
				BCe = ROL(Agu, 20);
				Aka ^= Da;
				BCi = ROL(Aka, 3);
				Ame ^= De;
				BCo = ROL(Ame, 45);
				Asi ^= Di;
				BCu = ROL(Asi, 61);
				Ega = BCa ^ ((~BCe) & BCi);
				Ege = BCe ^ ((~BCi) & BCo);
				Egi = BCi ^ ((~BCo) & BCu);
				Ego = BCo ^ ((~BCu) & BCa);
				Egu = BCu ^ ((~BCa) & BCe);

				Abe ^= De;
				BCa = ROL(Abe, 1);
				Agi ^= Di;
				BCe = ROL(Agi, 6);
				Ako ^= Do;
				BCi = ROL(Ako, 25);
				Amu ^= Du;
				BCo = ROL(Amu, 8);
				Asa ^= Da;
				BCu = ROL(Asa, 18);
				Eka = BCa ^ ((~BCe) & BCi);
				Eke = BCe ^ ((~BCi) & BCo);
				Eki = BCi ^ ((~BCo) & BCu);
				Eko = BCo ^ ((~BCu) & BCa);
				Eku = BCu ^ ((~BCa) & BCe);

				Abu ^= Du;
				BCa = ROL(Abu, 27);
				Aga ^= Da;
				BCe = ROL(Aga, 36);
				Ake ^= De;
				BCi = ROL(Ake, 10);
				Ami ^= Di;
				BCo = ROL(Ami, 15);
				Aso ^= Do;
				BCu = ROL(Aso, 56);
				Ema = BCa ^ ((~BCe) & BCi);
				Eme = BCe ^ ((~BCi) & BCo);
				Emi = BCi ^ ((~BCo) & BCu);
				Emo = BCo ^ ((~BCu) & BCa);
				Emu = BCu ^ ((~BCa) & BCe);

				Abi ^= Di;
				BCa = ROL(Abi, 62);
				Ago ^= Do;
				BCe = ROL(Ago, 55);
				Aku ^= Du;
				BCi = ROL(Aku, 39);
				Ama ^= Da;
				BCo = ROL(Ama, 41);
				Ase ^= De;
				BCu = ROL(Ase, 2);
				Esa = BCa ^ ((~BCe) & BCi);
				Ese = BCe ^ ((~BCi) & BCo);
				Esi = BCi ^ ((~BCo) & BCu);
				Eso = BCo ^ ((~BCu) & BCa);
				Esu = BCu ^ ((~BCa) & BCe);

				//    prepareTheta
				BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
				BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
				BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
				BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
				BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

				//thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
				Da = BCu ^ ROL(BCe, 1);
				De = BCa ^ ROL(BCi, 1);
				Di = BCe ^ ROL(BCo, 1);
				Do = BCi ^ ROL(BCu, 1);
				Du = BCo ^ ROL(BCa, 1);

				Eba ^= Da;
				BCa = Eba;
				Ege ^= De;
				BCe = ROL(Ege, 44);
				Eki ^= Di;
				BCi = ROL(Eki, 43);
				Emo ^= Do;
				BCo = ROL(Emo, 21);
				Esu ^= Du;
				BCu = ROL(Esu, 14);
				Aba = BCa ^ ((~BCe) & BCi);
				Aba ^= KeccakF_RoundConstants[round + 1];
				Abe = BCe ^ ((~BCi) & BCo);
				Abi = BCi ^ ((~BCo) & BCu);
				Abo = BCo ^ ((~BCu) & BCa);
				Abu = BCu ^ ((~BCa) & BCe);

				Ebo ^= Do;
				BCa = ROL(Ebo, 28);
				Egu ^= Du;
				BCe = ROL(Egu, 20);
				Eka ^= Da;
				BCi = ROL(Eka, 3);
				Eme ^= De;
				BCo = ROL(Eme, 45);
				Esi ^= Di;
				BCu = ROL(Esi, 61);
				Aga = BCa ^ ((~BCe) & BCi);
				Age = BCe ^ ((~BCi) & BCo);
				Agi = BCi ^ ((~BCo) & BCu);
				Ago = BCo ^ ((~BCu) & BCa);
				Agu = BCu ^ ((~BCa) & BCe);

				Ebe ^= De;
				BCa = ROL(Ebe, 1);
				Egi ^= Di;
				BCe = ROL(Egi, 6);
				Eko ^= Do;
				BCi = ROL(Eko, 25);
				Emu ^= Du;
				BCo = ROL(Emu, 8);
				Esa ^= Da;
				BCu = ROL(Esa, 18);
				Aka = BCa ^ ((~BCe) & BCi);
				Ake = BCe ^ ((~BCi) & BCo);
				Aki = BCi ^ ((~BCo) & BCu);
				Ako = BCo ^ ((~BCu) & BCa);
				Aku = BCu ^ ((~BCa) & BCe);

				Ebu ^= Du;
				BCa = ROL(Ebu, 27);
				Ega ^= Da;
				BCe = ROL(Ega, 36);
				Eke ^= De;
				BCi = ROL(Eke, 10);
				Emi ^= Di;
				BCo = ROL(Emi, 15);
				Eso ^= Do;
				BCu = ROL(Eso, 56);
				Ama = BCa ^ ((~BCe) & BCi);
				Ame = BCe ^ ((~BCi) & BCo);
				Ami = BCi ^ ((~BCo) & BCu);
				Amo = BCo ^ ((~BCu) & BCa);
				Amu = BCu ^ ((~BCa) & BCe);

				Ebi ^= Di;
				BCa = ROL(Ebi, 62);
				Ego ^= Do;
				BCe = ROL(Ego, 55);
				Eku ^= Du;
				BCi = ROL(Eku, 39);
				Ema ^= Da;
				BCo = ROL(Ema, 41);
				Ese ^= De;
				BCu = ROL(Ese, 2);
				Asa = BCa ^ ((~BCe) & BCi);
				Ase = BCe ^ ((~BCi) & BCo);
				Asi = BCi ^ ((~BCo) & BCu);
				Aso = BCo ^ ((~BCu) & BCa);
				Asu = BCu ^ ((~BCa) & BCe);
			}

			//copyToState(state, A)
			state[0] = Aba;
			state[1] = Abe;
			state[2] = Abi;
			state[3] = Abo;
			state[4] = Abu;
			state[5] = Aga;
			state[6] = Age;
			state[7] = Agi;
			state[8] = Ago;
			state[9] = Agu;
			state[10] = Aka;
			state[11] = Ake;
			state[12] = Aki;
			state[13] = Ako;
			state[14] = Aku;
			state[15] = Ama;
			state[16] = Ame;
			state[17] = Ami;
			state[18] = Amo;
			state[19] = Amu;
			state[20] = Asa;
			state[21] = Ase;
			state[22] = Asi;
			state[23] = Aso;
			state[24] = Asu;
		}

		/*************************************************
		* Name:        keccak_init
		*
		* Description: Initializes the Keccak state.
		*
		* Arguments:   - ulong *s: pointer to Keccak state
		**************************************************/
		private static void keccak_init(ulong[] s) {
			Debug.Assert(s.Length == 25);

			for (int i = 0; i < 25; i++) {
				s[i] = 0;
			}
		}

		/*************************************************
		* Name:        keccak_absorb
		*
		* Description: Absorb step of Keccak; incremental.
		*
		* Arguments:   - ulong *s: pointer to Keccak state
		*              - unsigned int pos: position in current block to be absorbed
		*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
		*              - const uint8_t *in: pointer to input to be absorbed into s
		*              - int inlen: length of input in bytes
		*
		* Returns new position pos in current block
		**************************************************/
		private static int keccak_absorb(ulong[] s, int pos, int r, byte[] in_buf, int inlen) {
			int in_buf_pos;
			int i;

			in_buf_pos = 0;

			Debug.Assert(s.Length == 25);

			while (pos + inlen >= r) {
				for (i = pos; i < r; i++) {
					s[i / 8] ^= (ulong)in_buf[in_buf_pos++] << (8 * (i % 8));
				}

				inlen -= r - pos;
				KeccakF1600_StatePermute(s);
				pos = 0;
			}

			for (i = pos; i < pos + inlen; i++)
				s[i / 8] ^= (ulong)in_buf[in_buf_pos++] << (8 * (i % 8));

			return i;
		}

		/*************************************************
		* Name:        keccak_finalize
		*
		* Description: Finalize absorb step.
		*
		* Arguments:   - ulong *s: pointer to Keccak state
		*              - unsigned int pos: position in current block to be absorbed
		*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
		*              - uint8_t p: domain separation byte
		**************************************************/
		private static void keccak_finalize(ulong[] s, int pos, int r, byte p) {
			Debug.Assert(s.Length == 25);

			s[pos / 8] ^= (ulong)p << (8 * (pos % 8));
			s[(r / 8) - 1] ^= 1UL << 63;
		}

		/*************************************************
		* Name:        keccak_squeeze
		*
		* Description: Squeeze step of Keccak. Squeezes arbitratrily many bytes.
		*              Modifies the state. Can be called multiple times to keep
		*              squeezing, i.e., is incremental.
		*
		* Arguments:   - uint8_t *out: pointer to output
		*              - int outlen: number of bytes to be squeezed (written to out)
		*              - ulong *s: pointer to input/output Keccak state
		*              - unsigned int pos: number of bytes in current block already squeezed
		*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
		*
		* Returns new position pos in current block
		**************************************************/
		private static int keccak_squeeze(byte[] out_buf, int out_buf_pos, int outlen, ulong[] s, int pos, int r) {
			int i;

			Debug.Assert(s.Length == 25);
			Debug.Assert(out_buf.Length >= outlen);

			while (outlen != 0) {
				if (pos == r) {
					KeccakF1600_StatePermute(s);
					pos = 0;
				}
				for (i = pos; i < r && i < pos + outlen; i++) {
					out_buf[out_buf_pos++] = (byte)(s[i / 8] >> (8 * (i % 8)));
				}
				outlen -= i - pos;
				pos = i;
			}

			return pos;
		}


		/*************************************************
		* Name:        keccak_absorb_once
		*
		* Description: Absorb step of Keccak;
		*              non-incremental, starts by zeroeing the state.
		*
		* Arguments:   - ulong *s: pointer to (uninitialized) output Keccak state
		*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
		*              - const uint8_t *in: pointer to input to be absorbed into s
		*              - int inlen: length of input in bytes
		*              - uint8_t p: domain-separation byte for different Keccak-derived functions
		**************************************************/
		private static void keccak_absorb_once(ulong[] s, int r, byte[] in_buf, int inlen, byte p) {
			int in_buf_pos;
			int i;

			in_buf_pos = 0;

			Debug.Assert(s.Length == 25);

			for (i = 0; i < 25; i++) {
				s[i] = 0;
			}

			while (inlen >= r) {
				for (i = 0; i < r / 8; i++) {
					s[i] ^= load64(in_buf, in_buf_pos + (8 * i));
				}
				in_buf_pos += r;
				inlen -= r;
				KeccakF1600_StatePermute(s);
			}

			for (i = 0; i < inlen; i++) {
				s[i / 8] ^= (ulong)in_buf[i + in_buf_pos] << (8 * (i % 8));
			}

			s[i / 8] ^= (ulong)p << (8 * (i % 8));
			s[(r - 1) / 8] ^= 1UL << 63;
		}

		/*************************************************
		* Name:        keccak_squeezeblocks
		*
		* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
		*              Modifies the state. Can be called multiple times to keep
		*              squeezing, i.e., is incremental. Assumes zero bytes of current
		*              block have already been squeezed.
		*
		* Arguments:   - uint8_t *out: pointer to output blocks
		*              - int nblocks: number of blocks to be squeezed (written to out)
		*              - ulong *s: pointer to input/output Keccak state
		*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
		**************************************************/
		private static void keccak_squeezeblocks(byte[] out_buf, int out_buf_pos, int nblocks, ulong[] s, int r) {
			Debug.Assert(s.Length == 25);

			while (nblocks > 0) {
				KeccakF1600_StatePermute(s);
				for (int i = 0; i < r / 8; i++) {
					store64(out_buf, out_buf_pos + (8 * i), s[i]);
				}
				out_buf_pos += r;
				nblocks -= 1;
			}
		}

		/*************************************************
		* Name:        shake128_init
		*
		* Description: Initilizes Keccak state for use as SHAKE128 XOF
		*
		* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
		**************************************************/
		/// <summary>
		/// Initializes the Keccak state for use as SHAKE128 XOF.
		/// </summary>
		/// <param name="state"></param>
		public static void shake128_init(KeccakState state) {
			keccak_init(state.s);
			state.pos = 0;
		}

		/*************************************************
		* Name:        shake128_absorb
		*
		* Description: Absorb step of the SHAKE128 XOF; incremental.
		*
		* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
		*              - const uint8_t *in: pointer to input to be absorbed into s
		*              - int inlen: length of input in bytes
		**************************************************/
		/// <summary>
		/// Absorb step of the SHAKE128 XOF; incremental.
		/// </summary>
		/// <param name="state"></param>
		/// <param name="in_buf"></param>
		/// <param name="inlen"></param>
		public static void shake128_absorb(KeccakState state, byte[] in_buf, int inlen) {
			state.pos = keccak_absorb(state.s, state.pos, SHAKE128_RATE, in_buf, inlen);
		}

		/*************************************************
		* Name:        shake128_finalize
		*
		* Description: Finalize absorb step of the SHAKE128 XOF.
		*
		* Arguments:   - keccak_state *state: pointer to Keccak state
		**************************************************/
		/// <summary>
		/// Finalize absorb step of the SHAKE128 XOF.
		/// </summary>
		/// <param name="state"></param>
		public static void shake128_finalize(KeccakState state) {
			keccak_finalize(state.s, state.pos, SHAKE128_RATE, 0x1F);
			state.pos = SHAKE128_RATE;
		}

		/*************************************************
		* Name:        shake128_squeeze
		*
		* Description: Squeeze step of SHAKE128 XOF. Squeezes arbitraily many
		*              bytes. Can be called multiple times to keep squeezing.
		*
		* Arguments:   - uint8_t *out: pointer to output blocks
		*              - int outlen : number of bytes to be squeezed (written to output)
		*              - keccak_state *s: pointer to input/output Keccak state
		**************************************************/
		/// <summary>
		/// Squeeze step of SHAKE128 XOF. Squeezes arbitrarily many bytes.
		/// </summary>
		/// <param name="out_buf"></param>
		/// <param name="out_buf_pos"></param>
		/// <param name="outlen"></param>
		/// <param name="state"></param>
		public static void shake128_squeeze(byte[] out_buf, int out_buf_pos, int outlen, KeccakState state) {
			state.pos = keccak_squeeze(out_buf, out_buf_pos, outlen, state.s, state.pos, SHAKE128_RATE);
		}

		/*************************************************
		* Name:        shake128_absorb_once
		*
		* Description: Initialize, absorb into and finalize SHAKE128 XOF; non-incremental.
		*
		* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
		*              - const uint8_t *in: pointer to input to be absorbed into s
		*              - int inlen: length of input in bytes
		**************************************************/
		/// <summary>
		/// Initialize, absorb into and finalize SHAKE128 XOF; non-incremental.
		/// </summary>
		/// <param name="state"></param>
		/// <param name="in_buf"></param>
		/// <param name="inlen"></param>
		public static void shake128_absorb_once(KeccakState state, byte[] in_buf, int inlen) {
			keccak_absorb_once(state.s, SHAKE128_RATE, in_buf, inlen, 0x1F);
			state.pos = SHAKE128_RATE;
		}

		/*************************************************
		* Name:        shake128_squeezeblocks
		*
		* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
		*              SHAKE128_RATE bytes each. Can be called multiple times
		*              to keep squeezing. Assumes new block has not yet been
		*              started (state.pos = SHAKE128_RATE).
		*
		* Arguments:   - uint8_t *out: pointer to output blocks
		*              - int nblocks: number of blocks to be squeezed (written to output)
		*              - keccak_state *s: pointer to input/output Keccak state
		**************************************************/
		/// <summary>
		/// Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes each.
		/// </summary>
		/// <param name="out_buf"></param>
		/// <param name="out_buf_pos"></param>
		/// <param name="nblocks"></param>
		/// <param name="state"></param>
		public static void shake128_squeezeblocks(byte[] out_buf, int out_buf_pos, int nblocks, KeccakState state) {
			keccak_squeezeblocks(out_buf, out_buf_pos, nblocks, state.s, SHAKE128_RATE);
		}

		/*************************************************
		* Name:        shake256_init
		*
		* Description: Initilizes Keccak state for use as SHAKE256 XOF
		*
		* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
		**************************************************/
		/// <summary>
		/// Initializes the Keccak state for use as SHAKE256 XOF.
		/// </summary>
		/// <param name="state"></param>
		public static void shake256_init(KeccakState state) {
			keccak_init(state.s);
			state.pos = 0;
		}

		/*************************************************
		* Name:        shake256_absorb
		*
		* Description: Absorb step of the SHAKE256 XOF; incremental.
		*
		* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
		*              - const uint8_t *in: pointer to input to be absorbed into s
		*              - int inlen: length of input in bytes
		**************************************************/
		/// <summary>
		/// Absorb step of the SHAKE256 XOF; incremental.
		/// </summary>
		/// <param name="state"></param>
		/// <param name="in_buf"></param>
		/// <param name="inlen"></param>
		public static void shake256_absorb(KeccakState state, byte[] in_buf, int inlen) {
			state.pos = keccak_absorb(state.s, state.pos, SHAKE256_RATE, in_buf, inlen);
		}

		/*************************************************
		* Name:        shake256_finalize
		*
		* Description: Finalize absorb step of the SHAKE256 XOF.
		*
		* Arguments:   - keccak_state *state: pointer to Keccak state
		**************************************************/
		/// <summary>
		/// Finalize absorb step of the SHAKE256 XOF.
		/// </summary>
		/// <param name="state"></param>
		public static void shake256_finalize(KeccakState state) {
			keccak_finalize(state.s, state.pos, SHAKE256_RATE, 0x1F);
			state.pos = SHAKE256_RATE;
		}

		/*************************************************
		* Name:        shake256_squeeze
		*
		* Description: Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
		*              bytes. Can be called multiple times to keep squeezing.
		*
		* Arguments:   - uint8_t *out: pointer to output blocks
		*              - int outlen : number of bytes to be squeezed (written to output)
		*              - keccak_state *s: pointer to input/output Keccak state
		**************************************************/
		/// <summary>
		/// Squeeze step of SHAKE256 XOF. Squeezes arbitrarily many bytes.
		/// </summary>
		/// <param name="out_buf"></param>
		/// <param name="out_buf_pos"></param>
		/// <param name="outlen"></param>
		/// <param name="state"></param>
		public static void shake256_squeeze(byte[] out_buf, int out_buf_pos, int outlen, KeccakState state) {
			state.pos = keccak_squeeze(out_buf, out_buf_pos, outlen, state.s, state.pos, SHAKE256_RATE);
		}

		/*************************************************
		* Name:        shake256_absorb_once
		*
		* Description: Initialize, absorb into and finalize SHAKE256 XOF; non-incremental.
		*
		* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
		*              - const uint8_t *in: pointer to input to be absorbed into s
		*              - int inlen: length of input in bytes
		**************************************************/
		/// <summary>
		/// Initialize, absorb into and finalize SHAKE256 XOF; non-incremental.
		/// </summary>
		/// <param name="state"></param>
		/// <param name="in_buf"></param>
		/// <param name="inlen"></param>
		public static void shake256_absorb_once(KeccakState state, byte[] in_buf, int inlen) {
			keccak_absorb_once(state.s, SHAKE256_RATE, in_buf, inlen, 0x1F);
			state.pos = SHAKE256_RATE;
		}

		/*************************************************
		* Name:        shake256_squeezeblocks
		*
		* Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
		*              SHAKE256_RATE bytes each. Can be called multiple times
		*              to keep squeezing. Assumes next block has not yet been
		*              started (state.pos = SHAKE256_RATE).
		*
		* Arguments:   - uint8_t *out: pointer to output blocks
		*              - int nblocks: number of blocks to be squeezed (written to output)
		*              - keccak_state *s: pointer to input/output Keccak state
		**************************************************/
		/// <summary>
		/// Squeeze step of SHAKE256 XOF. Squeezes full blocks of SHAKE256_RATE bytes each.
		/// </summary>
		/// <param name="out_buf"></param>
		/// <param name="out_buf_pos"></param>
		/// <param name="nblocks"></param>
		/// <param name="state"></param>
		public static void shake256_squeezeblocks(byte[] out_buf, int out_buf_pos, int nblocks, KeccakState state) {
			keccak_squeezeblocks(out_buf, out_buf_pos, nblocks, state.s, SHAKE256_RATE);
		}

		/*************************************************
		* Name:        shake128
		*
		* Description: SHAKE128 XOF with non-incremental API
		*
		* Arguments:   - uint8_t *out: pointer to output
		*              - int outlen: requested output length in bytes
		*              - const uint8_t *in: pointer to input
		*              - int inlen: length of input in bytes
		**************************************************/
		/// <summary>
		/// SHAKE128 XOF with non-incremental API.
		/// </summary>
		/// <param name="out_buf"></param>
		/// <param name="outlen"></param>
		/// <param name="in_buf"></param>
		/// <param name="inlen"></param>
		public static void shake128(byte[] out_buf, int outlen, byte[] in_buf, int inlen) {
			KeccakState state;
			int out_buf_pos;
			int nblocks;

			state = new KeccakState();

			shake128_absorb_once(state, in_buf, inlen);
			nblocks = outlen / SHAKE128_RATE;
			shake128_squeezeblocks(out_buf, 0, nblocks, state);
			outlen -= nblocks * SHAKE128_RATE;
			out_buf_pos = nblocks * SHAKE128_RATE;
			shake128_squeeze(out_buf, out_buf_pos, outlen, state);
		}

		/*************************************************
		* Name:        shake256
		*
		* Description: SHAKE256 XOF with non-incremental API
		*
		* Arguments:   - uint8_t *out: pointer to output
		*              - int outlen: requested output length in bytes
		*              - const uint8_t *in: pointer to input
		*              - int inlen: length of input in bytes
		**************************************************/
		/// <summary>
		/// SHAKE256 XOF with non-incremental API.
		/// </summary>
		/// <param name="out_buf"></param>
		/// <param name="outlen"></param>
		/// <param name="in_buf"></param>
		/// <param name="inlen"></param>
		public static void shake256(byte[] out_buf, int outlen, byte[] in_buf, int inlen) {
			KeccakState state;
			int out_buf_pos;
			int nblocks;

			state = new KeccakState();

			shake256_absorb_once(state, in_buf, inlen);
			nblocks = outlen / SHAKE256_RATE;
			shake256_squeezeblocks(out_buf, 0, nblocks, state);
			outlen -= nblocks * SHAKE256_RATE;
			out_buf_pos = nblocks * SHAKE256_RATE;
			shake256_squeeze(out_buf, out_buf_pos, outlen, state);
		}

		/*************************************************
		* Name:        sha3_256
		*
		* Description: SHA3-256 with non-incremental API
		*
		* Arguments:   - uint8_t *h: pointer to output (32 bytes)
		*              - const uint8_t *in: pointer to input
		*              - int inlen: length of input in bytes
		**************************************************/
		/// <summary>
		/// SHA3-256 with non-incremental API.
		/// </summary>
		/// <param name="h"></param>
		/// <param name="in_buf"></param>
		/// <param name="inlen"></param>
		public static void sha3_256(out byte[] h, byte[] in_buf, int inlen) {
			ulong[] s;

			s = new ulong[25];
			h = new byte[32];

			keccak_absorb_once(s, SHA3_256_RATE, in_buf, inlen, 0x06);
			KeccakF1600_StatePermute(s);
			for (int i = 0; i < 4; i++) {
				store64(h, 8 * i, s[i]);
			}
		}

		/*************************************************
		* Name:        sha3_512
		*
		* Description: SHA3-512 with non-incremental API
		*
		* Arguments:   - uint8_t *h: pointer to output (64 bytes)
		*              - const uint8_t *in: pointer to input
		*              - int inlen: length of input in bytes
		**************************************************/
		/// <summary>
		/// SHA3-512 with non-incremental API.
		/// </summary>
		/// <param name="h"></param>
		/// <param name="in_buf"></param>
		/// <param name="inlen"></param>
		public static void sha3_512(out byte[] h, byte[] in_buf, int inlen) {
			ulong[] s;

			s = new ulong[25];
			h = new byte[64];

			keccak_absorb_once(s, SHA3_512_RATE, in_buf, inlen, 0x06);
			KeccakF1600_StatePermute(s);
			for (int i = 0; i < 8; i++) {
				store64(h, 8 * i, s[i]);
			}
		}
	}
}