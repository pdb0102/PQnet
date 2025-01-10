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

using System.Diagnostics;

namespace PQnet.Digest {
	/// <summary>
	/// Implements the FIPS 202 Secure Hash Algorithm Keccak (SHAKE) extendable-output base functionality
	/// </summary>
	public abstract class KeccakBase {
		/* Based on the public domain implementation in crypto_hash/keccakc512/simple/ from
		 * http://bench.cr.yp.to/supercop.html by Ronny Van Keer and the public domain "TweetFips202"
		 * implementation from https://twitter.com/tweetfips202 by Gilles Van Assche, Daniel J. Bernstein,
		 * and Peter Schwabe */

		private const int TotalRounds = 24;

		/// <summary>
		/// The SHAKE-128 lane size in bytes.
		/// </summary>
		public const int Shake128Rate = 168;

		/// <summary>
		/// The SHAKE-256 lane size in bytes.
		/// </summary>
		public const int Shake256Rate = 136;

		/// <summary>
		/// The SHA3-224 lane size in bytes.
		/// </summary>
		public const int Sha3_224Rate = 144;

		/// <summary>
		/// The SHA3-256 lane size in bytes.
		/// </summary>
		public const int Sha3_256Rate = 136;

		/// <summary>
		/// The SHA3-384 lane size in bytes.
		/// </summary>
		public const int Sha3_384Rate = 104;

		/// <summary>
		/// The SHA3-512 lane size in bytes.
		/// </summary>
		public const int Sha3_512Rate = 72;


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
		/// The Keccak sponge state
		/// </summary>
		protected ulong[] state;

		/// <summary>
		/// Position in current block
		/// </summary>
		protected int pos;

		/// <summary>
		/// Rate in bytes
		/// </summary>
		protected int rate;

		/// <summary>
		/// Domain separator
		/// </summary>
		protected byte prefix;

		/// <summary>
		/// Instantiates a new KeccakBase object
		/// </summary>
		protected KeccakBase() {
			state = new ulong[25];
		}

		/// <summary>
		/// Perform the Keccak F1600 permutation on the state
		/// </summary>
		public void StatePermute() {
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

			for (int round = 0; round < TotalRounds; round += 2) {
				//    prepareTheta
				BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
				BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
				BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
				BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
				BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

				//thetaRhoPiChiIotaPrepareTheta(round, A, E)
				Da = BCu ^ (BCe << 1) ^ (BCe >> (64 - 1));
				De = BCa ^ (BCi << 1) ^ (BCi >> (64 - 1));
				Di = BCe ^ (BCo << 1) ^ (BCo >> (64 - 1));
				Do = BCi ^ (BCu << 1) ^ (BCu >> (64 - 1));
				Du = BCo ^ (BCa << 1) ^ (BCa >> (64 - 1));

				Aba ^= Da;
				BCa = Aba;
				Age ^= De;
				BCe = (Age << 44) ^ (Age >> (64 - 44));
				Aki ^= Di;
				BCi = (Aki << 43) ^ (Aki >> (64 - 43));
				Amo ^= Do;
				BCo = (Amo << 21) ^ (Amo >> (64 - 21));
				Asu ^= Du;
				BCu = (Asu << 14) ^ (Asu >> (64 - 14));
				Eba = BCa ^ ((~BCe) & BCi);
				Eba ^= KeccakF_RoundConstants[round];
				Ebe = BCe ^ ((~BCi) & BCo);
				Ebi = BCi ^ ((~BCo) & BCu);
				Ebo = BCo ^ ((~BCu) & BCa);
				Ebu = BCu ^ ((~BCa) & BCe);

				Abo ^= Do;
				BCa = (Abo << 28) ^ (Abo >> (64 - 28));
				Agu ^= Du;
				BCe = (Agu << 20) ^ (Agu >> (64 - 20));
				Aka ^= Da;
				BCi = (Aka << 3) ^ (Aka >> (64 - 3));
				Ame ^= De;
				BCo = (Ame << 45) ^ (Ame >> (64 - 45));
				Asi ^= Di;
				BCu = (Asi << 61) ^ (Asi >> (64 - 61));
				Ega = BCa ^ ((~BCe) & BCi);
				Ege = BCe ^ ((~BCi) & BCo);
				Egi = BCi ^ ((~BCo) & BCu);
				Ego = BCo ^ ((~BCu) & BCa);
				Egu = BCu ^ ((~BCa) & BCe);

				Abe ^= De;
				BCa = (Abe << 1) ^ (Abe >> (64 - 1));
				Agi ^= Di;
				BCe = (Agi << 6) ^ (Agi >> (64 - 6));
				Ako ^= Do;
				BCi = (Ako << 25) ^ (Ako >> (64 - 25));
				Amu ^= Du;
				BCo = (Amu << 8) ^ (Amu >> (64 - 8));
				Asa ^= Da;
				BCu = (Asa << 18) ^ (Asa >> (64 - 18));
				Eka = BCa ^ ((~BCe) & BCi);
				Eke = BCe ^ ((~BCi) & BCo);
				Eki = BCi ^ ((~BCo) & BCu);
				Eko = BCo ^ ((~BCu) & BCa);
				Eku = BCu ^ ((~BCa) & BCe);

				Abu ^= Du;
				BCa = (Abu << 27) ^ (Abu >> (64 - 27));
				Aga ^= Da;
				BCe = (Aga << 36) ^ (Aga >> (64 - 36));
				Ake ^= De;
				BCi = (Ake << 10) ^ (Ake >> (64 - 10));
				Ami ^= Di;
				BCo = (Ami << 15) ^ (Ami >> (64 - 15));
				Aso ^= Do;
				BCu = (Aso << 56) ^ (Aso >> (64 - 56));
				Ema = BCa ^ ((~BCe) & BCi);
				Eme = BCe ^ ((~BCi) & BCo);
				Emi = BCi ^ ((~BCo) & BCu);
				Emo = BCo ^ ((~BCu) & BCa);
				Emu = BCu ^ ((~BCa) & BCe);

				Abi ^= Di;
				BCa = (Abi << 62) ^ (Abi >> (64 - 62));
				Ago ^= Do;
				BCe = (Ago << 55) ^ (Ago >> (64 - 55));
				Aku ^= Du;
				BCi = (Aku << 39) ^ (Aku >> (64 - 39));
				Ama ^= Da;
				BCo = (Ama << 41) ^ (Ama >> (64 - 41));
				Ase ^= De;
				BCu = (Ase << 2) ^ (Ase >> (64 - 2));
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
				Da = BCu ^ (BCe << 1) ^ (BCe >> (64 - 1));
				De = BCa ^ (BCi << 1) ^ (BCi >> (64 - 1));
				Di = BCe ^ (BCo << 1) ^ (BCo >> (64 - 1));
				Do = BCi ^ (BCu << 1) ^ (BCu >> (64 - 1));
				Du = BCo ^ (BCa << 1) ^ (BCa >> (64 - 1));

				Eba ^= Da;
				BCa = Eba;
				Ege ^= De;
				BCe = (Ege << 44) ^ (Ege >> (64 - 44));
				Eki ^= Di;
				BCi = (Eki << 43) ^ (Eki >> (64 - 43));
				Emo ^= Do;
				BCo = (Emo << 21) ^ (Emo >> (64 - 21));
				Esu ^= Du;
				BCu = (Esu << 14) ^ (Esu >> (64 - 14));
				Aba = BCa ^ ((~BCe) & BCi);
				Aba ^= KeccakF_RoundConstants[round + 1];
				Abe = BCe ^ ((~BCi) & BCo);
				Abi = BCi ^ ((~BCo) & BCu);
				Abo = BCo ^ ((~BCu) & BCa);
				Abu = BCu ^ ((~BCa) & BCe);

				Ebo ^= Do;
				BCa = (Ebo << 28) ^ (Ebo >> (64 - 28));
				Egu ^= Du;
				BCe = (Egu << 20) ^ (Egu >> (64 - 20));
				Eka ^= Da;
				BCi = (Eka << 3) ^ (Eka >> (64 - 3));
				Eme ^= De;
				BCo = (Eme << 45) ^ (Eme >> (64 - 45));
				Esi ^= Di;
				BCu = (Esi << 61) ^ (Esi >> (64 - 61));
				Aga = BCa ^ ((~BCe) & BCi);
				Age = BCe ^ ((~BCi) & BCo);
				Agi = BCi ^ ((~BCo) & BCu);
				Ago = BCo ^ ((~BCu) & BCa);
				Agu = BCu ^ ((~BCa) & BCe);

				Ebe ^= De;
				BCa = (Ebe << 1) ^ (Ebe >> (64 - 1));
				Egi ^= Di;
				BCe = (Egi << 6) ^ (Egi >> (64 - 6));
				Eko ^= Do;
				BCi = (Eko << 25) ^ (Eko >> (64 - 25));
				Emu ^= Du;
				BCo = (Emu << 8) ^ (Emu >> (64 - 8));
				Esa ^= Da;
				BCu = (Esa << 18) ^ (Esa >> (64 - 18));
				Aka = BCa ^ ((~BCe) & BCi);
				Ake = BCe ^ ((~BCi) & BCo);
				Aki = BCi ^ ((~BCo) & BCu);
				Ako = BCo ^ ((~BCu) & BCa);
				Aku = BCu ^ ((~BCa) & BCe);

				Ebu ^= Du;
				BCa = (Ebu << 27) ^ (Ebu >> (64 - 27));
				Ega ^= Da;
				BCe = (Ega << 36) ^ (Ega >> (64 - 36));
				Eke ^= De;
				BCi = (Eke << 10) ^ (Eke >> (64 - 10));
				Emi ^= Di;
				BCo = (Emi << 15) ^ (Emi >> (64 - 15));
				Eso ^= Do;
				BCu = (Eso << 56) ^ (Eso >> (64 - 56));
				Ama = BCa ^ ((~BCe) & BCi);
				Ame = BCe ^ ((~BCi) & BCo);
				Ami = BCi ^ ((~BCo) & BCu);
				Amo = BCo ^ ((~BCu) & BCa);
				Amu = BCu ^ ((~BCa) & BCe);

				Ebi ^= Di;
				BCa = (Ebi << 62) ^ (Ebi >> (64 - 62));
				Ego ^= Do;
				BCe = (Ego << 55) ^ (Ego >> (64 - 55));
				Eku ^= Du;
				BCi = (Eku << 39) ^ (Eku >> (64 - 39));
				Ema ^= Da;
				BCo = (Ema << 41) ^ (Ema >> (64 - 41));
				Ese ^= De;
				BCu = (Ese << 2) ^ (Ese >> (64 - 2));
				Asa = BCa ^ ((~BCe) & BCi);
				Ase = BCe ^ ((~BCi) & BCo);
				Asi = BCi ^ ((~BCo) & BCu);
				Aso = BCo ^ ((~BCu) & BCa);
				Asu = BCu ^ ((~BCa) & BCe);
			}

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

		/// <summary>
		/// Initializes the Keccak state
		/// </summary>
		public virtual void Init() {
			for (int i = 0; i < 25; i++) {
				state[i] = 0;
			}
			pos = 0;
		}

		/// <summary>
		/// Absorb data into the Keccak state
		/// </summary>
		/// <param name="in_buf">The data to absorb</param>
		/// <param name="inlen">The number of bytes to absorb from <paramref name="inlen"/></param>
		/// <returns>The new position in the current block</returns>
		/// <remarks>Updates the position in the current block</remarks>
		public virtual int Absorb(byte[] in_buf, int inlen) {
			int in_buf_pos;
			int i;

			in_buf_pos = 0;

			while (pos + inlen >= rate) {
				for (i = pos; i < rate; i++) {
					state[i / 8] ^= (ulong)in_buf[in_buf_pos++] << (8 * (i % 8));
				}

				inlen -= rate - pos;
				StatePermute();
				pos = 0;
			}

			for (i = pos; i < pos + inlen; i++) {
				state[i / 8] ^= (ulong)in_buf[in_buf_pos++] << (8 * (i % 8));
			}

			pos = i;

			return i;
		}

		/// <summary>
		/// Finalizes the absorb step
		/// </summary>
		/// <remarks>This method absorbs the prefix (domain separation byte) and end-marker into the state. Updates the position to the end of the current block.</remarks>
		public virtual void FinalizeAbsorb() {
			state[pos / 8] ^= (ulong)prefix << (8 * (pos % 8));
			state[(rate / 8) - 1] ^= 1UL << 63;
			pos = rate;
		}

		/// <summary>
		/// Squeeze data from the Keccak state
		/// </summary>
		/// <param name="out_buf">The buffer to store squeeded bytes</param>
		/// <param name="out_buf_pos">The index into <paramref name="out_buf"/> where to start storing squeezed bytes</param>
		/// <param name="outlen">The number of bytes to squeeze out</param>
		/// <returns>The new position in current block</returns>
		public virtual int Squeeze(byte[] out_buf, int out_buf_pos, int outlen) {
			int i;

			Debug.Assert(out_buf.Length >= outlen);

			while (outlen != 0) {
				if (pos == rate) {
					StatePermute();
					pos = 0;
				}
				for (i = pos; i < rate && i < pos + outlen; i++) {
					out_buf[out_buf_pos++] = (byte)(state[i / 8] >> (8 * (i % 8)));
				}
				outlen -= i - pos;
				pos = i;
			}

			return pos;
		}

		/// <summary>
		/// Absorb data into the Keccak state and finalize the absorb step
		/// </summary>
		/// <param name="in_buf">The data to absorb</param>
		/// <param name="inlen">The number of bytes to absorb from <paramref name="in_buf"/></param>
		/// <remarks>Updates the position in the current block to the end of the block</remarks>
		public virtual void AbsorbOnce(byte[] in_buf, int inlen) {
			int offset;
			int i;

			for (i = 0; i < 25; i++) {
				state[i] = 0;
			}

			offset = 0;
			while (inlen >= rate) {
				for (i = 0; i < rate / 8; i++) {
					state[i] ^= in_buf[offset++] | ((ulong)in_buf[offset++] << 8) | ((ulong)in_buf[offset++] << 16) | ((ulong)in_buf[offset++] << 24) | ((ulong)in_buf[offset++] << 32) | ((ulong)in_buf[offset++] << 40) | ((ulong)in_buf[offset++] << 48) | ((ulong)in_buf[offset++] << 56);
				}
				inlen -= rate;
				StatePermute();
			}

			for (i = 0; i < inlen; i++) {
				state[i / 8] ^= (ulong)in_buf[offset++] << (8 * (i % 8));
			}

			state[i / 8] ^= (ulong)prefix << (8 * (i % 8));
			state[(rate - 1) / 8] ^= 1UL << 63;

			pos = rate;
		}

		/// <summary>
		/// Squeeze full blocks of <see cref="rate"/> bytes each
		/// </summary>
		/// <param name="out_buf">The buffer to store squeeded bytes</param>
		/// <param name="out_buf_pos">The index into <paramref name="out_buf"/> where to start storing squeezed bytes</param>
		/// <param name="nblocks"></param>
		/// <returns>Number of bytes stored in <paramref name="out_buf"/></returns>
		/// <remarks>Starts squeezing at the beginning of the current block (assumes nothing has been squeezed from the current block yet). Can be called multiple times.</remarks>
		public virtual int SqueezeBlocks(byte[] out_buf, int out_buf_pos, int nblocks) {
			int offset;

			offset = 0;
			while (nblocks > 0) {
				StatePermute();
				for (int i = 0; i < rate / 8; i++) {
					out_buf[offset++] = (byte)state[i];
					out_buf[offset++] = (byte)(state[i] >> 8);
					out_buf[offset++] = (byte)(state[i] >> 16);
					out_buf[offset++] = (byte)(state[i] >> 24);
					out_buf[offset++] = (byte)(state[i] >> 32);
					out_buf[offset++] = (byte)(state[i] >> 40);
					out_buf[offset++] = (byte)(state[i] >> 48);
					out_buf[offset++] = (byte)(state[i] >> 56);
				}
				nblocks -= 1;
			}

			return offset;
		}

		/// <summary>
		/// One-shot compute of the hash of the input data
		/// </summary>
		/// <param name="out_buf">The buffer receiving the hash</param>
		/// <param name="outlen">The desired length of the hash</param>
		/// <param name="input">The data for which to compute the hash</param>
		/// <param name="inlen">The number of bytes to consume from <paramref name="input"/></param>
		/// <returns>The SHAKE hash for <paramref name="input"/></returns>
		/// <remarks>Resets any existing state on input</remarks>
		public virtual void Hash(byte[] out_buf, int outlen, byte[] input, int inlen) {
			int blocks;

			Init();

			AbsorbOnce(input, inlen);

			blocks = outlen / rate;
			if (blocks > 0) {
				int out_pos;

				out_pos = SqueezeBlocks(out_buf, 0, blocks);
				Squeeze(out_buf, out_pos, outlen - out_pos);
				return;
			}

			Squeeze(out_buf, 0, outlen);
		}

	}
}