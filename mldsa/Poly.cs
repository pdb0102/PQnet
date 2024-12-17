using System.Diagnostics;

namespace mldsa_net;
public abstract partial class DilithiumBase {
	private const int POLY_UNIFORM_NBLOCKS = (768 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES;

	private int POLY_UNIFORM_ETA_NBLOCKS {
		get {
			if (Eta == 2) {
				return (136 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES;
			} else if (Eta == 4) {
				return (227 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES;
			} else {
				throw new Exception("Invalid Eta");
			}
		}
	}

	private int POLY_UNIFORM_GAMMA1_NBLOCKS {
		get {
			return (PolyZPackedBytes + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES;
		}
	}

	public class poly {
		private int n;

		public poly(int N) {
			n = N;

			coeffs = new int[N];
		}

		public poly Clone() {
			poly clone;

			clone = new poly(n);
			for (int i = 0; i < n; i++) {
				clone.coeffs[i] = coeffs[i];
			}
			return clone;
		}

		public int[] coeffs;
	}

	/// <summary>
	/// Inplace reduction of all coefficients of polynomial to representative in [-6283008,6283008].
	/// </summary>
	/// <param name="a">polynominal</param>
	public void poly_reduce(poly a) {
		for (int i = 0; i < N; i++) {
			a.coeffs[i] = reduce32(a.coeffs[i]);
		}
	}

	/// <summary>
	/// For all coefficients of in/out polynomial add Q if coefficient is negative.
	/// </summary>
	/// <param name="a">polynominal</param>
	public void poly_caddq(poly a) {
		for (int i = 0; i < N; i++) {
			a.coeffs[i] = caddq(a.coeffs[i]);
		}
	}

	/// <summary>
	/// Add polynomials. No modular reduction is performed.
	/// </summary>
	/// <param name="c">Output polynominal</param>
	/// <param name="a">First summand</param>
	/// <param name="b">Second summand</param>
	public void poly_add(poly c, poly a, poly b) {
		for (int i = 0; i < N; i++) {
			c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
		}
	}

	/// <summary>
	/// Subtract polynomials. No modular reduction is performed.
	/// </summary>
	/// <param name="c">Output polynominal</param>
	/// <param name="a">First polynominal</param>
	/// <param name="b">Second polynominal to be subtracted from first</param>
	public void poly_sub(poly c, poly a, poly b) {
		for (int i = 0; i < N; i++) {
			c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
		}
	}

	/// <summary>
	/// Multiply polynomial by 2^D without modular reduction. 
	/// </summary>
	/// <param name="a">Polynominal</param>
	/// <remarks>
	/// Multiply polynomial by 2^D without modular reduction. 
	/// </remarks>
	public void poly_shiftl(poly a) {
		for (int i = 0; i < N; i++) {
			a.coeffs[i] <<= D;
		}
	}

	/// <summary>
	/// Inplace forward NTT. Coefficients can grow by 8*Q in absolute value.
	/// </summary>
	/// <param name="a">Polynominal</param>
	public void poly_ntt(poly a) {
		ntt(a.coeffs);
	}

	/// <summary>
	/// Inplace inverse NTT and multiplication by 2^{32}.
	/// </summary>
	/// <param name="a"></param>
	/// <remarks>
	/// Input coefficients need to be less than Q in absolute value and output coefficients are again bounded by Q.
	/// </remarks>
	public void poly_invntt_tomont(poly a) {
		invntt_tomont(a.coeffs);
	}

	/// <summary>
	/// Pointwise multiplication of polynomials in NTT domain representation and multiplication of resulting polynomial by 2^{-32}.
	/// </summary>
	/// <param name="c">Output polynominal</param>
	/// <param name="a">First polynominal</param>
	/// <param name="b">Second polynominal</param>
	public void poly_pointwise_montgomery(poly c, poly a, poly b) {
		for (int i = 0; i < N; i++) {
			c.coeffs[i] = montgomery_reduce((long)a.coeffs[i] * b.coeffs[i]);
		}
	}

	/// <summary>
	/// For all coefficients c of the input polynomial, compute c0, c1 such that c mod Q = c1*2^D + c0 with -2^{D-1} < c0 <= 2^{D-1}. 
	/// </summary>
	/// <param name="a1">polynomial with coefficients c1</param>
	/// <param name="a0">polynomial with coefficients c0</param>
	/// <param name="a">input polynomial</param>
	/// <remarks>
	/// Assumes coefficients to be standard representatives.
	/// </remarks>
	public void poly_power2round(poly a1, poly a0, poly a) {
		for (int i = 0; i < N; i++) {
			a1.coeffs[i] = power2round(out a0.coeffs[i], a.coeffs[i]);
		}
	}

	/// <summary>
	/// For all coefficients c of the input polynomial, compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0 with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
	/// </summary>
	/// <param name="a1"></param>
	/// <param name="a0"></param>
	/// <param name="a"></param>
	/// <remarks>
	/// Assumes coefficients to be standard representatives.
	/// </remarks>
	public void poly_decompose(poly a1, poly a0, poly a) {
		for (int i = 0; i < N; i++) {
			a1.coeffs[i] = decompose(out a0.coeffs[i], a.coeffs[i]);
		}
	}

	/// <summary>
	/// Compute hint polynomial. The coefficients of which indicate whether the low bits of the corresponding coefficient of the input polynomial overflow into the high bits.
	/// </summary>
	/// <param name="h">output hint polynomial</param>
	/// <param name="a0">low part of input polynomial</param>
	/// <param name="a1">high part of input polynomial</param>
	/// <returns>number of 1 bits</returns>
	public uint poly_make_hint(poly h, poly a0, poly a1) {
		uint s;

		s = 0;

		for (int i = 0; i < N; i++) {
			h.coeffs[i] = make_hint(a0.coeffs[i], a1.coeffs[i]);
			s += (uint)h.coeffs[i];
		}

		return s;
	}


	/// <summary>
	/// Use hint polynomial to correct the high bits of a polynomial
	/// </summary>
	/// <param name="b">output polynomial with corrected high bits</param>
	/// <param name="a">input polynomial</param>
	/// <param name="h">input hint polynomial</param>
	public void poly_use_hint(poly b, poly a, poly h) {
		for (int i = 0; i < N; i++) {
			b.coeffs[i] = use_hint(a.coeffs[i], h.coeffs[i]);
		}
	}

	/// <summary>
	/// Check infinity norm of polynomial against given bound.
	/// </summary>
	/// <param name="a">polynomial</param>
	/// <param name="B">norm bound</param>
	/// <returns>0 if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.</returns>
	/// <remarks>
	/// Assumes input coefficients were reduced by reduce32().
	/// </remarks>
	public int poly_chknorm(poly a, int B) {
		long t;

		if (B > (Q - 1) / 8) {
			return 1;
		}

		// It is ok to leak which coefficient violates the bound since
		// the probability for each coefficient is independent of secret
		// data but we must not leak the sign of the centralized representative.

		for (int i = 0; i < N; i++) {
			/* Absolute value */
			t = a.coeffs[i] >> 31;
			t = a.coeffs[i] - (t & (2 * a.coeffs[i]));

			if (t >= B) {
				return 1;
			}
		}

		return 0;
	}

	/// <summary>
	/// Sample uniformly random coefficients in [0, Q-1] by performing rejection sampling on array of random bytes
	/// </summary>
	/// <param name="a">output array</param>
	/// <param name="len">number of coefficients to be sampled</param>
	/// <param name="buf">array of random bytes</param>
	/// <returns></returns>
	public int rej_uniform(int[] a, int a_offset, int len, byte[] buf, int buflen) {
		int ctr;
		int pos;
		uint t;

		ctr = pos = 0;
		while ((ctr < len) && ((pos + 3) <= buflen)) {
			t = buf[pos++];
			t |= (uint)buf[pos++] << 8;
			t |= (uint)buf[pos++] << 16;
			t &= 0x7FFFFF;

			if (t < Q) {
				a[a_offset + ctr++] = (int)t;
			}
		}

		return ctr;
	}

	/*************************************************
* Name:        poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [0,Q-1] by performing rejection sampling on the
*              output stream of SHAKE128(seed|nonce)
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length SEEDBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
	private void poly_uniform(poly a, byte[] seed, ushort nonce) {
		int off;
		int ctr;
		int buflen;
		byte[] buf;
		keccak_state state;

		buflen = POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES;
		buf = new byte[(POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES) + 2];

		state = new keccak_state();

		dilithium_shake128_stream_init(state, seed, nonce);
		shake128_squeezeblocks(buf, 0, POLY_UNIFORM_NBLOCKS, state);

		ctr = rej_uniform(a.coeffs, 0, N, buf, buflen);

		while (ctr < N) {
			off = buflen % 3;
			for (int i = 0; i < off; i++) {
				buf[i] = buf[buflen - off + i];
			}

			shake128_squeezeblocks(buf, off, 1, state);
			buflen = STREAM128_BLOCKBYTES + off;
			ctr += rej_uniform(a.coeffs, ctr, N - ctr, buf, buflen);
		}
	}

	/*************************************************
	* Name:        rej_eta
	*
	* Description: Sample uniformly random coefficients in [-ETA, ETA] by
	*              performing rejection sampling on array of random bytes.
	*
	* Arguments:   - int32_t *a: pointer to output array (allocated)
	*              - unsigned int len: number of coefficients to be sampled
	*              - const uint8_t *buf: array of random bytes
	*              - unsigned int buflen: length of array of random bytes
	*
	* Returns number of sampled coefficients. Can be smaller than len if not enough
	* random bytes were given.
	**************************************************/
	private int rej_eta(int[] a, int a_offset, int len, byte[] buf, int buflen) {
		int ctr;
		int pos;
		int t0;
		int t1;

		ctr = 0;
		pos = 0;

		// FIXME - move Eta if outside and dup while
		while (ctr < len && pos < buflen) {
			t0 = buf[pos] & 0x0F;
			t1 = buf[pos++] >> 4;

			if (Eta == 2) {
				if (t0 < 15) {
					t0 = t0 - (((205 * t0) >> 10) * 5);
					a[a_offset + ctr++] = 2 - t0;
				}
				if (t1 < 15 && ctr < len) {
					t1 = t1 - (((205 * t1) >> 10) * 5);
					a[a_offset + ctr++] = 2 - t1;
				}
			} else if (Eta == 4) {
				if (t0 < 9) {
					a[a_offset + ctr++] = 4 - t0;
				}
				if (t1 < 9 && ctr < len) {
					a[a_offset + ctr++] = 4 - t1;
				}
			} else {
				throw new Exception("Invalid Eta");
			}
		}
		return ctr;
	}

	/*************************************************
	* Name:        poly_uniform_eta
	*
	* Description: Sample polynomial with uniformly random coefficients
	*              in [-ETA,ETA] by performing rejection sampling on the
	*              output stream from SHAKE256(seed|nonce)
	*
	* Arguments:   - poly *a: pointer to output polynomial
	*              - const uint8_t seed[]: byte array with seed of length CRHBYTES
	*              - uint16_t nonce: 2-byte nonce
	**************************************************/
	private void poly_uniform_eta(poly a, byte[] seed, ushort nonce) {
		byte[] buf;
		int buflen;
		int ctr;
		keccak_state state;

		Debug.Assert(seed.Length == CrhBytes);

		state = new keccak_state();
		buflen = POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES;
		buf = new byte[POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES];

		dilithium_shake256_stream_init(state, seed, nonce);
		shake256_squeezeblocks(buf, 0, POLY_UNIFORM_ETA_NBLOCKS, state);

		ctr = rej_eta(a.coeffs, 0, N, buf, buflen);

		while (ctr < N) {
			shake256_squeezeblocks(buf, 0, 1, state);
			ctr += rej_eta(a.coeffs, ctr, N - ctr, buf, STREAM256_BLOCKBYTES);
		}
	}

	/*************************************************
	* Name:        poly_uniform_gamma1m1
	*
	* Description: Sample polynomial with uniformly random coefficients
	*              in [-(GAMMA1 - 1), GAMMA1] by unpacking output stream
	*              of SHAKE256(seed|nonce)
	*
	* Arguments:   - poly *a: pointer to output polynomial
	*              - const uint8_t seed[]: byte array with seed of length CRHBYTES
	*              - uint16_t nonce: 16-bit nonce
	**************************************************/
	private void poly_uniform_gamma1(poly a, byte[] seed, ushort nonce) {
		byte[] buf;
		keccak_state state;

		Debug.Assert(seed.Length == CrhBytes);

		state = new keccak_state();
		buf = new byte[POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES];

		dilithium_shake256_stream_init(state, seed, nonce);
		shake256_squeezeblocks(buf, 0, POLY_UNIFORM_GAMMA1_NBLOCKS, state);
		polyz_unpack(a, buf, 0);
	}

	/*************************************************
	* Name:        challenge
	*
	* Description: Implementation of H. Samples polynomial with TAU nonzero
	*              coefficients in {-1,1} using the output stream of
	*              SHAKE256(seed).
	*
	* Arguments:   - poly *c: pointer to output polynomial
	*              - const uint8_t mu[]: byte array containing seed of length CTILDEBYTES
	**************************************************/
	private void poly_challenge(poly c, byte[] seed) {
		uint b, pos;
		byte[] buf;
		ulong signs;
		buf = new byte[SHAKE256_RATE];
		keccak_state state;

		state = new keccak_state();

		shake256_init(state);
		shake256_absorb(state, seed, CTildeBytes);
		shake256_finalize(state);
		shake256_squeezeblocks(buf, 0, 1, state);

		signs = 0;
		for (int i = 0; i < 8; i++) {
			signs |= (ulong)buf[i] << (8 * i);
		}
		pos = 8;

		for (int i = 0; i < N; i++) {
			c.coeffs[i] = 0;
		}
		for (int i = N - Tau; i < N; i++) {
			do {
				if (pos >= SHAKE256_RATE) {
					shake256_squeezeblocks(buf, 0, 1, state);
					pos = 0;
				}

				b = buf[pos++];
			} while (b > i);

			c.coeffs[i] = c.coeffs[b];
			c.coeffs[b] = (int)(1 - (2 * (signs & 1)));
			signs >>= 1;
		}
	}

	/*************************************************
	* Name:        polyeta_pack
	*
	* Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
	*
	* Arguments:   - uint8_t *r: pointer to output byte array with at least
	*                            POLYETA_PACKEDBYTES bytes
	*              - const poly *a: pointer to input polynomial
	**************************************************/
	private void polyeta_pack(byte[] r, int r_offset, poly a) {
		byte[] t;

		Debug.Assert(r.Length >= PolyEtaPackedBytes);

		t = new byte[8];

		if (Eta == 2) {
			for (int i = 0; i < N / 8; i++) {
				t[0] = (byte)(Eta - a.coeffs[(8 * i) + 0]);
				t[1] = (byte)(Eta - a.coeffs[(8 * i) + 1]);
				t[2] = (byte)(Eta - a.coeffs[(8 * i) + 2]);
				t[3] = (byte)(Eta - a.coeffs[(8 * i) + 3]);
				t[4] = (byte)(Eta - a.coeffs[(8 * i) + 4]);
				t[5] = (byte)(Eta - a.coeffs[(8 * i) + 5]);
				t[6] = (byte)(Eta - a.coeffs[(8 * i) + 6]);
				t[7] = (byte)(Eta - a.coeffs[(8 * i) + 7]);

				r[r_offset + (3 * i) + 0] = (byte)((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
				r[r_offset + (3 * i) + 1] = (byte)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
				r[r_offset + (3 * i) + 2] = (byte)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
			}
		} else if (Eta == 4) {
			for (int i = 0; i < N / 2; i++) {
				t[0] = (byte)(Eta - a.coeffs[(2 * i) + 0]);
				t[1] = (byte)(Eta - a.coeffs[(2 * i) + 1]);
				r[r_offset + i] = (byte)(t[0] | (t[1] << 4));
			}
		} else {
			throw new Exception("Invalid ETA");
		}
	}

	/*************************************************
	* Name:        polyeta_unpack
	*
	* Description: Unpack polynomial with coefficients in [-ETA,ETA].
	*
	* Arguments:   - poly *r: pointer to output polynomial
	*              - const uint8_t *a: byte array with bit-packed polynomial
	**************************************************/
	void polyeta_unpack(poly r, byte[] a, int a_offset) {
		if (Eta == 2) {
			for (int i = 0; i < N / 8; i++) {
				r.coeffs[(8 * i) + 0] = (a[a_offset + (3 * i) + 0] >> 0) & 7;
				r.coeffs[(8 * i) + 1] = (a[a_offset + (3 * i) + 0] >> 3) & 7;
				r.coeffs[(8 * i) + 2] = ((a[a_offset + (3 * i) + 0] >> 6) | (a[a_offset + (3 * i) + 1] << 2)) & 7;
				r.coeffs[(8 * i) + 3] = (a[a_offset + (3 * i) + 1] >> 1) & 7;
				r.coeffs[(8 * i) + 4] = (a[a_offset + (3 * i) + 1] >> 4) & 7;
				r.coeffs[(8 * i) + 5] = ((a[a_offset + (3 * i) + 1] >> 7) | (a[a_offset + (3 * i) + 2] << 1)) & 7;
				r.coeffs[(8 * i) + 6] = (a[a_offset + (3 * i) + 2] >> 2) & 7;
				r.coeffs[(8 * i) + 7] = (a[a_offset + (3 * i) + 2] >> 5) & 7;

				r.coeffs[(8 * i) + 0] = Eta - r.coeffs[(8 * i) + 0];
				r.coeffs[(8 * i) + 1] = Eta - r.coeffs[(8 * i) + 1];
				r.coeffs[(8 * i) + 2] = Eta - r.coeffs[(8 * i) + 2];
				r.coeffs[(8 * i) + 3] = Eta - r.coeffs[(8 * i) + 3];
				r.coeffs[(8 * i) + 4] = Eta - r.coeffs[(8 * i) + 4];
				r.coeffs[(8 * i) + 5] = Eta - r.coeffs[(8 * i) + 5];
				r.coeffs[(8 * i) + 6] = Eta - r.coeffs[(8 * i) + 6];
				r.coeffs[(8 * i) + 7] = Eta - r.coeffs[(8 * i) + 7];
			}
		} else if (Eta == 4) {
			for (int i = 0; i < N / 2; i++) {
				r.coeffs[(2 * i) + 0] = a[a_offset + i] & 0x0F;
				r.coeffs[(2 * i) + 1] = a[a_offset + i] >> 4;
				r.coeffs[(2 * i) + 0] = Eta - r.coeffs[(2 * i) + 0];
				r.coeffs[(2 * i) + 1] = Eta - r.coeffs[(2 * i) + 1];
			}
		} else {
			throw new Exception("Invalid ETA");
		}
	}

	/*************************************************
	* Name:        polyt1_pack
	*
	* Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
	*              Input coefficients are assumed to be standard representatives.
	*
	* Arguments:   - uint8_t *r: pointer to output byte array with at least
	*                            POLYT1_PACKEDBYTES bytes
	*              - const poly *a: pointer to input polynomial
	**************************************************/
	private void polyt1_pack(byte[] r, int r_offset, poly a) {
		for (int i = 0; i < N / 4; i++) {
			r[r_offset + (5 * i) + 0] = (byte)(a.coeffs[(4 * i) + 0] >> 0);
			r[r_offset + (5 * i) + 1] = (byte)((a.coeffs[(4 * i) + 0] >> 8) | (a.coeffs[(4 * i) + 1] << 2));
			r[r_offset + (5 * i) + 2] = (byte)((a.coeffs[(4 * i) + 1] >> 6) | (a.coeffs[(4 * i) + 2] << 4));
			r[r_offset + (5 * i) + 3] = (byte)((a.coeffs[(4 * i) + 2] >> 4) | (a.coeffs[(4 * i) + 3] << 6));
			r[r_offset + (5 * i) + 4] = (byte)(a.coeffs[(4 * i) + 3] >> 2);
		}
	}

	/*************************************************
	* Name:        polyt1_unpack
	*
	* Description: Unpack polynomial t1 with 10-bit coefficients.
	*              Output coefficients are standard representatives.
	*
	* Arguments:   - poly *r: pointer to output polynomial
	*              - const uint8_t *a: byte array with bit-packed polynomial
	**************************************************/
	private void polyt1_unpack(poly r, byte[] a, int a_offset) {
		for (int i = 0; i < N / 4; i++) {
			r.coeffs[(4 * i) + 0] = ((a[a_offset + (5 * i) + 0] >> 0) | (int)((uint)a[a_offset + (5 * i) + 1] << 8)) & 0x3FF;
			r.coeffs[(4 * i) + 1] = ((a[a_offset + (5 * i) + 1] >> 2) | (int)((uint)a[a_offset + (5 * i) + 2] << 6)) & 0x3FF;
			r.coeffs[(4 * i) + 2] = ((a[a_offset + (5 * i) + 2] >> 4) | (int)((uint)a[a_offset + (5 * i) + 3] << 4)) & 0x3FF;
			r.coeffs[(4 * i) + 3] = ((a[a_offset + (5 * i) + 3] >> 6) | (int)((uint)a[a_offset + (5 * i) + 4] << 2)) & 0x3FF;
		}


	}

	/*************************************************
	* Name:        polyt0_pack
	*
	* Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
	*
	* Arguments:   - uint8_t *r: pointer to output byte array with at least
	*                            POLYT0_PACKEDBYTES bytes
	*              - const poly *a: pointer to input polynomial
	**************************************************/
	private void polyt0_pack(byte[] r, int r_offset, poly a) {
		uint[] t;

		t = new uint[8];

		for (int i = 0; i < N / 8; i++) {
			t[0] = (uint)((1 << (D - 1)) - a.coeffs[(8 * i) + 0]);
			t[1] = (uint)((1 << (D - 1)) - a.coeffs[(8 * i) + 1]);
			t[2] = (uint)((1 << (D - 1)) - a.coeffs[(8 * i) + 2]);
			t[3] = (uint)((1 << (D - 1)) - a.coeffs[(8 * i) + 3]);
			t[4] = (uint)((1 << (D - 1)) - a.coeffs[(8 * i) + 4]);
			t[5] = (uint)((1 << (D - 1)) - a.coeffs[(8 * i) + 5]);
			t[6] = (uint)((1 << (D - 1)) - a.coeffs[(8 * i) + 6]);
			t[7] = (uint)((1 << (D - 1)) - a.coeffs[(8 * i) + 7]);

			r[r_offset + (13 * i) + 0] = (byte)t[0];
			r[r_offset + (13 * i) + 1] = (byte)(t[0] >> 8);
			r[r_offset + (13 * i) + 1] |= (byte)(t[1] << 5);
			r[r_offset + (13 * i) + 2] = (byte)(t[1] >> 3);
			r[r_offset + (13 * i) + 3] = (byte)(t[1] >> 11);
			r[r_offset + (13 * i) + 3] |= (byte)(t[2] << 2);
			r[r_offset + (13 * i) + 4] = (byte)(t[2] >> 6);
			r[r_offset + (13 * i) + 4] |= (byte)(t[3] << 7);
			r[r_offset + (13 * i) + 5] = (byte)(t[3] >> 1);
			r[r_offset + (13 * i) + 6] = (byte)(t[3] >> 9);
			r[r_offset + (13 * i) + 6] |= (byte)(t[4] << 4);
			r[r_offset + (13 * i) + 7] = (byte)(t[4] >> 4);
			r[r_offset + (13 * i) + 8] = (byte)(t[4] >> 12);
			r[r_offset + (13 * i) + 8] |= (byte)(t[5] << 1);
			r[r_offset + (13 * i) + 9] = (byte)(t[5] >> 7);
			r[r_offset + (13 * i) + 9] |= (byte)(t[6] << 6);
			r[r_offset + (13 * i) + 10] = (byte)(t[6] >> 2);
			r[r_offset + (13 * i) + 11] = (byte)(t[6] >> 10);
			r[r_offset + (13 * i) + 11] |= (byte)(t[7] << 3);
			r[r_offset + (13 * i) + 12] = (byte)(t[7] >> 5);
		}
	}

	/*************************************************
	* Name:        polyt0_unpack
	*
	* Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
	*
	* Arguments:   - poly *r: pointer to output polynomial
	*              - const uint8_t *a: byte array with bit-packed polynomial
	**************************************************/
	void polyt0_unpack(poly r, byte[] a, int a_offset) {
		for (int i = 0; i < N / 8; i++) {
			r.coeffs[(8 * i) + 0] = a[a_offset + (13 * i) + 0];
			r.coeffs[(8 * i) + 0] |= (int)((uint)a[a_offset + (13 * i) + 1] << 8);
			r.coeffs[(8 * i) + 0] &= 0x1FFF;

			r.coeffs[(8 * i) + 1] = a[a_offset + (13 * i) + 1] >> 5;
			r.coeffs[(8 * i) + 1] |= (int)((uint)a[a_offset + (13 * i) + 2] << 3);
			r.coeffs[(8 * i) + 1] |= (int)((uint)a[a_offset + (13 * i) + 3] << 11);
			r.coeffs[(8 * i) + 1] &= 0x1FFF;

			r.coeffs[(8 * i) + 2] = a[a_offset + (13 * i) + 3] >> 2;
			r.coeffs[(8 * i) + 2] |= (int)((uint)a[a_offset + (13 * i) + 4] << 6);
			r.coeffs[(8 * i) + 2] &= 0x1FFF;

			r.coeffs[(8 * i) + 3] = a[a_offset + (13 * i) + 4] >> 7;
			r.coeffs[(8 * i) + 3] |= (int)((uint)a[a_offset + (13 * i) + 5] << 1);
			r.coeffs[(8 * i) + 3] |= (int)((uint)a[a_offset + (13 * i) + 6] << 9);
			r.coeffs[(8 * i) + 3] &= 0x1FFF;

			r.coeffs[(8 * i) + 4] = a[a_offset + (13 * i) + 6] >> 4;
			r.coeffs[(8 * i) + 4] |= (int)((uint)a[a_offset + (13 * i) + 7] << 4);
			r.coeffs[(8 * i) + 4] |= (int)((uint)a[a_offset + (13 * i) + 8] << 12);
			r.coeffs[(8 * i) + 4] &= 0x1FFF;

			r.coeffs[(8 * i) + 5] = a[a_offset + (13 * i) + 8] >> 1;
			r.coeffs[(8 * i) + 5] |= (int)((uint)a[a_offset + (13 * i) + 9] << 7);
			r.coeffs[(8 * i) + 5] &= 0x1FFF;

			r.coeffs[(8 * i) + 6] = a[a_offset + (13 * i) + 9] >> 6;
			r.coeffs[(8 * i) + 6] |= (int)((uint)a[a_offset + (13 * i) + 10] << 2);
			r.coeffs[(8 * i) + 6] |= (int)((uint)a[a_offset + (13 * i) + 11] << 10);
			r.coeffs[(8 * i) + 6] &= 0x1FFF;

			r.coeffs[(8 * i) + 7] = a[a_offset + (13 * i) + 11] >> 3;
			r.coeffs[(8 * i) + 7] |= (int)((uint)a[a_offset + (13 * i) + 12] << 5);
			r.coeffs[(8 * i) + 7] &= 0x1FFF;

			r.coeffs[(8 * i) + 0] = (1 << (D - 1)) - r.coeffs[(8 * i) + 0];
			r.coeffs[(8 * i) + 1] = (1 << (D - 1)) - r.coeffs[(8 * i) + 1];
			r.coeffs[(8 * i) + 2] = (1 << (D - 1)) - r.coeffs[(8 * i) + 2];
			r.coeffs[(8 * i) + 3] = (1 << (D - 1)) - r.coeffs[(8 * i) + 3];
			r.coeffs[(8 * i) + 4] = (1 << (D - 1)) - r.coeffs[(8 * i) + 4];
			r.coeffs[(8 * i) + 5] = (1 << (D - 1)) - r.coeffs[(8 * i) + 5];
			r.coeffs[(8 * i) + 6] = (1 << (D - 1)) - r.coeffs[(8 * i) + 6];
			r.coeffs[(8 * i) + 7] = (1 << (D - 1)) - r.coeffs[(8 * i) + 7];
		}
	}

	/*************************************************
	* Name:        polyz_pack
	*
	* Description: Bit-pack polynomial with coefficients
	*              in [-(GAMMA1 - 1), GAMMA1].
	*
	* Arguments:   - uint8_t *r: pointer to output byte array with at least
	*                            POLYZ_PACKEDBYTES bytes
	*              - const poly *a: pointer to input polynomial
	**************************************************/
	private void polyz_pack(byte[] r, int r_offset, poly a) {
		uint[] t;

		t = new uint[4];

		if (Gamma1 == (1 << 17)) {
			for (int i = 0; i < N / 4; i++) {
				t[0] = (uint)(Gamma1 - a.coeffs[(4 * i) + 0]);
				t[1] = (uint)(Gamma1 - a.coeffs[(4 * i) + 1]);
				t[2] = (uint)(Gamma1 - a.coeffs[(4 * i) + 2]);
				t[3] = (uint)(Gamma1 - a.coeffs[(4 * i) + 3]);

				r[r_offset + (9 * i) + 0] = (byte)t[0];
				r[r_offset + (9 * i) + 1] = (byte)(t[0] >> 8);
				r[r_offset + (9 * i) + 2] = (byte)(t[0] >> 16);
				r[r_offset + (9 * i) + 2] |= (byte)(t[1] << 2);
				r[r_offset + (9 * i) + 3] = (byte)(t[1] >> 6);
				r[r_offset + (9 * i) + 4] = (byte)(t[1] >> 14);
				r[r_offset + (9 * i) + 4] |= (byte)(t[2] << 4);
				r[r_offset + (9 * i) + 5] = (byte)(t[2] >> 4);
				r[r_offset + (9 * i) + 6] = (byte)(t[2] >> 12);
				r[r_offset + (9 * i) + 6] |= (byte)(t[3] << 6);
				r[r_offset + (9 * i) + 7] = (byte)(t[3] >> 2);
				r[r_offset + (9 * i) + 8] = (byte)(t[3] >> 10);
			}
		} else if (Gamma1 == (1 << 19)) {
			for (int i = 0; i < N / 2; i++) {
				t[0] = (uint)(Gamma1 - a.coeffs[(2 * i) + 0]);
				t[1] = (uint)(Gamma1 - a.coeffs[(2 * i) + 1]);

				r[r_offset + (5 * i) + 0] = (byte)t[0];
				r[r_offset + (5 * i) + 1] = (byte)(t[0] >> 8);
				r[r_offset + (5 * i) + 2] = (byte)(t[0] >> 16);
				r[r_offset + (5 * i) + 2] |= (byte)(t[1] << 4);
				r[r_offset + (5 * i) + 3] = (byte)(t[1] >> 4);
				r[r_offset + (5 * i) + 4] = (byte)(t[1] >> 12);
			}
		} else {
			throw new Exception("Invalid Gamma1");
		}
	}

	/*************************************************
	* Name:        polyz_unpack
	*
	* Description: Unpack polynomial z with coefficients
	*              in [-(GAMMA1 - 1), GAMMA1].
	*
	* Arguments:   - poly *r: pointer to output polynomial
	*              - const uint8_t *a: byte array with bit-packed polynomial
	**************************************************/
	private void polyz_unpack(poly r, byte[] a, int a_offset) {
		if (Gamma1 == (1 << 17)) {
			for (int i = 0; i < N / 4; i++) {
				r.coeffs[(4 * i) + 0] = a[a_offset + (9 * i) + 0];
				r.coeffs[(4 * i) + 0] |= (int)((uint)a[a_offset + (9 * i) + 1] << 8);
				r.coeffs[(4 * i) + 0] |= (int)((uint)a[a_offset + (9 * i) + 2] << 16);
				r.coeffs[(4 * i) + 0] &= 0x3FFFF;

				r.coeffs[(4 * i) + 1] = a[a_offset + (9 * i) + 2] >> 2;
				r.coeffs[(4 * i) + 1] |= (int)((uint)a[a_offset + (9 * i) + 3] << 6);
				r.coeffs[(4 * i) + 1] |= (int)((uint)a[a_offset + (9 * i) + 4] << 14);
				r.coeffs[(4 * i) + 1] &= 0x3FFFF;

				r.coeffs[(4 * i) + 2] = a[a_offset + (9 * i) + 4] >> 4;
				r.coeffs[(4 * i) + 2] |= (int)((uint)a[a_offset + (9 * i) + 5] << 4);
				r.coeffs[(4 * i) + 2] |= (int)((uint)a[a_offset + (9 * i) + 6] << 12);
				r.coeffs[(4 * i) + 2] &= 0x3FFFF;

				r.coeffs[(4 * i) + 3] = a[a_offset + (9 * i) + 6] >> 6;
				r.coeffs[(4 * i) + 3] |= (int)((uint)a[a_offset + (9 * i) + 7] << 2);
				r.coeffs[(4 * i) + 3] |= (int)((uint)a[a_offset + (9 * i) + 8] << 10);
				r.coeffs[(4 * i) + 3] &= 0x3FFFF;

				r.coeffs[(4 * i) + 0] = Gamma1 - r.coeffs[(4 * i) + 0];
				r.coeffs[(4 * i) + 1] = Gamma1 - r.coeffs[(4 * i) + 1];
				r.coeffs[(4 * i) + 2] = Gamma1 - r.coeffs[(4 * i) + 2];
				r.coeffs[(4 * i) + 3] = Gamma1 - r.coeffs[(4 * i) + 3];
			}
		} else if (Gamma1 == (1 << 19)) {
			for (int i = 0; i < N / 2; i++) {
				r.coeffs[(2 * i) + 0] = a[a_offset + (5 * i) + 0];
				r.coeffs[(2 * i) + 0] |= (int)((uint)a[a_offset + (5 * i) + 1] << 8);
				r.coeffs[(2 * i) + 0] |= (int)((uint)a[a_offset + (5 * i) + 2] << 16);
				r.coeffs[(2 * i) + 0] &= 0xFFFFF;

				r.coeffs[(2 * i) + 1] = a[a_offset + (5 * i) + 2] >> 4;
				r.coeffs[(2 * i) + 1] |= (int)((uint)a[a_offset + (5 * i) + 3] << 4);
				r.coeffs[(2 * i) + 1] |= (int)((uint)a[a_offset + (5 * i) + 4] << 12);
				/* r.coeffs[2*i+1] &= 0xFFFFF; */ /* No effect, since we're anyway at 20 bits */

				r.coeffs[(2 * i) + 0] = Gamma1 - r.coeffs[(2 * i) + 0];
				r.coeffs[(2 * i) + 1] = Gamma1 - r.coeffs[(2 * i) + 1];
			}
		} else {
			throw new Exception("Invalid Gamma1");
		}


	}

	/*************************************************
	* Name:        polyw1_pack
	*
	* Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
	*              Input coefficients are assumed to be standard representatives.
	*
	* Arguments:   - uint8_t *r: pointer to output byte array with at least
	*                            POLYW1_PACKEDBYTES bytes
	*              - const poly *a: pointer to input polynomial
	**************************************************/
	private void polyw1_pack(byte[] r, int r_offset, poly a) {

		if (Gamma2 == (Q - 1) / 88) {
			for (int i = 0; i < N / 4; i++) {
				r[r_offset + (3 * i) + 0] = (byte)a.coeffs[(4 * i) + 0];
				r[r_offset + (3 * i) + 0] |= (byte)(a.coeffs[(4 * i) + 1] << 6);
				r[r_offset + (3 * i) + 1] = (byte)(a.coeffs[(4 * i) + 1] >> 2);
				r[r_offset + (3 * i) + 1] |= (byte)(a.coeffs[(4 * i) + 2] << 4);
				r[r_offset + (3 * i) + 2] = (byte)(a.coeffs[(4 * i) + 2] >> 4);
				r[r_offset + (3 * i) + 2] |= (byte)(a.coeffs[(4 * i) + 3] << 2);
			}
		} else if (Gamma2 == (Q - 1) / 32) {
			for (int i = 0; i < N / 2; i++)
				r[r_offset + i] = (byte)(a.coeffs[(2 * i) + 0] | (a.coeffs[(2 * i) + 1] << 4));
		} else {
			throw new Exception("Invalid Gamma2");
		}
	}
}