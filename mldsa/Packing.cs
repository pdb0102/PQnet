namespace mldsa_net;
public abstract partial class DilithiumBase {

	/*************************************************
	* Name:        pack_pk
	*
	* Description: Bit-pack public key pk = (rho, t1).
	*
	* Arguments:   - uint8_t pk[]: output byte array
	*              - const uint8_t rho[]: byte array containing rho
	*              - const polyveck *t1: pointer to vector t1
	**************************************************/
	private void pack_pk(byte[] pk, byte[] rho, polyveck t1) {
		for (int i = 0; i < SeedBytes; i++) {
			pk[i] = rho[i];
		}

		for (int i = 0; i < K; i++) {
			polyt1_pack(pk, SeedBytes + (i * PolyT1PackedBytes), t1.vec[i]);
		}
	}

	/*************************************************
	* Name:        unpack_pk
	*
	* Description: Unpack public key pk = (rho, t1).
	*
	* Arguments:   - const uint8_t rho[]: output byte array for rho
	*              - const polyveck *t1: pointer to output vector t1
	*              - uint8_t pk[]: byte array containing bit-packed pk
	**************************************************/
	void unpack_pk(byte[] rho, polyveck t1, byte[] pk) {
		int i;

		for (i = 0; i < SeedBytes; i++) {
			rho[i] = pk[i];
		}

		for (i = 0; i < K; i++) {
			polyt1_unpack(t1.vec[i], pk, SeedBytes + (i * PolyT1PackedBytes));
		}
	}

	/*************************************************
	* Name:        pack_sk
	*
	* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
	*
	* Arguments:   - uint8_t sk[]: output byte array
	*              - const uint8_t rho[]: byte array containing rho
	*              - const uint8_t tr[]: byte array containing tr
	*              - const uint8_t key[]: byte array containing key
	*              - const polyveck *t0: pointer to vector t0
	*              - const polyvecl *s1: pointer to vector s1
	*              - const polyveck *s2: pointer to vector s2
	**************************************************/
	private void pack_sk(byte[] sk, byte[] rho, byte[] tr, byte[] key, polyveck t0, polyvecl s1, polyveck s2) {
		int sk_offset;
		int i;

		sk_offset = 0;

		for (i = 0; i < SeedBytes; i++) {
			sk[sk_offset + i] = rho[i];
		}
		sk_offset += SeedBytes;

		for (i = 0; i < SeedBytes; i++) {
			sk[sk_offset + i] = key[i];
		}
		sk_offset += SeedBytes;

		for (i = 0; i < TrBytes; i++) {
			sk[sk_offset + i] = tr[i];
		}
		sk_offset += TrBytes;

		for (i = 0; i < L; i++) {
			polyeta_pack(sk, sk_offset + (i * PolyEtaPackedBytes), s1.vec[i]);
		}
		sk_offset += L * PolyEtaPackedBytes;

		for (i = 0; i < K; i++) {
			polyeta_pack(sk, sk_offset + (i * PolyEtaPackedBytes), s2.vec[i]);
		}
		sk_offset += K * PolyEtaPackedBytes;

		for (i = 0; i < K; i++) {
			polyt0_pack(sk, sk_offset + (i * PolyT0PackedBytes), t0.vec[i]);
		}
	}

	/*************************************************
	* Name:        unpack_sk
	*
	* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
	*
	* Arguments:   - const uint8_t rho[]: output byte array for rho
	*              - const uint8_t tr[]: output byte array for tr
	*              - const uint8_t key[]: output byte array for key
	*              - const polyveck *t0: pointer to output vector t0
	*              - const polyvecl *s1: pointer to output vector s1
	*              - const polyveck *s2: pointer to output vector s2
	*              - uint8_t sk[]: byte array containing bit-packed sk
	**************************************************/
	private void unpack_sk(byte[] rho, byte[] tr, byte[] key, polyveck t0, polyvecl s1, polyveck s2, byte[] sk) {
		int sk_offset;

		sk_offset = 0;

		for (int i = 0; i < SeedBytes; i++) {
			rho[i] = sk[sk_offset + i];
		}
		sk_offset += SeedBytes;

		for (int i = 0; i < SeedBytes; i++) {
			key[i] = sk[sk_offset + i];
		}
		sk_offset += SeedBytes;

		for (int i = 0; i < TrBytes; i++) {
			tr[i] = sk[sk_offset + i];
		}
		sk_offset += TrBytes;

		for (int i = 0; i < L; i++) {
			polyeta_unpack(s1.vec[i], sk, sk_offset + (i * PolyEtaPackedBytes));
		}
		sk_offset += L * PolyEtaPackedBytes;

		for (int i = 0; i < K; i++) {
			polyeta_unpack(s2.vec[i], sk, sk_offset + (i * PolyEtaPackedBytes));
		}
		sk_offset += K * PolyEtaPackedBytes;

		for (int i = 0; i < K; i++) {
			polyt0_unpack(t0.vec[i], sk, sk_offset + (i * PolyT0PackedBytes));
		}
	}

	/*************************************************
	* Name:        pack_sig
	*
	* Description: Bit-pack signature sig = (c, z, h).
	*
	* Arguments:   - uint8_t sig[]: output byte array
	*              - const uint8_t *c: pointer to challenge hash length SeedBytes
	*              - const polyvecl *z: pointer to vector z
	*              - const polyveck *h: pointer to hint vector h
	**************************************************/
	private void pack_sig(byte[] sig, byte[] c, polyvecl z, polyveck h) {
		int sig_offset;
		int k;

		sig_offset = 0;

		for (int i = 0; i < CTildeBytes; i++) {
			sig[sig_offset + i] = c[i];
		}
		sig_offset += CTildeBytes;

		for (int i = 0; i < L; i++) {
			polyz_pack(sig, sig_offset + (i * PolyZPackedBytes), z.vec[i]);
		}
		sig_offset += L * PolyZPackedBytes;

		/* Encode h */
		for (int i = 0; i < Omega + K; i++) {
			sig[sig_offset + i] = 0;
		}

		k = 0;
		for (int i = 0; i < K; i++) {
			for (int j = 0; j < N; j++) {
				if (h.vec[i].coeffs[j] != 0) {
					sig[sig_offset + k++] = (byte)j;
				}
			}

			sig[sig_offset + Omega + i] = (byte)k;
		}
	}

	/*************************************************
	* Name:        unpack_sig
	*
	* Description: Unpack signature sig = (c, z, h).
	*
	* Arguments:   - uint8_t *c: pointer to output challenge hash
	*              - polyvecl *z: pointer to output vector z
	*              - polyveck *h: pointer to output hint vector h
	*              - const uint8_t sig[]: byte array containing
	*                bit-packed signature
	*
	* Returns 1 in case of malformed signature; otherwise 0.
	**************************************************/
	private int unpack_sig(byte[] c, polyvecl z, polyveck h, byte[] sig) {
		int sig_offset;
		int k;

		sig_offset = 0;

		for (int i = 0; i < CTildeBytes; i++) {
			c[i] = sig[sig_offset + i];
		}
		sig_offset += CTildeBytes;

		for (int i = 0; i < L; i++) {
			polyz_unpack(z.vec[i], sig, sig_offset + (i * PolyZPackedBytes));
		}
		sig_offset += L * PolyZPackedBytes;

		/* Decode h */
		k = 0;
		for (int i = 0; i < K; i++) {
			for (int j = 0; j < N; ++j) {
				h.vec[i].coeffs[j] = 0;
			}

			if (sig[sig_offset + Omega + i] < k || sig[sig_offset + Omega + i] > Omega) {
				return 1;
			}

			for (int j = k; j < sig[sig_offset + Omega + i]; ++j) {
				/* Coefficients are ordered for strong unforgeability */
				if (j > k && sig[sig_offset + j] <= sig[sig_offset + j - 1]) {
					return 1;
				}
				h.vec[i].coeffs[sig[sig_offset + j]] = 1;
			}

			k = sig[sig_offset + Omega + i];
		}

		/* Extra indices are zero for strong unforgeability */
		for (int j = k; j < Omega; ++j) {
			if (sig[sig_offset + j] != 0) {
				return 1;
			}
		}

		return 0;
	}
}
