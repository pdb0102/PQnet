using System.Diagnostics;

namespace mldsa_net;
public abstract partial class DilithiumBase {
	private const int STREAM128_BLOCKBYTES = SHAKE128_RATE;
	private const int STREAM256_BLOCKBYTES = SHAKE256_RATE;

	private void dilithium_shake128_stream_init(keccak_state state, byte[] seed, ushort nonce) {
		byte[] t;

		t = new byte[2];
		t[0] = (byte)(nonce & 0xff);
		t[1] = (byte)(nonce >> 8);

		Debug.Assert(seed.Length >= SeedBytes);

		shake128_init(state);
		shake128_absorb(state, seed, SeedBytes);
		shake128_absorb(state, t, 2);
		shake128_finalize(state);
	}


	void dilithium_shake256_stream_init(keccak_state state, byte[] seed, ushort nonce) {
		byte[] t;

		t = new byte[2];
		t[0] = (byte)(nonce & 0xff);
		t[1] = (byte)(nonce >> 8);

		shake256_init(state);
		shake256_absorb(state, seed, CrhBytes);
		shake256_absorb(state, t, 2);
		shake256_finalize(state);
	}
}
