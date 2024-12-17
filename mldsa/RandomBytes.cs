using System.Security.Cryptography;

namespace mldsa_net;
public abstract partial class DilithiumBase {
	private void randombytes(out byte[] out_buffer, int outlen) {
		out_buffer = RandomNumberGenerator.GetBytes(outlen);
	}
}
