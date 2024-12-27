namespace slhdsa;
internal class Sha2Cat1Hash : IHashAlgorithm {
	private int m;
	private int n;

	public Sha2Cat1Hash(int m, int n) {
		this.m = m;
		this.n = n;
	}

	public string Name {
		get {
			return "SHA2";
		}
	}

	public bool is_shake {
		get {
			return false;
		}
	}

	public byte[] f(byte[] pk_seed, IAddress adrs, byte[] m_1) {
		byte[] data;

		data = new byte[pk_seed.Length + adrs.Bytes.Length + m_1.Length];
		Array.Copy(pk_seed, data, pk_seed.Length);
		Array.Copy(adrs.Bytes, 0, data, pk_seed.Length, adrs.Bytes.Length);
		Array.Copy(m_1, 0, data, pk_seed.Length + adrs.Bytes.Length, m_1.Length);

		return Shake256.HashData(data, n);
	}

	public byte[] h(byte[] pb_seed, IAddress adrs, byte[] m_2) {
		throw new NotImplementedException();
	}

	public byte[] h_msg(byte[] r, byte[] pk_seed, byte[] pk_root, byte[] m) {
		byte[] data;

		data = new byte[r.Length + pk_seed.Length + pk_root.Length + m.Length];
		Array.Copy(r, data, r.Length);
		Array.Copy(pk_seed, 0, data, r.Length, pk_seed.Length);
		Array.Copy(pk_root, 0, data, r.Length + pk_seed.Length, pk_root.Length);
		Array.Copy(m, 0, data, r.Length + pk_seed.Length + pk_root.Length, m.Length);

		return Shake256.HashData(data, this.m);
	}

	public byte[] prf(byte[] pk_seed, byte[] sk_seed, IAddress adrs) {
		byte[] data;

	}

	public byte[] prf_msg(byte[] sk_prf, byte[] opt_rand, byte[] m) {
		throw new NotImplementedException();
	}

	public byte[] t_len(byte[] pk_seed, IAddress adrs, byte[] m_l) {
		throw new NotImplementedException();
	}

	private
}
