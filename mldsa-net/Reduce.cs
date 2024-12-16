namespace mldsa_net;
public abstract partial class DilithiumBase {
	private const int MONT = -4186625; // 2^32 % Q
	private const int QINV = 58728449; // q^(-1) mod 2^32


	/// <summary>
	/// Montgomery reduction; given a 64-bit integer a, computes 32-bit integer congruent to a * R^-1 mod Q,
	/// </summary>
	/// <param name="a">finite field element a</param>
	/// <returns>r</returns>
	/// <remarks>
	/// For finite field element a with -2^{31}Q <= a <= Q*2^31, compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
	/// </remarks>
	public int montgomery_reduce(long a) {
		int t;

		t = (int)a * QINV;
		t = (int)((a - ((long)t * Q)) >> 32);
		return t;
	}

	/// <summary>
	/// Reduce a coefficient a mod Q.
	/// </summary>
	/// <param name="a">finite field element a</param>
	/// <returns>r</returns>
	/// <remarks>
	/// For finite field element a with a <= 2^{31} - 2^{22} - 1, compute r \equiv a (mod Q) such that -6283008 <= r <= 6283008.
	/// </remarks>
	public int reduce32(int a) {
		int t;

		t = (a + (1 << 22)) >> 23;
		t = a - (t * Q);
		return t;
	}

	/// <summary>
	/// Add Q if input coefficient is negative.
	/// </summary>
	/// <param name="a">finite field element a</param>
	/// <returns>r</returns>
	public int caddq(int a) {
		a += (a >> 31) & Q;
		return a;
	}

	/// <summary>
	/// 
	/// </summary>
	/// <param name="a">finite field element a</param>
	/// <returns>r</returns>
	/// <remarks>
	/// For finite field element a, compute standard representative r = a mod^+ Q.
	/// </remarks>
	public int freeze(int a) {
		a = reduce32(a);
		a = caddq(a);
		return a;
	}

}
