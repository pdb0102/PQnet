namespace mldsa_net;
public abstract partial class DilithiumBase {
	/// <summary>
	/// Gets whether the signature should be randomized or predictable (same input causes same signature)
	/// </summary>
	public abstract bool RandomizedSignature { get; }

	/// <summary>
	/// 
	/// </summary>
	public virtual int SeedBytes {
		get {
			return 32;
		}
	}

	/// <summary>
	/// 
	/// </summary>
	public virtual int CrhBytes {
		get {
			return 64;
		}
	}


	/// <summary>
	/// 
	/// </summary>
	public virtual int TrBytes {
		get {
			return 64;
		}
	}

	/// <summary>
	/// 
	/// </summary>
	public virtual int RndBytes {
		get {
			return 32;
		}
	}

	/// <summary>
	/// 
	/// </summary>
	public virtual int N {
		get {
			return 256;
		}
	}

	/// <summary>
	/// 
	/// </summary>
	public virtual int Q {
		get {
			return 8380417;
		}
	}

	/// <summary>
	/// 
	/// </summary>
	public virtual int D {
		get {
			return 13;
		}
	}

	/// <summary>
	/// 
	/// </summary>
	public virtual int RootOfUnity {
		get {
			return 1753;
		}
	}

	public abstract int K { get; }
	public abstract int L { get; }
	public abstract int Eta { get; }
	public abstract int Tau { get; }
	public abstract int Beta { get; }
	public abstract int Gamma1 { get; }
	public abstract int Gamma2 { get; }
	public abstract int Omega { get; }
	public abstract int CTildeBytes { get; }


	public virtual int PolyT1PackedBytes {
		get {
			return 320;
		}
	}

	public virtual int PolyT0PackedBytes {
		get {
			return 416;
		}
	}

	public virtual int PolyVecHPacketBytes {
		get {
			return Omega + K;
		}
	}

	public virtual int PolyZPackedBytes {
		get {
			if (Gamma1 == (1 << 17)) {
				return 576;
			}
			if (Gamma1 == (1 << 19)) {
				return 640;
			}
			throw new NotImplementedException();
		}
	}

	public virtual int PolyW1PackedBytes {
		get {
			if (Gamma2 == (Q - 1) / 88) {
				return 192;
			}
			if (Gamma2 == (Q - 1) / 32) {
				return 128;
			}
			throw new NotImplementedException();
		}
	}

	public virtual int PolyEtaPackedBytes {
		get {
			if (Eta == 2) {
				return 96;
			}
			if (Eta == 4) {
				return 128;
			}
			throw new NotImplementedException();
		}
	}

	/// <summary>
	/// The size of the public key, in bytes.
	/// </summary>
	public virtual int PublicKeybytes {
		get {
			return SeedBytes + (K * PolyT1PackedBytes);
		}
	}

	/// <summary>
	/// The size of the private (secret) key, in bytes.
	/// </summary>
	public virtual int SecretKeyBytes {
		get {
			return (2 * SeedBytes)
				+ TrBytes
				+ (L * PolyEtaPackedBytes)
				+ (K * PolyEtaPackedBytes)
				+ (K * PolyT0PackedBytes);
		}
	}

	/// <summary>
	/// The size of the signature, in bytes.
	/// </summary>
	public virtual int SignatureBytes {
		get {
			return CTildeBytes + (L * PolyZPackedBytes) + PolyVecHPacketBytes;
		}
	}
}
