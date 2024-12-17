namespace mldsa_net;
public class Dilithium3 : DilithiumBase {
	private bool randomized_signature;

	public Dilithium3() {
	}

	public override bool RandomizedSignature {
		get {
			return randomized_signature;
		}
	}

	public override int K {
		get {
			return 6;
		}
	}

	public override int L {
		get {
			return 5;
		}
	}

	public override int Eta {
		get {
			return 4;
		}
	}

	public override int Tau {
		get {
			return 49;
		}
	}

	public override int Beta {
		get {
			return 196;
		}
	}

	public override int Gamma1 {
		get {
			return 1 << 19;
		}
	}

	public override int Gamma2 {
		get {
			return (Q - 1) / 32;
		}
	}

	public override int Omega {
		get {
			return 55;
		}
	}

	public override int CTildeBytes {
		get {
			return 48;
		}
	}
}
