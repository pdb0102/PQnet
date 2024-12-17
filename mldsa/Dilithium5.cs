namespace mldsa_net;
public class Dilithium5 : DilithiumBase {
	private bool randomized_signature;

	public Dilithium5() {
	}

	public override bool RandomizedSignature {
		get {
			return randomized_signature;
		}
	}

	public override int K {
		get {
			return 8;
		}
	}

	public override int L {
		get {
			return 7;
		}
	}

	public override int Eta {
		get {
			return 2;
		}
	}

	public override int Tau {
		get {
			return 60;
		}
	}

	public override int Beta {
		get {
			return 120;
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
			return 75;
		}
	}

	public override int CTildeBytes {
		get {
			return 64;
		}
	}
}
