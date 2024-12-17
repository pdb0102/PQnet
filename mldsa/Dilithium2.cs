namespace mldsa_net;
public class Dilithium2 : DilithiumBase {
	private bool randomized_signature;

	public Dilithium2() {
	}

	public override bool RandomizedSignature {
		get {
			return randomized_signature;
		}
	}

	public override int K {
		get {
			return 4;
		}
	}

	public override int L {
		get {
			return 4;
		}
	}

	public override int Eta {
		get {
			return 2;
		}
	}

	public override int Tau {
		get {
			return 39;
		}
	}

	public override int Beta {
		get {
			return 78;
		}
	}

	public override int Gamma1 {
		get {
			return 1 << 17;
		}
	}

	public override int Gamma2 {
		get {
			return (Q - 1) / 88;
		}
	}

	public override int Omega {
		get {
			return 80;
		}
	}

	public override int CTildeBytes {
		get {
			return 32;
		}
	}
}
