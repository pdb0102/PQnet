using System.Runtime.Serialization;

namespace mldsa_net.test.AVCP;
/// <summary>
/// ML-DSA sigGen Test Case JSON Schema
/// </summary>
[DataContract]
public class AcvpMlDsaKeyGenTestCase {
	/// <summary>
	/// Numeric identifier for the test case, unique across the entire vector set
	/// </summary>
	[DataMember(Name = "tcId")]
	public int TcId { get; set; }

	/// <summary>
	/// The seed used to generate the key pair
	/// </summary>
	[DataMember(Name = "seed")]
	public string Seed { get; set; }

	/// <summary>
	/// <see cref="Seed"/> as a byte array
	/// </summary>
	[IgnoreDataMember]
	public byte[] SeedBytes {
		get {
			if (Seed == null) {
				return null;
			}
			return Utilities.HexToBytes(Seed, out _);
		}
	}

	/// <summary>
	/// The public key
	/// </summary>
	[DataMember(Name = "pk")]
	public string PublicKey { get; set; }

	/// <summary>
	/// <see cref="PublicKey"/> as a byte array
	/// </summary>
	[IgnoreDataMember]
	public byte[] PublicKeyBytes {
		get {
			if (PublicKey == null) {
				return null;
			}
			return Utilities.HexToBytes(PublicKey, out _);
		}
	}

	/// <summary>								   
	/// The public key
	/// </summary>
	[DataMember(Name = "sk")]
	public string SecretKey { get; set; }

	/// <summary>
	/// <see cref="SecretKey"/> as a byte array
	/// </summary>
	[IgnoreDataMember]
	public byte[] SecretKeyBytes {
		get {
			if (PublicKey == null) {
				return null;
			}
			return Utilities.HexToBytes(SecretKey, out _);
		}
	}

}
