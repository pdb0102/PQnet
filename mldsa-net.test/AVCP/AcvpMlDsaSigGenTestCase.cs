using System.Runtime.Serialization;

namespace mldsa_net.test.AVCP;
/// <summary>
/// ML-DSA sigGen Test Groups JSON Schema
/// </summary>
[DataContract]
public class AcvpMlDsaSigGenTestCase {
	/// <summary>
	/// Numeric identifier for the test case, unique across the entire vector set
	/// </summary>
	[DataMember(Name = "tcId")]
	public int TcId { get; set; }

	/// <summary>
	/// The message used to generate the signature
	/// </summary>
	[DataMember(Name = "message")]
	public string Message { get; set; }

	/// <summary>
	/// <see cref="Message"/> as a byte array
	/// </summary>
	[IgnoreDataMember]
	public byte[] MessageBytes {
		get {
			if (Message == null) {
				return null;
			}
			return Utilities.HexToBytes(Message, out _);
		}
	}

	/// <summary>
	/// The seed used to generate the key pair
	/// </summary>
	[DataMember(Name = "sk")]
	public string SecretKey { get; set; }

	/// <summary>
	/// <see cref="SecretKey"/> as a byte array
	/// </summary>
	[IgnoreDataMember]
	public byte[] SecretKeyBytes {
		get {
			if (SecretKey == null) {
				return null;
			}
			return Utilities.HexToBytes(SecretKey, out _);
		}
	}

	/// <summary>
	/// When the test group properties "testType": "AFT" and "deterministic": false, the random value used to generate the signature
	/// </summary>
	[DataMember(Name = "rnd")]
	public string Random { get; set; }

	/// <summary>
	/// <see cref="Random"/> as a byte array
	/// </summary>
	[IgnoreDataMember]
	public byte[] RandomBytes {
		get {
			if (Random == null) {
				return null;
			}
			return Utilities.HexToBytes(Random, out _);
		}
	}

	/// <summary>
	/// The expected signature
	/// </summary>
	[DataMember(Name = "signature")]
	public string Signature { get; set; }

	/// <summary>
	/// <see cref="Random"/> as a byte array
	/// </summary>
	[IgnoreDataMember]
	public byte[] SignatureBytes {
		get {
			if (Signature == null) {
				return null;
			}
			return Utilities.HexToBytes(Signature, out _);
		}
	}

}
