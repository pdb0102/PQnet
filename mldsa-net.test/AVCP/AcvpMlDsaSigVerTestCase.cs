using System.Runtime.Serialization;

namespace mldsa_net.test.AVCP;
/// <summary>
/// ML-DSA sigVer Test Groups JSON Schema
/// </summary>
[DataContract]
public class AcvpMlDsaSigVerTestCase {
	/// <summary>
	/// Numeric identifier for the test case, unique across the entire vector set
	/// </summary>
	[DataMember(Name = "tcId")]
	public int TcId { get; set; }

	/// <summary>
	/// The message used to verify with the signature
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
	/// The signature to verify
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

	/// <summary>
	/// Gets whether the test is expected to pass
	/// </summary>
	[DataMember(Name = "testPassed")]
	public bool TestPassed { get; set; }
}
