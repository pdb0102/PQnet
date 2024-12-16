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
	/// The seed used to generate the key pair
	/// </summary>
	[DataMember(Name = "sk")]
	public string SecretKey { get; set; }

	/// <summary>
	/// When the test group properties "testType": "AFT" and "deterministic": false, the random value used to generate the signature
	/// </summary>
	[DataMember(Name = "rnd")]
	public string Random { get; set; }
}
