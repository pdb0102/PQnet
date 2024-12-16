using System.Runtime.Serialization;

namespace mldsa_net.test.AVCP;
/// <summary>
/// ML-DSA sigGen Test Case JSON Schema
/// </summary>
[DataContract]
public class AcvpMlDsaTestGroup<T> {
	/// <summary>
	/// Numeric identifier for the test group, unique across the entire vector set
	/// </summary>
	[DataMember(Name = "tgId")]
	public int TgId { get; set; }

	/// <summary>
	/// The test operation performed
	/// </summary>
	[DataMember(Name = "testType")]
	public string TestType { get; set; }

	/// <summary>
	/// The ML-DSA parameter set used
	/// </summary>
	[DataMember(Name = "parameterSet")]
	public string ParameterSet { get; set; }

	/// <summary>
	/// List of individual test vector JSON objects 
	/// </summary>
	[DataMember(Name = "tests")]
	public List<T> Tests { get; set; }
}
