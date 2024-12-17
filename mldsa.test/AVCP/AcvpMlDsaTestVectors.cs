using System.Runtime.Serialization;

namespace mldsa_net.test.AVCP;
/// <summary>
/// ML-DSA keyGen/sigGen/sigVer Test Case JSON Schema
/// </summary>
[DataContract]
public class AcvpMlDsaTestVectors<T> {
	/// <summary>
	/// Unique numeric vector set identifier
	/// </summary>
	[DataMember(Name = "vsId")]
	public int VsId { get; set; }

	/// <summary>
	/// Algorithm defined in the capability exchange
	/// </summary>
	[DataMember(Name = "algorithm")]
	public string Algorithm { get; set; }

	/// <summary>
	/// Mode defined in the capability exchange
	/// </summary>
	[DataMember(Name = "mode")]
	public string Mode { get; set; }

	/// <summary>
	/// Protocol test revision selected
	/// </summary>
	[DataMember(Name = "revision")]
	public string Revision { get; set; }

	/// <summary>
	/// List of test groups
	/// </summary>
	[DataMember(Name = "testGroups")]
	public List<AcvpMlDsaTestGroup<T>> TestGroups { get; set; }
}
