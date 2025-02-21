using System.Text;

using PQnet.Digest;

namespace TestApp {
	class Program {
		static void Main(string[] args) {
			byte[] arm;
			byte[] refb;
			byte[] sys;

			refb = new byte[32];
			arm = Sha256Arm64.ComputeHash(Encoding.UTF8.GetBytes("test"));
			Sha256.sha256(refb, Encoding.UTF8.GetBytes("test"), 4);
			sys = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("test"));

		}
	}
}