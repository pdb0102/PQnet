using System.Text;
using System.Text.RegularExpressions;

namespace TestApp;
internal class GenerateKeccak {
	// Replacement strings:
	// 1) ROL64in256\((?<d>[^,]*),(?<a>[^,]*),(?<o>[^\)]*)\) => ${d} = Avx2.Or(Avx2.ShiftLeftLogical(${a}, ${o}), Avx2.ShiftRightLogical(${a}, 64 - ${o})) 
	// 2) XOR256\((?<a>[^,]*),(?<b>[^\)]*)\) => Avx2.Xor(${a}, ${b})
	// 3) XOReq256\((?<a>[^,]*),(?<b>[^\)]*) => ${a} = Avx2.Xor(${a}, ${b})
	// 4) ANDnu256\((?<a>[^,]*),(?<b>[^\)]*)\) => Avx2.AndNot(${a}, ${b})
	// 5) ROL64in256_8\((?<d>[^,]*),(?<a>[^\)]*)\) => ${d} = Avx2.Shuffle(${a}, rho8)
	// 6) ROL64in256_56\((?<d>[^,]*),(?<a>[^\)]*)\) => ${d} = Avx2.Shuffle(${a}, rho56)
	// 7) CONST256_64\((?<a>[^\)]*)\) => ${a}

	private static List<Tuple<string, string>> match_list = new List<Tuple<string, string>> {
		new Tuple<string, string>(@"ROL64in256\((?<d>[^,]*),(?<a>[^,]*),(?<o>[^\)]*)\)", @"${d} = Avx2.Or(Avx2.ShiftLeftLogical(${a}, ${o}), Avx2.ShiftRightLogical(${a}, 64 - ${o}))"),
		new Tuple<string, string>(@"ANDnu256\((?<a>[^,]*),(?<b>[^\)]*)\)", @"Avx2.AndNot(${a}, ${b})"),
		new Tuple<string, string>(@"XOR256\((?<a>[^,]*),(?<b>[^\)]*)\)", @"Avx2.Xor(${a}, ${b})"),
		new Tuple<string, string>(@"XOReq256\((?<a>[^,]*),(?<b>[^\)]*)\)", @"${a} = Avx2.Xor(${a}, ${b})"),
		new Tuple<string, string>(@"ROL64in256_8\((?<d>[^,]*),(?<a>[^\)]*)\)", @"${d} = Avx2.Shuffle(${a}.AsByte(), rho8).AsUInt64()"),
		new Tuple<string, string>(@"ROL64in256_56\((?<d>[^,]*),(?<a>[^\)]*)\)", @"${d} = Avx2.Shuffle(${a}.AsByte(), rho56).AsUInt64()"),
		new Tuple<string, string>(@"CONST256_64\((?<a>[^\)]*)\)", @"${a}"),
	};

	public static string GenerateProcessFullLane() {
		StringBuilder sb;
		List<string> lines;
		string line;

		sb = new StringBuilder();
		lines = new List<string>(full_lane_process.Split("\n", StringSplitOptions.TrimEntries));
		for (int x = 0; x < lines.Count; x++) {
			line = Regex.Replace(lines[x], @"XOR_In\((?<a>[^,]*),(?<b>[^\)]*)\)", @"${a} = Avx2.Xor(${a}, Vector256.Create(ref interleaved_data[${b} * 32])");
			sb.AppendFormat(line);
		}

		return sb.ToString();
	}

	private static string full_lane_process =
		"XOR_In(Aba, 0);\n" +
		"XOR_In(Abe, 1);\n" +
		"XOR_In(Abi, 2);\n" +
		"XOR_In(Abo, 3);\n" +
		"XOR_In(Abu, 4);\n" +
		"XOR_In(Aga, 5);\n" +
		"XOR_In(Age, 6);\n" +
		"XOR_In(Agi, 7);\n" +
		"XOR_In(Ago, 8);\n" +
		"XOR_In(Agu, 9);\n" +
		"XOR_In(Aka, 10);\n" +
		"XOR_In(Ake, 11);\n" +
		"XOR_In(Aki, 12);\n" +
		"XOR_In(Ako, 13);\n" +
		"XOR_In(Aku, 14);\n" +
		"XOR_In(Ama, 15);\n" +
		"XOR_In(Ame, 16);\n" +
		"XOR_In(Ami, 17);\n" +
		"XOR_In(Amo, 18);\n" +
		"XOR_In(Amu, 19);\n" +
		"XOR_In(Asa, 20);\n";

	public static string GenerateRounds24() {
		StringBuilder sb;

		sb = new StringBuilder();
		sb.AppendLine("// GenerateRounds24 generated code start");

		// Generate 24 rounds
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 0, "A", "E");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 1, "E", "A");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 2, "A", "E");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 3, "E", "A");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 4, "A", "E");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 5, "E", "A");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 6, "A", "E");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 7, "E", "A");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 8, "A", "E");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 9, "E", "A");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 10, "A", "E");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 11, "E", "A");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 12, "A", "E");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 13, "E", "A");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 14, "A", "E");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 15, "E", "A");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 16, "A", "E");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 17, "E", "A");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 18, "A", "E");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 19, "E", "A");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 20, "A", "E");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 21, "E", "A");
		Prepare_thetaRhoPiChiIotaPrepareTheta(sb, 22, "A", "E");
		Prepare_thetaRhoPiChiIota(sb, 23, "E", "A");

		sb.AppendLine("// GenerateRounds24 generated code end");

		return sb.ToString();
	}

	private static void Prepare_thetaRhoPiChiIotaPrepareTheta(StringBuilder sb, int i, string A, string E) {
		List<string> lines;
		string line;

		lines = new List<string>(thetaRhoPiChiIotaPrepareTheta_i_A_E.Split("\n", StringSplitOptions.TrimEntries));
		for (int x = 0; x < lines.Count; x++) {
			line = lines[x];
			for (int j = 0; j < match_list.Count; j++) {
				line = Regex.Replace(line, match_list[j].Item1, match_list[j].Item2);
			}
			sb.AppendFormat(line, i, A, E);
			sb.AppendLine();
		}
		//sb.AppendFormat(thetaRhoPiChiIotaPrepareTheta_i_A_E, i, A, E);
	}

	private static void Prepare_thetaRhoPiChiIota(StringBuilder sb, int i, string A, string E) {
		List<string> lines;
		string line;

		lines = new List<string>(thetaRhoPiChiIota_i_A_E.Split("\n", StringSplitOptions.TrimEntries));
		for (int x = 0; x < lines.Count; x++) {
			line = lines[x];
			for (int j = 0; j < match_list.Count; j++) {
				line = Regex.Replace(line, match_list[j].Item1, match_list[j].Item2);
			}
			sb.AppendFormat(line, i, A, E);
			sb.AppendLine();
		}

		//sb.AppendFormat(thetaRhoPiChiIota_i_A_E, i, A, E);
	}

	private const string thetaRhoPiChiIotaPrepareTheta_i_A_E =
			"ROL64in256(Ce1, Ce, 1); \n" +
			"Da = XOR256(Cu, Ce1); \n" +
			"ROL64in256(Ci1, Ci, 1); \n" +
			"De = XOR256(Ca, Ci1); \n" +
			"ROL64in256(Co1, Co, 1); \n" +
			"Di = XOR256(Ce, Co1); \n" +
			"ROL64in256(Cu1, Cu, 1); \n" +
			"Do = XOR256(Ci, Cu1); \n" +
			"ROL64in256(Ca1, Ca, 1); \n" +
			"Du = XOR256(Co, Ca1); \n" +
			"\n" +
			"XOReq256({1}ba, Da); \n" +
			"Bba = {1}ba; \n" +
			"XOReq256({1}ge, De); \n" +
			"ROL64in256(Bbe, {1}ge, 44); \n" +
			"XOReq256({1}ki, Di); \n" +
			"ROL64in256(Bbi, {1}ki, 43); \n" +
			"{2}ba = XOR256(Bba, ANDnu256(Bbe, Bbi)); \n" +
			"XOReq256({2}ba, CONST256_64(KeccakF1600RoundConstants[{0}])); \n" +
			"Ca = {2}ba; \n" +
			"XOReq256({1}mo, Do); \n" +
			"ROL64in256(Bbo, {1}mo, 21); \n" +
			"{2}be = XOR256(Bbe, ANDnu256(Bbi, Bbo)); \n" +
			"Ce = {2}be; \n" +
			"XOReq256({1}su, Du); \n" +
			"ROL64in256(Bbu, {1}su, 14); \n" +
			"{2}bi = XOR256(Bbi, ANDnu256(Bbo, Bbu)); \n" +
			"Ci = {2}bi; \n" +
			"{2}bo = XOR256(Bbo, ANDnu256(Bbu, Bba)); \n" +
			"Co = {2}bo; \n" +
			"{2}bu = XOR256(Bbu, ANDnu256(Bba, Bbe)); \n" +
			"Cu = {2}bu; \n" +
			"\n" +
			"\n" +
			"XOReq256({1}bo, Do); \n" +
			"ROL64in256(Bga, {1}bo, 28); \n" +
			"XOReq256({1}gu, Du); \n" +
			"ROL64in256(Bge, {1}gu, 20); \n" +
			"XOReq256({1}ka, Da); \n" +
			"ROL64in256(Bgi, {1}ka, 3); \n" +
			"{2}ga = XOR256(Bga, ANDnu256(Bge, Bgi)); \n" +
			"XOReq256(Ca, {2}ga); \n" +
			"XOReq256({1}me, De); \n" +
			"ROL64in256(Bgo, {1}me, 45); \n" +
			"{2}ge = XOR256(Bge, ANDnu256(Bgi, Bgo)); \n" +
			"XOReq256(Ce, {2}ge); \n" +
			"XOReq256({1}si, Di); \n" +
			"ROL64in256(Bgu, {1}si, 61); \n" +
			"{2}gi = XOR256(Bgi, ANDnu256(Bgo, Bgu)); \n" +
			"XOReq256(Ci, {2}gi); \n" +
			"{2}go = XOR256(Bgo, ANDnu256(Bgu, Bga)); \n" +
			"XOReq256(Co, {2}go); \n" +
			"{2}gu = XOR256(Bgu, ANDnu256(Bga, Bge)); \n" +
			"XOReq256(Cu, {2}gu); \n" +
			"\n" +
			"\n" +
			"XOReq256({1}be, De); \n" +
			"ROL64in256(Bka, {1}be, 1); \n" +
			"XOReq256({1}gi, Di); \n" +
			"ROL64in256(Bke, {1}gi, 6); \n" +
			"XOReq256({1}ko, Do); \n" +
			"ROL64in256(Bki, {1}ko, 25); \n" +
			"{2}ka = XOR256(Bka, ANDnu256(Bke, Bki)); \n" +
			"XOReq256(Ca, {2}ka); \n" +
			"XOReq256({1}mu, Du); \n" +
			"ROL64in256_8(Bko, {1}mu); \n" +
			"{2}ke = XOR256(Bke, ANDnu256(Bki, Bko)); \n" +
			"XOReq256(Ce, {2}ke); \n" +
			"XOReq256({1}sa, Da); \n" +
			"ROL64in256(Bku, {1}sa, 18); \n" +
			"{2}ki = XOR256(Bki, ANDnu256(Bko, Bku)); \n" +
			"XOReq256(Ci, {2}ki); \n" +
			"{2}ko = XOR256(Bko, ANDnu256(Bku, Bka)); \n" +
			"XOReq256(Co, {2}ko); \n" +
			"{2}ku = XOR256(Bku, ANDnu256(Bka, Bke)); \n" +
			"XOReq256(Cu, {2}ku); \n" +
			"\n" +
			"\n" +
			"XOReq256({1}bu, Du); \n" +
			"ROL64in256(Bma, {1}bu, 27); \n" +
			"XOReq256({1}ga, Da); \n" +
			"ROL64in256(Bme, {1}ga, 36); \n" +
			"XOReq256({1}ke, De); \n" +
			"ROL64in256(Bmi, {1}ke, 10); \n" +
			"{2}ma = XOR256(Bma, ANDnu256(Bme, Bmi)); \n" +
			"XOReq256(Ca, {2}ma); \n" +
			"XOReq256({1}mi, Di); \n" +
			"ROL64in256(Bmo, {1}mi, 15); \n" +
			"{2}me = XOR256(Bme, ANDnu256(Bmi, Bmo)); \n" +
			"XOReq256(Ce, {2}me); \n" +
			"XOReq256({1}so, Do); \n" +
			"ROL64in256_56(Bmu, {1}so); \n" +
			"{2}mi = XOR256(Bmi, ANDnu256(Bmo, Bmu)); \n" +
			"XOReq256(Ci, {2}mi); \n" +
			"{2}mo = XOR256(Bmo, ANDnu256(Bmu, Bma)); \n" +
			"XOReq256(Co, {2}mo); \n" +
			"{2}mu = XOR256(Bmu, ANDnu256(Bma, Bme)); \n" +
			"XOReq256(Cu, {2}mu); \n" +
			"\n" +
			"\n" +
			"XOReq256({1}bi, Di); \n" +
			"ROL64in256(Bsa, {1}bi, 62); \n" +
			"XOReq256({1}go, Do); \n" +
			"ROL64in256(Bse, {1}go, 55); \n" +
			"XOReq256({1}ku, Du); \n" +
			"ROL64in256(Bsi, {1}ku, 39); \n" +
			"{2}sa = XOR256(Bsa, ANDnu256(Bse, Bsi)); \n" +
			"XOReq256(Ca, {2}sa); \n" +
			"XOReq256({1}ma, Da); \n" +
			"ROL64in256(Bso, {1}ma, 41); \n" +
			"{2}se = XOR256(Bse, ANDnu256(Bsi, Bso)); \n" +
			"XOReq256(Ce, {2}se); \n" +
			"XOReq256({1}se, De); \n" +
			"ROL64in256(Bsu, {1}se, 2); \n" +
			"{2}si = XOR256(Bsi, ANDnu256(Bso, Bsu)); \n" +
			"XOReq256(Ci, {2}si); \n" +
			"{2}so = XOR256(Bso, ANDnu256(Bsu, Bsa)); \n" +
			"XOReq256(Co, {2}so); \n" +
			"{2}su = XOR256(Bsu, ANDnu256(Bsa, Bse)); \n" +
			"XOReq256(Cu, {2}su); \n";

	private static string thetaRhoPiChiIota_i_A_E =
			"ROL64in256(Ce1, Ce, 1); \r\n" +
			"Da = XOR256(Cu, Ce1); \r\n" +
			"ROL64in256(Ci1, Ci, 1); \r\n" +
			"De = XOR256(Ca, Ci1); \r\n" +
			"ROL64in256(Co1, Co, 1); \r\n" +
			"Di = XOR256(Ce, Co1); \r\n" +
			"ROL64in256(Cu1, Cu, 1); \r\n" +
			"Do = XOR256(Ci, Cu1); \r\n" +
			"ROL64in256(Ca1, Ca, 1); \r\n" +
			"Du = XOR256(Co, Ca1); \r\n\r\n" +
			"XOReq256({1}ba, Da); \r\n" +
			"Bba = {1}ba; \r\n" +
			"XOReq256({1}ge, De); \r\n" +
			"ROL64in256(Bbe, {1}ge, 44); \r\n" +
			"XOReq256({1}ki, Di); \r\n" +
			"ROL64in256(Bbi, {1}ki, 43); \r\n" +
			"{2}ba = XOR256(Bba, ANDnu256(Bbe, Bbi)); \r\n" +
			"XOReq256({2}ba, CONST256_64(KeccakF1600RoundConstants[{0}])); \r\n" +
			"XOReq256({1}mo, Do); \r\n" +
			"ROL64in256(Bbo, {1}mo, 21); \r\n" +
			"{2}be = XOR256(Bbe, ANDnu256(Bbi, Bbo)); \r\n" +
			"XOReq256({1}su, Du); \r\n" +
			"ROL64in256(Bbu, {1}su, 14); \r\n" +
			"{2}bi = XOR256(Bbi, ANDnu256(Bbo, Bbu)); \r\n" +
			"{2}bo = XOR256(Bbo, ANDnu256(Bbu, Bba)); \r\n" +
			"{2}bu = XOR256(Bbu, ANDnu256(Bba, Bbe)); \r\n\r\n" +
			"XOReq256({1}bo, Do); \r\n" +
			"ROL64in256(Bga, {1}bo, 28); \r\n" +
			"XOReq256({1}gu, Du); \r\n" +
			"ROL64in256(Bge, {1}gu, 20); \r\n" +
			"XOReq256({1}ka, Da); \r\n" +
			"ROL64in256(Bgi, {1}ka, 3); \r\n" +
			"{2}ga = XOR256(Bga, ANDnu256(Bge, Bgi)); \r\n" +
			"XOReq256({1}me, De); \r\n" +
			"ROL64in256(Bgo, {1}me, 45); \r\n" +
			"{2}ge = XOR256(Bge, ANDnu256(Bgi, Bgo)); \r\n" +
			"XOReq256({1}si, Di); \r\n" +
			"ROL64in256(Bgu, {1}si, 61); \r\n" +
			"{2}gi = XOR256(Bgi, ANDnu256(Bgo, Bgu)); \r\n" +
			"{2}go = XOR256(Bgo, ANDnu256(Bgu, Bga)); \r\n" +
			"{2}gu = XOR256(Bgu, ANDnu256(Bga, Bge)); \r\n\r\n" +
			"XOReq256({1}be, De); \r\n" +
			"ROL64in256(Bka, {1}be, 1); \r\n" +
			"XOReq256({1}gi, Di); \r\n" +
			"ROL64in256(Bke, {1}gi, 6); \r\n" +
			"XOReq256({1}ko, Do); \r\n" +
			"ROL64in256(Bki, {1}ko, 25); \r\n" +
			"{2}ka = XOR256(Bka, ANDnu256(Bke, Bki)); \r\n" +
			"XOReq256({1}mu, Du); \r\n" +
			"ROL64in256_8(Bko, {1}mu); \r\n" +
			"{2}ke = XOR256(Bke, ANDnu256(Bki, Bko)); \r\n" +
			"XOReq256({1}sa, Da); \r\n" +
			"ROL64in256(Bku, {1}sa, 18); \r\n" +
			"{2}ki = XOR256(Bki, ANDnu256(Bko, Bku)); \r\n" +
			"{2}ko = XOR256(Bko, ANDnu256(Bku, Bka)); \r\n" +
			"{2}ku = XOR256(Bku, ANDnu256(Bka, Bke)); \r\n\r\n" +
			"XOReq256({1}bu, Du); \r\n" +
			"ROL64in256(Bma, {1}bu, 27); \r\n" +
			"XOReq256({1}ga, Da); \r\n" +
			"ROL64in256(Bme, {1}ga, 36); \r\n" +
			"XOReq256({1}ke, De); \r\n" +
			"ROL64in256(Bmi, {1}ke, 10); \r\n" +
			"{2}ma = XOR256(Bma, ANDnu256(Bme, Bmi)); \r\n" +
			"XOReq256({1}mi, Di); \r\n" +
			"ROL64in256(Bmo, {1}mi, 15); \r\n" +
			"{2}me = XOR256(Bme, ANDnu256(Bmi, Bmo)); \r\n" +
			"XOReq256({1}so, Do); \r\n" +
			"ROL64in256_56(Bmu, {1}so); \r\n" +
			"{2}mi = XOR256(Bmi, ANDnu256(Bmo, Bmu)); \r\n" +
			"{2}mo = XOR256(Bmo, ANDnu256(Bmu, Bma)); \r\n" +
			"{2}mu = XOR256(Bmu, ANDnu256(Bma, Bme)); \r\n\r\n" +
			"XOReq256({1}bi, Di); \r\n" +
			"ROL64in256(Bsa, {1}bi, 62); \r\n" +
			"XOReq256({1}go, Do); \r\n" +
			"ROL64in256(Bse, {1}go, 55); \r\n" +
			"XOReq256({1}ku, Du); \r\n" +
			"ROL64in256(Bsi, {1}ku, 39); \r\n" +
			"{2}sa = XOR256(Bsa, ANDnu256(Bse, Bsi)); \r\n" +
			"XOReq256({1}ma, Da); \r\n" +
			"ROL64in256(Bso, {1}ma, 41); \r\n" +
			"{2}se = XOR256(Bse, ANDnu256(Bsi, Bso)); \r\n" +
			"XOReq256({1}se, De); \r\n" +
			"ROL64in256(Bsu, {1}se, 2); \r\n" +
			"{2}si = XOR256(Bsi, ANDnu256(Bso, Bsu)); \r\n" +
			"{2}so = XOR256(Bso, ANDnu256(Bsu, Bsa)); \r\n" +
			"{2}su = XOR256(Bsu, ANDnu256(Bsa, Bse)); \r\n";
}