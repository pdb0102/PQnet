// See https://aka.ms/new-console-template for more information
using System.Diagnostics;
using System.Runtime.Intrinsics.X86;
using System.Text;

using PQnet.Digest;

using TestApp;

void Shake128NistMonteCarloVectors() {
	Shake128 shake128;
	string msg_txt;
	byte[] msg;
	byte[] output;
	byte[] reference;
	int len;
	int outlen;
	int max_outlen;
	int min_outlen;
	int range;

	msg_txt = "c8b310cb97efa3855434998fa81c7674";
	min_outlen = 128 / 8;
	max_outlen = 1120 / 8;

	shake128 = new Shake128();

	output = new byte[256];
	reference = new byte[256];

	msg = msg_txt.HexToBytes();
	Array.Copy(msg, output, msg.Length);

	outlen = max_outlen;
	range = max_outlen - min_outlen + 1;

	for (int j = 0; j < 100; j++) {
		for (int i = 1; i < 1001; i++) {
			len = outlen;

			shake128.Init();
			shake128.AbsorbOnce(output, 16);
			shake128.Squeeze(output, 0, len);
			if (len < 16) {
				Array.Fill(output, (byte)0, 16 - len, len - 16);
			}
			outlen = min_outlen + (((output[len - 2] << 8) + output[len - 1]) % range);
			Console.WriteLine($"loop = {i}\nOutputlen = {len * 8}\nOutput = {output.ToHexString(0, len)}");
		}
	}


}

Shake128NistMonteCarloVectors();
Console.WriteLine($"Supported: {Avx2.X64.IsSupported}");

byte[] test;
test = Encoding.ASCII.GetBytes("test");
Tuple<byte[], byte[], byte[], byte[]> hash;

byte[] ss = Sha3_512.ComputeHash(test);
byte[] old;
old = PQnet.Digest.Sha3_512.ComputeHash(test, 4);

Stopwatch timer;

timer = Stopwatch.StartNew();
hash = Shake256x4.HashData(test, test, test, test, 64);
timer.Stop();
Console.WriteLine($"Shake256 x 4: {timer.ElapsedTicks} ticks");

timer = Stopwatch.StartNew();
hash = Shake256x4.HashData(test, test, test, test, 64);
timer.Stop();
Console.WriteLine($"Shake256 x 4: {timer.ElapsedTicks} ticks");

timer = Stopwatch.StartNew();
hash = Shake256x4.HashData(test, test, test, test, 64);
timer.Stop();
Console.WriteLine($"Shake256 x 4: {timer.ElapsedTicks} ticks");

byte[] fips;

#if not
fips = new byte[64];
PQnet.Digest.Shake.shake256(fips, 64, test, 4);
ShakeX4 shake;
byte[] data1 = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4 };
byte[] data2 = { 2, 2, 2, 2, 2, 2, 2, 2, 2 };
byte[] data3 = { 3, 3, 3, 3, 3, 3, 3, 3, 3 };
byte[] data4 = { 4, 4, 4, 4, 4, 4, 4, 4, 4 };

Vector256<byte> b = Vector256.LoadUnsafe(ref data1[0]);
string code = GenerateKeccak.GenerateRounds24();
code = GenerateKeccak.GenerateProcessFullLane();

shake = new ShakeX4();

shake.PermuteAll_24rounds();

#if not
state = new Sha256Parallel8.SHA256state();
Sha256Parallel8.sha256_init8x(state);

byte[] message;
byte[] in0;
byte[] in1;
byte[] in2;
byte[] in3;
byte[] in4;
byte[] in5;
byte[] in6;
byte[] in7;

in0 = Encoding.UTF8.GetBytes("1234");
in1 = in0;
in2 = in0;
in3 = in0;
in4 = in0;
in5 = in0;
in6 = in0;
in7 = in0;

byte[] out0;
byte[] out1;
byte[] out2;
byte[] out3;
byte[] out4;
byte[] out5;
byte[] out6;
byte[] out7;

Sha256Parallel8.perform_sha256x8(out out0, out out1, out out2, out out3, out out4, out out5, out out6, out out7, in0, in1, in2, in3, in4, in5, in6, in7);

Console.WriteLine($"Out0: {out0.ToHexString()}");
Console.WriteLine($"SHA2: {SHA256.Create().ComputeHash(in0).ToHexString()}");


#endif
#endif