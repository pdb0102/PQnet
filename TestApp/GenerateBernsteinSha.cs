using System.Text.RegularExpressions;

namespace TestApp;
internal class GenerateBernsteinSha {
	public static void Generate(string sha256_file, string sha512_file) {

		string Sha512_Bernstein = @"	private static int crypto_hashblocks_sha512(byte[] statebytes, byte[] in_buf, ulong inlen) {
		ulong[] state;
		ulong a;
		ulong b;
		ulong c;
		ulong d;
		ulong e;
		ulong f;
		ulong g;
		ulong h;
		ulong T1;
		ulong T2;
		int in_buf_offset;

		in_buf_offset = 0;
		state = new ulong[8];
		a = load_bigendian_64(statebytes, 0);
		state[0] = a;
		b = load_bigendian_64(statebytes, 8);
		state[1] = b;
		c = load_bigendian_64(statebytes, 16);
		state[2] = c;
		d = load_bigendian_64(statebytes, 24);
		state[3] = d;
		e = load_bigendian_64(statebytes, 32);
		state[4] = e;
		f = load_bigendian_64(statebytes, 40);
		state[5] = f;
		g = load_bigendian_64(statebytes, 48);
		state[6] = g;
		h = load_bigendian_64(statebytes, 56);
		state[7] = h;

		while (inlen >= 128) {
			ulong w0 = load_bigendian_64(in_buf, in_buf_offset + 0);
			ulong w1 = load_bigendian_64(in_buf, in_buf_offset + 8);
			ulong w2 = load_bigendian_64(in_buf, in_buf_offset + 16);
			ulong w3 = load_bigendian_64(in_buf, in_buf_offset + 24);
			ulong w4 = load_bigendian_64(in_buf, in_buf_offset + 32);
			ulong w5 = load_bigendian_64(in_buf, in_buf_offset + 40);
			ulong w6 = load_bigendian_64(in_buf, in_buf_offset + 48);
			ulong w7 = load_bigendian_64(in_buf, in_buf_offset + 56);
			ulong w8 = load_bigendian_64(in_buf, in_buf_offset + 64);
			ulong w9 = load_bigendian_64(in_buf, in_buf_offset + 72);
			ulong w10 = load_bigendian_64(in_buf, in_buf_offset + 80);
			ulong w11 = load_bigendian_64(in_buf, in_buf_offset + 88);
			ulong w12 = load_bigendian_64(in_buf, in_buf_offset + 96);
			ulong w13 = load_bigendian_64(in_buf, in_buf_offset + 104);
			ulong w14 = load_bigendian_64(in_buf, in_buf_offset + 112);
			ulong w15 = load_bigendian_64(in_buf, in_buf_offset + 120);

			F_64(w0, 0x428a2f98d728ae22UL)


	F_64(w1, 0x7137449123ef65cdUL)


	F_64(w2, 0xb5c0fbcfec4d3b2fUL)


	F_64(w3, 0xe9b5dba58189dbbcUL)


	F_64(w4, 0x3956c25bf348b538UL)


	F_64(w5, 0x59f111f1b605d019UL)


	F_64(w6, 0x923f82a4af194f9bUL)


	F_64(w7, 0xab1c5ed5da6d8118UL)


	F_64(w8, 0xd807aa98a3030242UL)


	F_64(w9, 0x12835b0145706fbeUL)


	F_64(w10, 0x243185be4ee4b28cUL)


	F_64(w11, 0x550c7dc3d5ffb4e2UL)


	F_64(w12, 0x72be5d74f27b896fUL)


	F_64(w13, 0x80deb1fe3b1696b1UL)


	F_64(w14, 0x9bdc06a725c71235UL)


	F_64(w15, 0xc19bf174cf692694UL)



	M_64(w0, w14, w9, w1)
	M_64(w1, w15, w10, w2)
	M_64(w2, w0, w11, w3)
	M_64(w3, w1, w12, w4)
	M_64(w4, w2, w13, w5)
	M_64(w5, w3, w14, w6)
	M_64(w6, w4, w15, w7)
	M_64(w7, w5, w0, w8)
	M_64(w8, w6, w1, w9)
	M_64(w9, w7, w2, w10)
	M_64(w10, w8, w3, w11)
	M_64(w11, w9, w4, w12)
	M_64(w12, w10, w5, w13)
	M_64(w13, w11, w6, w14)
	M_64(w14, w12, w7, w15)
	M_64(w15, w13, w8, w0)


	F_64(w0, 0xe49b69c19ef14ad2UL)


	F_64(w1, 0xefbe4786384f25e3UL)


	F_64(w2, 0x0fc19dc68b8cd5b5UL)


	F_64(w3, 0x240ca1cc77ac9c65UL)


	F_64(w4, 0x2de92c6f592b0275UL)


	F_64(w5, 0x4a7484aa6ea6e483UL)


	F_64(w6, 0x5cb0a9dcbd41fbd4UL)


	F_64(w7, 0x76f988da831153b5UL)


	F_64(w8, 0x983e5152ee66dfabUL)


	F_64(w9, 0xa831c66d2db43210UL)


	F_64(w10, 0xb00327c898fb213fUL)


	F_64(w11, 0xbf597fc7beef0ee4UL)


	F_64(w12, 0xc6e00bf33da88fc2UL)


	F_64(w13, 0xd5a79147930aa725UL)


	F_64(w14, 0x06ca6351e003826fUL)


	F_64(w15, 0x142929670a0e6e70UL)



	M_64(w0, w14, w9, w1)
	M_64(w1, w15, w10, w2)
	M_64(w2, w0, w11, w3)
	M_64(w3, w1, w12, w4)
	M_64(w4, w2, w13, w5)
	M_64(w5, w3, w14, w6)
	M_64(w6, w4, w15, w7)
	M_64(w7, w5, w0, w8)
	M_64(w8, w6, w1, w9)
	M_64(w9, w7, w2, w10)
	M_64(w10, w8, w3, w11)
	M_64(w11, w9, w4, w12)
	M_64(w12, w10, w5, w13)
	M_64(w13, w11, w6, w14)
	M_64(w14, w12, w7, w15)
	M_64(w15, w13, w8, w0)


	F_64(w0, 0x27b70a8546d22ffcUL)


	F_64(w1, 0x2e1b21385c26c926UL)


	F_64(w2, 0x4d2c6dfc5ac42aedUL)


	F_64(w3, 0x53380d139d95b3dfUL)


	F_64(w4, 0x650a73548baf63deUL)


	F_64(w5, 0x766a0abb3c77b2a8UL)


	F_64(w6, 0x81c2c92e47edaee6UL)


	F_64(w7, 0x92722c851482353bUL)


	F_64(w8, 0xa2bfe8a14cf10364UL)


	F_64(w9, 0xa81a664bbc423001UL)


	F_64(w10, 0xc24b8b70d0f89791UL)


	F_64(w11, 0xc76c51a30654be30UL)


	F_64(w12, 0xd192e819d6ef5218UL)


	F_64(w13, 0xd69906245565a910UL)


	F_64(w14, 0xf40e35855771202aUL)


	F_64(w15, 0x106aa07032bbd1b8UL)



	M_64(w0, w14, w9, w1)
	M_64(w1, w15, w10, w2)
	M_64(w2, w0, w11, w3)
	M_64(w3, w1, w12, w4)
	M_64(w4, w2, w13, w5)
	M_64(w5, w3, w14, w6)
	M_64(w6, w4, w15, w7)
	M_64(w7, w5, w0, w8)
	M_64(w8, w6, w1, w9)
	M_64(w9, w7, w2, w10)
	M_64(w10, w8, w3, w11)
	M_64(w11, w9, w4, w12)
	M_64(w12, w10, w5, w13)
	M_64(w13, w11, w6, w14)
	M_64(w14, w12, w7, w15)
	M_64(w15, w13, w8, w0)


	F_64(w0, 0x19a4c116b8d2d0c8UL)


	F_64(w1, 0x1e376c085141ab53UL)


	F_64(w2, 0x2748774cdf8eeb99UL)


	F_64(w3, 0x34b0bcb5e19b48a8UL)


	F_64(w4, 0x391c0cb3c5c95a63UL)


	F_64(w5, 0x4ed8aa4ae3418acbUL)


	F_64(w6, 0x5b9cca4f7763e373UL)


	F_64(w7, 0x682e6ff3d6b2b8a3UL)


	F_64(w8, 0x748f82ee5defb2fcUL)


	F_64(w9, 0x78a5636f43172f60UL)


	F_64(w10, 0x84c87814a1f0ab72UL)


	F_64(w11, 0x8cc702081a6439ecUL)


	F_64(w12, 0x90befffa23631e28UL)


	F_64(w13, 0xa4506cebde82bde9UL)


	F_64(w14, 0xbef9a3f7b2c67915UL)


	F_64(w15, 0xc67178f2e372532bUL)



	M_64(w0, w14, w9, w1)
	M_64(w1, w15, w10, w2)
	M_64(w2, w0, w11, w3)
	M_64(w3, w1, w12, w4)
	M_64(w4, w2, w13, w5)
	M_64(w5, w3, w14, w6)
	M_64(w6, w4, w15, w7)
	M_64(w7, w5, w0, w8)
	M_64(w8, w6, w1, w9)
	M_64(w9, w7, w2, w10)
	M_64(w10, w8, w3, w11)
	M_64(w11, w9, w4, w12)
	M_64(w12, w10, w5, w13)
	M_64(w13, w11, w6, w14)
	M_64(w14, w12, w7, w15)
	M_64(w15, w13, w8, w0)


	F_64(w0, 0xca273eceea26619cUL)


	F_64(w1, 0xd186b8c721c0c207UL)


	F_64(w2, 0xeada7dd6cde0eb1eUL)


	F_64(w3, 0xf57d4f7fee6ed178UL)


	F_64(w4, 0x06f067aa72176fbaUL)


	F_64(w5, 0x0a637dc5a2c898a6UL)


	F_64(w6, 0x113f9804bef90daeUL)


	F_64(w7, 0x1b710b35131c471bUL)


	F_64(w8, 0x28db77f523047d84UL)


	F_64(w9, 0x32caab7b40c72493UL)


	F_64(w10, 0x3c9ebe0a15c9bebcUL)


	F_64(w11, 0x431d67c49c100d4cUL)


	F_64(w12, 0x4cc5d4becb3e42b6UL)


	F_64(w13, 0x597f299cfc657e2aUL)


	F_64(w14, 0x5fcb6fab3ad6faecUL)


	F_64(w15, 0x6c44198c4a475817UL)



	a += state[0];
			b += state[1];
			c += state[2];
			d += state[3];
			e += state[4];
			f += state[5];
			g += state[6];
			h += state[7];

			state[0] = a;
			state[1] = b;
			state[2] = c;
			state[3] = d;
			state[4] = e;
			state[5] = f;
			state[6] = g;
			state[7] = h;

			in_buf_offset += 128;
			inlen -= 128;
		}

		store_bigendian_64(statebytes, 0, state[0]);
		store_bigendian_64(statebytes, 8, state[1]);
		store_bigendian_64(statebytes, 16, state[2]);
		store_bigendian_64(statebytes, 24, state[3]);
		store_bigendian_64(statebytes, 32, state[4]);
		store_bigendian_64(statebytes, 40, state[5]);
		store_bigendian_64(statebytes, 48, state[6]);
		store_bigendian_64(statebytes, 56, state[7]);

		return inlen;
	}
";

		string Sha256_Bernstein = @"	private static int crypto_hashblocks_sha256(byte[] statebytes, byte[] in_buf, int inlen) {
		uint[] state;
		uint a;
		uint b;
		uint c;
		uint d;
		uint e;
		uint f;
		uint g;
		uint h;
		uint T1;
		uint T2;
		int in_buf_offset;

		in_buf_offset = 0;
		state = new uint[8];

		a = load_bigendian_32(statebytes, 0);
		state[0] = a;
		b = load_bigendian_32(statebytes, 4);
		state[1] = b;
		c = load_bigendian_32(statebytes, 8);
		state[2] = c;
		d = load_bigendian_32(statebytes, 12);
		state[3] = d;
		e = load_bigendian_32(statebytes, 16);
		state[4] = e;
		f = load_bigendian_32(statebytes, 20);
		state[5] = f;
		g = load_bigendian_32(statebytes, 24);
		state[6] = g;
		h = load_bigendian_32(statebytes, 28);
		state[7] = h;

		while (inlen >= 64) {
			uint w0 = load_bigendian_32(in_buf, in_buf_offset + 0);
			uint w1 = load_bigendian_32(in_buf, in_buf_offset + 4);
			uint w2 = load_bigendian_32(in_buf, in_buf_offset + 8);
			uint w3 = load_bigendian_32(in_buf, in_buf_offset + 12);
			uint w4 = load_bigendian_32(in_buf, in_buf_offset + 16);
			uint w5 = load_bigendian_32(in_buf, in_buf_offset + 20);
			uint w6 = load_bigendian_32(in_buf, in_buf_offset + 24);
			uint w7 = load_bigendian_32(in_buf, in_buf_offset + 28);
			uint w8 = load_bigendian_32(in_buf, in_buf_offset + 32);
			uint w9 = load_bigendian_32(in_buf, in_buf_offset + 36);
			uint w10 = load_bigendian_32(in_buf, in_buf_offset + 40);
			uint w11 = load_bigendian_32(in_buf, in_buf_offset + 44);
			uint w12 = load_bigendian_32(in_buf, in_buf_offset + 48);
			uint w13 = load_bigendian_32(in_buf, in_buf_offset + 52);
			uint w14 = load_bigendian_32(in_buf, in_buf_offset + 56);
			uint w15 = load_bigendian_32(in_buf, in_buf_offset + 60);

			F_32(w0, 0x428a2f98);


		F_32(w1, 0x71374491);


		F_32(w2, 0xb5c0fbcf);


		F_32(w3, 0xe9b5dba5);


		F_32(w4, 0x3956c25b);


		F_32(w5, 0x59f111f1);


		F_32(w6, 0x923f82a4);


		F_32(w7, 0xab1c5ed5);


		F_32(w8, 0xd807aa98);


		F_32(w9, 0x12835b01);


		F_32(w10, 0x243185be);


		F_32(w11, 0x550c7dc3);


		F_32(w12, 0x72be5d74);


		F_32(w13, 0x80deb1fe);


		F_32(w14, 0x9bdc06a7);


		F_32(w15, 0xc19bf174);



		M_32(w0, w14, w9, w1);
			M_32(w1, w15, w10, w2);
			M_32(w2, w0, w11, w3);
			M_32(w3, w1, w12, w4);
			M_32(w4, w2, w13, w5);
			M_32(w5, w3, w14, w6);
			M_32(w6, w4, w15, w7);
			M_32(w7, w5, w0, w8);
			M_32(w8, w6, w1, w9);
			M_32(w9, w7, w2, w10);
			M_32(w10, w8, w3, w11);
			M_32(w11, w9, w4, w12);
			M_32(w12, w10, w5, w13);
			M_32(w13, w11, w6, w14);
			M_32(w14, w12, w7, w15);
			M_32(w15, w13, w8, w0);



			F_32(w0, 0xe49b69c1);


		F_32(w1, 0xefbe4786);


		F_32(w2, 0x0fc19dc6);


		F_32(w3, 0x240ca1cc);


		F_32(w4, 0x2de92c6f);


		F_32(w5, 0x4a7484aa);


		F_32(w6, 0x5cb0a9dc);


		F_32(w7, 0x76f988da);


		F_32(w8, 0x983e5152);


		F_32(w9, 0xa831c66d);


		F_32(w10, 0xb00327c8);


		F_32(w11, 0xbf597fc7);


		F_32(w12, 0xc6e00bf3);


		F_32(w13, 0xd5a79147);


		F_32(w14, 0x06ca6351);


		F_32(w15, 0x14292967);



		M_32(w0, w14, w9, w1);
			M_32(w1, w15, w10, w2);
			M_32(w2, w0, w11, w3);
			M_32(w3, w1, w12, w4);
			M_32(w4, w2, w13, w5);
			M_32(w5, w3, w14, w6);
			M_32(w6, w4, w15, w7);
			M_32(w7, w5, w0, w8);
			M_32(w8, w6, w1, w9);
			M_32(w9, w7, w2, w10);
			M_32(w10, w8, w3, w11);
			M_32(w11, w9, w4, w12);
			M_32(w12, w10, w5, w13);
			M_32(w13, w11, w6, w14);
			M_32(w14, w12, w7, w15);
			M_32(w15, w13, w8, w0);



			F_32(w0, 0x27b70a85);


		F_32(w1, 0x2e1b2138);


		F_32(w2, 0x4d2c6dfc);


		F_32(w3, 0x53380d13);


		F_32(w4, 0x650a7354);


		F_32(w5, 0x766a0abb);


		F_32(w6, 0x81c2c92e);


		F_32(w7, 0x92722c85);


		F_32(w8, 0xa2bfe8a1);


		F_32(w9, 0xa81a664b);


		F_32(w10, 0xc24b8b70);


		F_32(w11, 0xc76c51a3);


		F_32(w12, 0xd192e819);


		F_32(w13, 0xd6990624);


		F_32(w14, 0xf40e3585);


		F_32(w15, 0x106aa070);



M_32(w0, w14, w9, w1);
M_32(w1, w15, w10, w2);
M_32(w2, w0, w11, w3);
M_32(w3, w1, w12, w4);
M_32(w4, w2, w13, w5);
M_32(w5, w3, w14, w6);
M_32(w6, w4, w15, w7);
M_32(w7, w5, w0, w8);
M_32(w8, w6, w1, w9);
M_32(w9, w7, w2, w10);
M_32(w10, w8, w3, w11);
M_32(w11, w9, w4, w12);
M_32(w12, w10, w5, w13);
M_32(w13, w11, w6, w14);
M_32(w14, w12, w7, w15);
M_32(w15, w13, w8, w0);


		F_32(w0, 0x19a4c116);


		F_32(w1, 0x1e376c08);


		F_32(w2, 0x2748774c);


		F_32(w3, 0x34b0bcb5);


		F_32(w4, 0x391c0cb3);


		F_32(w5, 0x4ed8aa4a);


		F_32(w6, 0x5b9cca4f);


		F_32(w7, 0x682e6ff3);


		F_32(w8, 0x748f82ee);


		F_32(w9, 0x78a5636f);


		F_32(w10, 0x84c87814);


		F_32(w11, 0x8cc70208);


		F_32(w12, 0x90befffa);


		F_32(w13, 0xa4506ceb);


		F_32(w14, 0xbef9a3f7);


		F_32(w15, 0xc67178f2);



		a += state[0];
			b += state[1];
			c += state[2];
			d += state[3];
			e += state[4];
			f += state[5];
			g += state[6];
			h += state[7];

			state[0] = a;
			state[1] = b;
			state[2] = c;
			state[3] = d;
			state[4] = e;
			state[5] = f;
			state[6] = g;
			state[7] = h;

			in_buf_offset += 64;
			inlen -= 64;
		}

		store_bigendian_32(statebytes, 0, state[0]);
		store_bigendian_32(statebytes, 4, state[1]);
		store_bigendian_32(statebytes, 8, state[2]);
		store_bigendian_32(statebytes, 12, state[3]);
		store_bigendian_32(statebytes, 16, state[4]);
		store_bigendian_32(statebytes, 20, state[5]);
		store_bigendian_32(statebytes, 24, state[6]);
		store_bigendian_32(statebytes, 28, state[7]);

		return inlen;
	}";

		Regex SHR = new Regex(@"SHR\((?<x>[^\)]*)\s*,\s*(?<c>[^\)]*)\)", RegexOptions.Compiled);
		string SHR_Replace = @"((${x}) >> (${c}))";

		Regex ROTR_32 = new Regex(@"ROTR_32\((?<x>[^\)]*)\s*,\s*(?<c>[^\)]*)\)", RegexOptions.Compiled);
		string ROTR_32_Replace = @"(((${x}) >> (${c})) | ((${x}) << (32 - (${c}))))";

		Regex ROTR_64 = new Regex(@"ROTR_64\((?<x>[^\)]*)\s*,\s*(?<c>[^\)]*)\)", RegexOptions.Compiled);
		string ROTR_64_Replace = @"(((${x}) >> (${c})) | ((${x}) << (64 - (${c}))))";

		Regex Ch = new Regex(@"Ch\((?<x>[^\)]*)\s*,(?<y>[^\)]*)\s*,\s*(?<z>[^\)]*)\)", RegexOptions.Compiled);
		string Ch_Replace = @"(((${x}) & (${y})) ^ (~(${x}) & (${z})))";

		Regex Maj = new Regex(@"Maj\((?<x>[^\)]*)\s*,(?<y>[^\)]*)\s*,\s*(?<z>[^\)]*)\)", RegexOptions.Compiled);
		string Maj_Replace = @"(((${x}) & (${y})) ^ ((${x}) & (${z})) ^ ((${y}) & (${z})))";

		Regex Sigma0_32 = new Regex(@"Sigma0_32\(\s*(?<x>[^\)]*)\)", RegexOptions.Compiled);
		string Sigma0_32_Replace = @"(ROTR_32(${x}, 2) ^ ROTR_32(${x},13) ^ ROTR_32(${x},22))";

		Regex Sigma1_32 = new Regex(@"Sigma1_32\(\s*(?<x>[^\)]*)\)", RegexOptions.Compiled);
		string Sigma1_32_Replace = @"(ROTR_32(${x}, 6) ^ ROTR_32(${x},11) ^ ROTR_32(${x},25))";

		Regex sigma0_32 = new Regex(@"sigma0_32\(\s*(?<x>[^\)]*)\)", RegexOptions.Compiled);
		string sigma0_32_Replace = @"(ROTR_32(${x}, 7) ^ ROTR_32(${x},18) ^ SHR(${x},3))";

		Regex sigma1_32 = new Regex(@"sigma1_32\(\s*(?<x>[^\)]*)\)", RegexOptions.Compiled);
		string sigma1_32_Replace = @"(ROTR_32(${x},17) ^ ROTR_32(${x},19) ^ SHR(${x},10))";

		Regex Sigma0_64 = new Regex(@"Sigma0_64\(\s*(?<x>[^\)]*)\)", RegexOptions.Compiled);
		string Sigma0_64_Replace = @"(ROTR_64(${x},28) ^ ROTR_64(${x},34) ^ ROTR_64(${x},39))";

		Regex Sigma1_64 = new Regex(@"Sigma1_64\(\s*(?<x>[^\)]*)\)", RegexOptions.Compiled);
		string Sigma1_64_Replace = @"(ROTR_64(${x},14) ^ ROTR_64(${x},18) ^ ROTR_64(${x},41))";

		Regex sigma0_64 = new Regex(@"sigma0_64\(\s*(?<x>[^\)]*)\)", RegexOptions.Compiled);
		string sigma0_64_Replace = @"(ROTR_64(${x},1) ^ ROTR_64(${x},8) ^ SHR(${x},7))";

		Regex sigma1_64 = new Regex(@"sigma1_64\(\s*(?<x>[^\)]*)\)", RegexOptions.Compiled);
		string sigma1_64_Replace = @"(ROTR_64(${x},19) ^ ROTR_64(${x},61) ^ SHR(${x},6))";

		Regex M_32 = new Regex(@"M_32\((?<w0>[^,)]*), (?<w14>[^,)]*), (?<w9>[^,)]*), (?<w1>[^\)]*)\)", RegexOptions.Compiled);
		string M_32_Replace = @"${w0} = sigma1_32(${w14}) + (${w9}) + sigma0_32(${w1}) + (${w0});";

		Regex M_64 = new Regex(@"M_64\((?<w0>[^,)]*), (?<w14>[^,)]*), (?<w9>[^,)]*), (?<w1>[^\)]*)\)", RegexOptions.Compiled);
		string M_64_Replace = @"${w0} = sigma1_64(${w14}) + (${w9}) + sigma0_64(${w1}) + (${w0});";

		Regex F_32 = new Regex(@"F_32\((?<w>[^,)]*)\s*,\s*(?<k>[^\)]*)\)", RegexOptions.Compiled);
		string F_32_Replace = @"T1 = h + Sigma1_32(e) + Ch(e, f, g) + (${k}) + (${w});
T2 = Sigma0_32(a) + Maj(a, b, c);
h = g;
g = f;
f = e;
e = d + T1;
d = c;
c = b;
b = a;
a = T1 + T2;
";

		Regex F_64 = new Regex(@"F_64\((?<w>[^,)]*)\s*,\s*(?<k>[^\)]*)\)", RegexOptions.Compiled);
		string F_64_Replace = @"T1 = h + Sigma1_64(e) + Ch(e, f, g) + (${k}) + (${w});
T2 = Sigma0_64(a) + Maj(a, b, c);
h = g;
g = f;
f = e;
e = d + T1;
d = c;
c = b;
b = a;
a = T1 + T2;
";

		string step1 = F_32.Replace(Sha256_Bernstein, F_32_Replace);
		string step2 = M_32.Replace(step1, M_32_Replace);
		string step3 = sigma1_32.Replace(step2, sigma1_32_Replace);
		string step4 = sigma0_32.Replace(step3, sigma0_32_Replace);
		string step5 = Sigma1_32.Replace(step4, Sigma1_32_Replace);
		string step6 = Sigma0_32.Replace(step5, Sigma0_32_Replace);
		string step7 = Maj.Replace(step6, Maj_Replace);
		string step8 = Ch.Replace(step7, Ch_Replace);
		string step9 = ROTR_32.Replace(step8, ROTR_32_Replace);
		string step10 = SHR.Replace(step9, SHR_Replace);
		File.WriteAllText(sha256_file, step10);

		step1 = F_64.Replace(Sha512_Bernstein, F_64_Replace);
		step2 = M_64.Replace(step1, M_64_Replace);
		step3 = sigma1_64.Replace(step2, sigma1_64_Replace);
		step4 = sigma0_64.Replace(step3, sigma0_64_Replace);
		step5 = Sigma1_64.Replace(step4, Sigma1_64_Replace);
		step6 = Sigma0_64.Replace(step5, Sigma0_64_Replace);
		step7 = Maj.Replace(step6, Maj_Replace);
		step8 = Ch.Replace(step7, Ch_Replace);
		step9 = ROTR_64.Replace(step8, ROTR_64_Replace);
		step10 = SHR.Replace(step9, SHR_Replace);
		File.WriteAllText(sha512_file, step10);
	}
}
