using PQnet;
using PQnet.Digest;


namespace TestApp {
	class Program {
		static void Main(string[] args) {
			byte[] seed;
			byte[] meh;
			byte[][] shake_out;
			byte[][] po;
			byte[] final_single;
			byte[] final_x4;
			KeccakBase[] shake_base;
			KeccakBase shake_final;
			KeccakBaseX4 shake_parallel_base;


			bool use_256 = false;
			int absorb_length = 1000;
			int squeeze_length = 1000;
			int iterations = 2;

			Rng.randombytes(out seed, absorb_length);
			seed = new byte[absorb_length];

			meh = new byte[Math.Max(absorb_length, squeeze_length)];

			if (!use_256) {
				shake_out = new byte[4][];
				po = new byte[4][];
				shake_base = new Shake128[4];
				shake_final = new Shake128();
				for (int i = 0; i < 4; i++) {
					shake_base[i] = new Shake128();
					shake_out[i] = new byte[squeeze_length];
					po[i] = new byte[squeeze_length];
				}
				shake_parallel_base = new Shake128x4();
			} else {
				shake_out = new byte[4][];
				po = new byte[4][];
				shake_base = new Shake256[4];
				shake_final = new Shake256();
				for (int i = 0; i < 4; i++) {
					shake_base[i] = new Shake256();
					shake_out[i] = new byte[squeeze_length];
					po[i] = new byte[squeeze_length];
				}
				shake_parallel_base = new Shake256x4();
			}

			for (int i = 0; i < iterations; i++) {
				shake_base[0].Init();
				shake_base[0].Absorb(i == 0 ? seed : shake_out[3], absorb_length);
				shake_base[0].FinalizeAbsorb();
				shake_base[0].Squeeze(shake_out[0], 0, squeeze_length);
				shake_base[1].Init();
				shake_base[1].Absorb(shake_out[0], absorb_length);
				shake_base[1].FinalizeAbsorb();
				shake_base[1].Squeeze(shake_out[1], 0, squeeze_length);
				shake_base[2].Init();
				shake_base[2].Absorb(shake_out[1], absorb_length);
				shake_base[2].FinalizeAbsorb();
				shake_base[2].Squeeze(shake_out[2], 0, squeeze_length);
				shake_base[3].Init();
				shake_base[3].Absorb(shake_out[2], absorb_length);
				shake_base[3].FinalizeAbsorb();
				shake_base[3].Squeeze(shake_out[3], 0, squeeze_length);
			}

			shake_final.Absorb(shake_out[0], squeeze_length);
			shake_final.Absorb(shake_out[1], squeeze_length);
			shake_final.Absorb(shake_out[2], squeeze_length);
			shake_final.Absorb(shake_out[3], squeeze_length);
			shake_final.FinalizeAbsorb();

			final_single = new byte[squeeze_length];
			shake_final.Squeeze(final_single, 0, squeeze_length);

			for (int i = 0; i < iterations; i++) {
				shake_parallel_base.Reset();
				shake_parallel_base.Sponge(i == 0 ? seed : po[3], seed, seed, seed, po[0], meh, meh, meh, squeeze_length, absorb_length);

#if DEBUG
				Console.WriteLine("First squeeze comparison:");
				for (int x = 0; x < shake_base[0].states.Count; x++) {
					if (shake_parallel_base.states0.Count <= x) {
						continue;
					}
					if (!Shake256.CompareStates(shake_base[0].states[x], shake_parallel_base.states0[x])) {
						Console.WriteLine($"States differ at {x}");
					}
				}
#endif
				shake_parallel_base.Reset();
				shake_parallel_base.Sponge(seed, po[0], seed, seed, meh, po[1], meh, meh, squeeze_length, absorb_length);

#if DEBUG
				Console.WriteLine("Second squeeze comparison:");
				for (int x = 0; x < shake_base[1].states.Count; x++) {
					if (shake_parallel_base.states1.Count <= x) {
						Console.WriteLine($"Skipping state {x}");
						continue;
					}
					if (!Shake256.CompareStates(shake_base[1].states[x], shake_parallel_base.states1[x])) {
						Console.WriteLine($"States differ at {x}");
					}
				}
#endif

				shake_parallel_base.Reset();
				shake_parallel_base.Sponge(seed, seed, po[1], seed, meh, meh, po[2], meh, squeeze_length, absorb_length);

#if DEBUG
				Console.WriteLine("Third squeeze comparison:");
				for (int x = 0; x < shake_base[2].states.Count; x++) {
					if (shake_parallel_base.states2.Count <= x) {
						Console.WriteLine($"Skipping state {x}");
						continue;
					}
					if (!Shake256.CompareStates(shake_base[2].states[x], shake_parallel_base.states2[x])) {
						Console.WriteLine($"States differ at {x}");
					}
				}
#endif

				shake_parallel_base.Reset();
				shake_parallel_base.Sponge(seed, seed, seed, po[2], meh, meh, meh, po[3], squeeze_length, absorb_length);

#if DEBUG
				Console.WriteLine("Fourth squeeze comparison:");
				for (int x = 0; x < shake_base[3].states.Count; x++) {
					if (shake_parallel_base.states0.Count <= x) {
						Console.WriteLine($"Skipping state {x}");
						continue;
					}
					if (!Shake256.CompareStates(shake_base[3].states[x], shake_parallel_base.states3[x])) {
						Console.WriteLine($"States differ at {x}");
					}
				}
#endif
				shake_parallel_base.Reset();
			}

			shake_parallel_base.Reset();
			final_x4 = new byte[squeeze_length * 4];
			meh = new byte[squeeze_length * 4];
			Array.Copy(po[0], 0, final_x4, 0, squeeze_length);
			Array.Copy(po[1], 0, final_x4, squeeze_length, squeeze_length);
			Array.Copy(po[2], 0, final_x4, squeeze_length * 2, squeeze_length);
			Array.Copy(po[3], 0, final_x4, squeeze_length * 3, squeeze_length);

			shake_parallel_base.Sponge(final_x4, meh, meh, meh, final_x4, meh, meh, meh, squeeze_length, squeeze_length * 4);

#if DEBUG
			Console.WriteLine("Final squeeze comparison:");
			for (int x = 0; x < shake_final.states.Count; x++) {
				if (shake_parallel_base.states0.Count <= x) {
					Console.WriteLine($"Skipping state {x}");
					continue;
				}
				if (!Shake256.CompareStates(shake_final.states[x], shake_parallel_base.states0[x])) {
					Console.WriteLine($"States differ at {x}");
				}
			}
#endif

			for (int i = 0; i < squeeze_length; i++) {
				if (final_single[i] != final_x4[i]) {
					Console.WriteLine($"Mismatch at {i}");
					break;
				}
			}
		}
	}
}