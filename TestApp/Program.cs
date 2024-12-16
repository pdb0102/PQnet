// See https://aka.ms/new-console-template for more information
using System.Text;

using mldsa_net;

using TestApp;

Console.WriteLine("Hello, World!");
Dilithium2 dilithium2 = new Dilithium2();
byte[] pk;
byte[] sk;

string shake128_input = "a6fe00064257aa318b621c5eb311d32bb8004c2fa1a969d205d71762cc5d2e633907992629d1b69d9557ff6d5e8deb454ab00f6e497c89a4fea09e257a6fa2074bd818ceb5981b3e3faefd6e720f2d1edd9c5e4a5c51e5009abf636ed5bca53fe159c8287014a1bd904f5c8a7501625f79ac81eb618f478ce21cae6664acffb30572f059e1ad0fc2912264e8f1ca52af26c8bf78e09d75f3dd9fc734afa8770abe0bd78c90cc2ff448105fb16dd2c5b7edd8611a62e537db9331f5023e16d6ec150cc6e706d7c7fcbfff930c7281831fd5c4aff86ece57ed0db882f59a5fe403105d0592ca38a081fed84922873f538ee774f13b8cc09bd0521db4374aec69f4bae6dcb66455822c0b84c91a3474ffac2ad06f0a4423cd2c6a49d4f0d6242d6a1890937b5d9835a5f0ea5b1d01884d22a6c1718e1f60b3ab5e232947c76ef70b344171083c688093b5f1475377e3069863";
byte[] shake128_input_bytes = shake128_input.HexToBytes();
string shake128_output = "3109d9472ca436e805c6b3db2251a9bc";
byte[] shake128_output_bytes = shake128_output.HexToBytes();

byte[] test;
test = Encoding.UTF8.GetBytes("blah");
byte[] hash = new byte[136];
Array.Copy(test, hash, test.Length);
//Dilithium2.shake256(hash, 136, hash, test.Length);

dilithium2.crypto_sign_keypair(out pk, out sk);

byte[] sig;

dilithium2.crypto_sign_signature(out sig, Encoding.ASCII.GetBytes("1234"), Array.Empty<byte>(), sk);

int ret = dilithium2.crypto_sign_verify(sig, Encoding.ASCII.GetBytes("1234"), Array.Empty<byte>(), pk);

Console.WriteLine("pk: " + BitConverter.ToString(pk));

