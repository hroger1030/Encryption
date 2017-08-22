using System;
using System.Collections.Generic;

using Encryption;
using NUnit.Framework;

namespace EncryptionUnitTests
{
    [TestFixture]
    public class CryptoRngTests
    {
        private static uint _MaxValue = 201;
        private static int _Trials = 10000;
        private static int _PasswordLength = 16;

        CryptoRng _Rand = new CryptoRng();

        [Test]
        [Category("CryptoRng")]
        public void TestRandomString()
        {
            string output = _Rand.GeneratePassword(_PasswordLength);

            Console.WriteLine(output);
            Assert.IsTrue(output.Length > 16);
        }

        [Test]
        [Category("CryptoRng")]
        public void TestRandomInt()
        {
            for (int i = 0; i < 100; i++)
            {
                var output = _Rand.GenerateInt(1,10);
                Assert.IsTrue(output >= 1 && output <= 10, $"Random number '{output}' is out of range");
            }
        }

        [Test]
        [Category("CryptoRng")]
        public void TestValueDistrabution()
        {
            // framework to test generation methods.
            // any methods exposed should produce normal distabutions...

            var test = new Dictionary<uint, int>();

            for (int i = 0; i < _Trials; i++)
            {
                var buffer = _Rand.GenerateUint(0, _MaxValue);

                if (!test.ContainsKey(buffer))
                    test.Add(buffer, 0);

                test[buffer]++;
            }

            // calculate the standard deviation...
            long sum = 0;

            foreach (var kvp in test)
                sum += (kvp.Key * kvp.Value);

            double average = sum / (double)_Trials;

            double deviation_sum = 0;

            foreach (var kvp in test)
                deviation_sum += (kvp.Key - average) * (kvp.Key - average);

            double std_deviation = Math.Pow((deviation_sum / (double)(_Trials - 1)), 0.5);
        }
    }
}
