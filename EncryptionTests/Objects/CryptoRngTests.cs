using Encryption;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace EncryptionUnitTests
{
    [TestFixture]
    public class CryptoRngTests
    {
        private const uint MAX_VALUE = 201;
        private const int TRIALS = 10000;
        private const int PASSWORD_LENGTH = 16;

        private readonly CryptoRng _Rand = new();

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_TestRandomString_Passes()
        {
            // output is in base64, this will always be longer than raw bytes
            string output = _Rand.GeneratePassword(PASSWORD_LENGTH);

            Console.WriteLine(output);
            Assert.IsTrue(output.Length > PASSWORD_LENGTH);
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_TestRandomInt_Passes()
        {
            for (int i = 0; i < 100; i++)
            {
                var output = _Rand.GenerateInt(1,10);
                Assert.IsTrue(output >= 1 && output <= 10, $"Random number '{output}' is out of range");
            }
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_TestValueDistrabution_Passes()
        {
            // framework to test generation methods.
            // any methods exposed should produce normal distabutions...

            var test = new Dictionary<uint, int>();

            for (int i = 0; i < TRIALS; i++)
            {
                var buffer = _Rand.GenerateUint(0, MAX_VALUE);

                if (!test.ContainsKey(buffer))
                    test.Add(buffer, 0);

                test[buffer]++;
            }

            // calculate the standard deviation...
            long sum = 0;

            foreach (var kvp in test)
                sum += (kvp.Key * kvp.Value);

            double average = sum / (double)TRIALS;

            double deviation_sum = 0;

            foreach (var kvp in test)
                deviation_sum += (kvp.Key - average) * (kvp.Key - average);

            double std_deviation = Math.Pow((deviation_sum / (TRIALS - 1)), 0.5);

            Assert.IsTrue(std_deviation > 0.5);
        }
    }
}
