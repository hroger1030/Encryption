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

        [Test]
        [Category("CryptoRng")]
        public void TestRandomString()
        {
            CryptoRng random = new CryptoRng();
            string output = random.GeneratePassword(_PasswordLength);

            Console.WriteLine(output);
            Assert.IsTrue(output.Length > 16);
        }

        [Test]
        [Category("CryptoRng")]
        public void TestValueDistrabution()
        {
            CryptoRng random = new CryptoRng();

            // framework to test generation methods.
            // any methods exposed should produce normal distabutions...

            var test = new Dictionary<uint, int>();

            for (int i = 0; i < _Trials; i++)
            {
                var buffer = random.GenerateUint(0, _MaxValue);

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
