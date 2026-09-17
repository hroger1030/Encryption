/*
The MIT License (MIT)

Copyright (c) 2017 Roger Hill

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

using Encryption;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;

namespace EncryptionUnitTests
{
    [TestFixture]
    public class CryptoRngTests : IDisposable
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
            Assert.That((output.Length > PASSWORD_LENGTH), Is.True);
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_TestRandomInt_Passes()
        {
            for (int i = 0; i < 100; i++)
            {
                var output = _Rand.GenerateInt(1,10);
                Assert.That((output >= 1 && output <= 10), Is.True, $"Random number '{output}' is out of range");
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

            double deviationSum = 0;

            foreach (var kvp in test)
                deviationSum += (kvp.Key - average) * (kvp.Key - average);

            double stdDeviation = Math.Pow((deviationSum / (TRIALS - 1)), 0.5);

            Assert.That((stdDeviation > 0.5), Is.True);
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_GenerateGuid_ProducesDistinctNonEmptyValues()
        {
            var guid1 = _Rand.GenerateGuid();
            var guid2 = _Rand.GenerateGuid();

            Assert.That(guid1, Is.Not.EqualTo(Guid.Empty));
            Assert.That(guid1, Is.Not.EqualTo(guid2));
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_GenerateDouble_ProducesVaryingValues()
        {
            var values = Enumerable.Range(0, 20).Select(_ => _Rand.GenerateDouble()).Distinct();

            Assert.That(values.Count(), Is.GreaterThan(1));
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_GenerateIntUnbounded_ProducesVaryingValues()
        {
            var values = Enumerable.Range(0, 20).Select(_ => _Rand.GenerateInt()).Distinct();

            Assert.That(values.Count(), Is.GreaterThan(1));
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_GenerateIntWithMax_StaysInRange()
        {
            for (int i = 0; i < 100; i++)
            {
                var output = _Rand.GenerateInt(10);
                Assert.That((output >= 0 && output <= 10), Is.True, $"Random number '{output}' is out of range");
            }
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_GenerateUintUnbounded_ProducesVaryingValues()
        {
            var values = Enumerable.Range(0, 20).Select(_ => _Rand.GenerateUint()).Distinct();

            Assert.That(values.Count(), Is.GreaterThan(1));
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_GenerateUintWithMax_StaysInRange()
        {
            for (int i = 0; i < 100; i++)
            {
                var output = _Rand.GenerateUint(10);
                Assert.That((output <= 10), Is.True, $"Random number '{output}' is out of range");
            }
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_GenerateUlong_ProducesVaryingValues()
        {
            var values = Enumerable.Range(0, 20).Select(_ => _Rand.GenerateUlong()).Distinct();

            Assert.That(values.Count(), Is.GreaterThan(1));
        }

        [Test]
        [Category("CryptoRng")]
        [TestCase(0)]
        [TestCase(1)]
        [TestCase(16)]
        [TestCase(64)]
        public void CryptoRng_GenerateByteArray_ReturnsRequestedLength(int length)
        {
            byte[] output = _Rand.GenerateByteArray(length);

            Assert.That(output.Length, Is.EqualTo(length));
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_GenerateByteArray_ProducesVaryingContent()
        {
            byte[] first = _Rand.GenerateByteArray(32);
            byte[] second = _Rand.GenerateByteArray(32);

            Assert.That(first.SequenceEqual(second), Is.False);
        }

        [Test]
        [Category("CryptoRng")]
        public void CryptoRng_GeneratePasswordWithAlphabet_OnlyUsesAlphabetCharacters()
        {
            const string alphabet = "abc123";

            for (int i = 0; i < 100; i++)
            {
                string password = _Rand.GeneratePassword(alphabet, PASSWORD_LENGTH);

                Assert.That(password.Length, Is.EqualTo(PASSWORD_LENGTH));
                Assert.That(password.All(alphabet.Contains), Is.True, $"Password '{password}' contained a character outside the alphabet");
            }
        }

        public void Dispose()
        {
            _Rand?.Dispose();
        }
    }
}
