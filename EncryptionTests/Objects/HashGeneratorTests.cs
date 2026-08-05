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
using System.Text;

namespace EncryptionUnitTests
{
    [TestFixture]
    public class HashGeneratorTests
    {
        private const string DEFAULT_TEXT = "a quick brown fox jumped over the lazy dog 象形字";
        private const string DEFAULT_SALT = "saltsalt";
        private const int ITERATIONS = 10;
        private const string HASH_ALGORITHM = "SHA256";

        [Test]
        [Category("HashGenerator")]
        public void HashGenerator_ComputeMD5Hash_StringAndBytesMatch()
        {
            string fromString = HashGenerator.ComputeMD5Hash(DEFAULT_TEXT);
            string fromBytes = HashGenerator.ComputeMD5Hash(Encoding.UTF8.GetBytes(DEFAULT_TEXT));

            Assert.That(fromString, Is.EqualTo(fromBytes));
            Assert.That(Convert.FromBase64String(fromString).Length, Is.EqualTo(16));
        }

        [Test]
        [Category("HashGenerator")]
        public void HashGenerator_ComputeSHA160Hash_StringAndBytesMatch()
        {
            string fromString = HashGenerator.ComputeSHA160Hash(DEFAULT_TEXT);
            string fromBytes = HashGenerator.ComputeSHA160Hash(Encoding.UTF8.GetBytes(DEFAULT_TEXT));

            Assert.That(fromString, Is.EqualTo(fromBytes));
            Assert.That(Convert.FromBase64String(fromString).Length, Is.EqualTo(20));
        }

        [Test]
        [Category("HashGenerator")]
        public void HashGenerator_ComputeSHA256Hash_StringAndBytesMatch()
        {
            string fromString = HashGenerator.ComputeSHA256Hash(DEFAULT_TEXT);
            string fromBytes = HashGenerator.ComputeSHA256Hash(Encoding.UTF8.GetBytes(DEFAULT_TEXT));

            Assert.That(fromString, Is.EqualTo(fromBytes));
            Assert.That(Convert.FromBase64String(fromString).Length, Is.EqualTo(32));
        }

        [Test]
        [Category("HashGenerator")]
        public void HashGenerator_ComputeSHA384Hash_StringAndBytesMatch()
        {
            string fromString = HashGenerator.ComputeSHA384Hash(DEFAULT_TEXT);
            string fromBytes = HashGenerator.ComputeSHA384Hash(Encoding.UTF8.GetBytes(DEFAULT_TEXT));

            Assert.That(fromString, Is.EqualTo(fromBytes));
            Assert.That(Convert.FromBase64String(fromString).Length, Is.EqualTo(48));
        }

        [Test]
        [Category("HashGenerator")]
        public void HashGenerator_ComputeSHA512Hash_StringAndBytesMatch()
        {
            string fromString = HashGenerator.ComputeSHA512Hash(DEFAULT_TEXT);
            string fromBytes = HashGenerator.ComputeSHA512Hash(Encoding.UTF8.GetBytes(DEFAULT_TEXT));

            Assert.That(fromString, Is.EqualTo(fromBytes));
            Assert.That(Convert.FromBase64String(fromString).Length, Is.EqualTo(64));
        }

        [Test]
        [Category("HashGenerator")]
        public void HashGenerator_ComputePBKDF2Hash_StringAndBytesMatch()
        {
            string fromString = HashGenerator.ComputePBKDF2Hash(DEFAULT_TEXT, DEFAULT_SALT, ITERATIONS, HASH_ALGORITHM);
            string fromBytes = HashGenerator.ComputePBKDF2Hash(Encoding.UTF8.GetBytes(DEFAULT_TEXT), Encoding.UTF8.GetBytes(DEFAULT_SALT), ITERATIONS, HASH_ALGORITHM);

            Assert.That(fromString, Is.EqualTo(fromBytes));
            Assert.That(Convert.FromBase64String(fromString).Length, Is.EqualTo(20));
        }

        [Test]
        [Category("HashGenerator")]
        public void HashGenerator_ComputePBKDF2Hash_DifferentSaltsProduceDifferentHashes()
        {
            string hash1 = HashGenerator.ComputePBKDF2Hash(DEFAULT_TEXT, "saltsalt", ITERATIONS, HASH_ALGORITHM);
            string hash2 = HashGenerator.ComputePBKDF2Hash(DEFAULT_TEXT, "differentsalt", ITERATIONS, HASH_ALGORITHM);

            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        [TestCase(null)]
        [TestCase("")]
        [Category("HashGenerator")]
        public void HashGenerator_ComputeMD5HashNullOrEmpty_Throws(string input)
        {
            Assert.Throws<ArgumentNullException>(() => HashGenerator.ComputeMD5Hash(input));
        }

        [TestCase(null)]
        [TestCase("")]
        [Category("HashGenerator")]
        public void HashGenerator_ComputeSHA160HashNullOrEmpty_Throws(string input)
        {
            Assert.Throws<ArgumentNullException>(() => HashGenerator.ComputeSHA160Hash(input));
        }

        [TestCase(null)]
        [TestCase("")]
        [Category("HashGenerator")]
        public void HashGenerator_ComputeSHA256HashNullOrEmpty_Throws(string input)
        {
            Assert.Throws<ArgumentNullException>(() => HashGenerator.ComputeSHA256Hash(input));
        }

        [TestCase(null)]
        [TestCase("")]
        [Category("HashGenerator")]
        public void HashGenerator_ComputeSHA384HashNullOrEmpty_Throws(string input)
        {
            Assert.Throws<ArgumentNullException>(() => HashGenerator.ComputeSHA384Hash(input));
        }

        [TestCase(null)]
        [TestCase("")]
        [Category("HashGenerator")]
        public void HashGenerator_ComputeSHA512HashNullOrEmpty_Throws(string input)
        {
            Assert.Throws<ArgumentNullException>(() => HashGenerator.ComputeSHA512Hash(input));
        }

        [Test]
        [Category("HashGenerator")]
        public void HashGenerator_ComputePBKDF2HashEmptyInput_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => HashGenerator.ComputePBKDF2Hash(string.Empty, DEFAULT_SALT, ITERATIONS, HASH_ALGORITHM));
        }

        [Test]
        [Category("HashGenerator")]
        public void HashGenerator_ComputePBKDF2HashEmptySalt_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => HashGenerator.ComputePBKDF2Hash(DEFAULT_TEXT, string.Empty, ITERATIONS, HASH_ALGORITHM));
        }

        [Test]
        [Category("HashGenerator")]
        public void HashGenerator_ComputePBKDF2HashZeroIterations_Throws()
        {
            Assert.Throws<ArgumentException>(() => HashGenerator.ComputePBKDF2Hash(DEFAULT_TEXT, DEFAULT_SALT, 0, HASH_ALGORITHM));
        }

        [Test]
        [Category("HashGenerator")]
        public void HashGenerator_ComputePBKDF2HashAlgorithmEmpty_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => HashGenerator.ComputePBKDF2Hash(DEFAULT_TEXT, DEFAULT_SALT, ITERATIONS, string.Empty));
        }
    }
}
