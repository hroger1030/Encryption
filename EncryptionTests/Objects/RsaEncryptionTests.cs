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
using System.Linq;
using System.Text;

namespace EncryptionUnitTests
{
    [TestFixture]
    public class RsaEncryptionTests
    {
        private const int DEFAULT_KEY_SIZE = 512;
        private const string DEFAULT_TEXT = "a quick brown fox";

        private RsaEncryption _Rsa;
        private string _PublicKey;
        private string _PrivateKey;

        [OneTimeSetUp]
        public void Init()
        {
            _Rsa = new RsaEncryption();
            _Rsa.GenerateKeys(DEFAULT_KEY_SIZE, out _PublicKey, out _PrivateKey);
        }

        [Test]
        [Category("RsaEncryption")]
        public void RsaEncryption_GenerateKeys_ProducesDistinctNonEmptyKeys()
        {
            Assert.That(string.IsNullOrEmpty(_PublicKey), Is.False);
            Assert.That(string.IsNullOrEmpty(_PrivateKey), Is.False);
            Assert.That(_PublicKey, Is.Not.EqualTo(_PrivateKey));
        }

        [Test]
        [Category("RsaEncryption")]
        public void RsaEncryption_EncryptDecryptString_RoundTrips()
        {
            string encrypted = _Rsa.Encrypt(DEFAULT_TEXT, _PublicKey, DEFAULT_KEY_SIZE);
            string decrypted = _Rsa.DecryptText(encrypted, _PrivateKey, DEFAULT_KEY_SIZE);

            Assert.That(decrypted, Is.EqualTo(DEFAULT_TEXT));
        }

        [Test]
        [Category("RsaEncryption")]
        public void RsaEncryption_EncryptDecryptBytes_RoundTrips()
        {
            byte[] plainText = Encoding.UTF8.GetBytes(DEFAULT_TEXT);

            byte[] encrypted = _Rsa.Encrypt(plainText, _PublicKey, DEFAULT_KEY_SIZE);
            byte[] decrypted = _Rsa.Decrypt(encrypted, _PrivateKey, DEFAULT_KEY_SIZE);

            Assert.That(plainText.SequenceEqual(decrypted), Is.True);
        }

        [Test]
        [Category("RsaEncryption")]
        public void RsaEncryption_EncryptedTextDiffersFromPlainText()
        {
            string encrypted = _Rsa.Encrypt(DEFAULT_TEXT, _PublicKey, DEFAULT_KEY_SIZE);

            Assert.That(encrypted, Is.Not.EqualTo(DEFAULT_TEXT));
        }

        [Test]
        [Category("RsaEncryption")]
        public void RsaEncryption_EncryptNullOrEmptyData_Throws()
        {
            Assert.Throws<ArgumentException>(() => _Rsa.Encrypt(Array.Empty<byte>(), _PublicKey, DEFAULT_KEY_SIZE));
            Assert.Throws<ArgumentException>(() => _Rsa.Encrypt((byte[])null, _PublicKey, DEFAULT_KEY_SIZE));
        }

        [Test]
        [Category("RsaEncryption")]
        public void RsaEncryption_EncryptNullOrEmptyPublicKey_Throws()
        {
            byte[] plainText = Encoding.UTF8.GetBytes(DEFAULT_TEXT);

            Assert.Throws<ArgumentException>(() => _Rsa.Encrypt(plainText, string.Empty, DEFAULT_KEY_SIZE));
            Assert.Throws<ArgumentException>(() => _Rsa.Encrypt(plainText, null, DEFAULT_KEY_SIZE));
        }

        [Test]
        [Category("RsaEncryption")]
        public void RsaEncryption_DecryptNullOrEmptyData_Throws()
        {
            Assert.Throws<ArgumentException>(() => _Rsa.Decrypt(Array.Empty<byte>(), _PrivateKey, DEFAULT_KEY_SIZE));
            Assert.Throws<ArgumentException>(() => _Rsa.Decrypt((byte[])null, _PrivateKey, DEFAULT_KEY_SIZE));
        }

        [Test]
        [Category("RsaEncryption")]
        public void RsaEncryption_DecryptNullOrEmptyPrivateKey_Throws()
        {
            byte[] encrypted = _Rsa.Encrypt(Encoding.UTF8.GetBytes(DEFAULT_TEXT), _PublicKey, DEFAULT_KEY_SIZE);

            Assert.Throws<ArgumentException>(() => _Rsa.Decrypt(encrypted, string.Empty, DEFAULT_KEY_SIZE));
            Assert.Throws<ArgumentException>(() => _Rsa.Decrypt(encrypted, null, DEFAULT_KEY_SIZE));
        }

        [Test]
        [Category("RsaEncryption")]
        public void RsaEncryption_WrongPrivateKey_Throws()
        {
            _Rsa.GenerateKeys(DEFAULT_KEY_SIZE, out string otherPublicKey, out string otherPrivateKey);
            byte[] encrypted = _Rsa.Encrypt(Encoding.UTF8.GetBytes(DEFAULT_TEXT), _PublicKey, DEFAULT_KEY_SIZE);

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => _Rsa.Decrypt(encrypted, otherPrivateKey, DEFAULT_KEY_SIZE));
        }

        [Test]
        [Category("RsaEncryption")]
        [TestCase(512, true)]
        [TestCase(1024, true)]
        [TestCase(2048, true)]
        public void RsaEncryption_IsValidKeySize_ReturnsTrueForSizesDivisibleBy8(int keySize, bool expected)
        {
            Assert.That(_Rsa.IsValidKeySize(keySize), Is.EqualTo(expected));
        }

        [Test]
        [Category("RsaEncryption")]
        [TestCase(511)]
        [TestCase(513)]
        public void RsaEncryption_IsValidKeySize_ReturnsFalseForSizesNotDivisibleBy8(int keySize)
        {
            Assert.That(_Rsa.IsValidKeySize(keySize), Is.False);
        }

        [Test]
        [Category("RsaEncryption")]
        public void RsaEncryption_EncryptWithKeySizeNotDivisibleBy8_Throws()
        {
            byte[] plainText = Encoding.UTF8.GetBytes(DEFAULT_TEXT);
            Assert.Throws<ArgumentException>(() => _Rsa.Encrypt(plainText, _PublicKey, 513));
        }

        [Test]
        [Category("RsaEncryption")]
        public void RsaEncryption_GenerateKeysWithKeySizeNotDivisibleBy8_Throws()
        {
            Assert.Throws<ArgumentException>(() => _Rsa.GenerateKeys(513, out _, out _));
        }
    }
}
