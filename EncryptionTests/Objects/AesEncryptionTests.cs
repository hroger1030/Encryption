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
using System.Security.Cryptography;

namespace EncryptionUnitTests
{
    [TestFixture]
    public class AesEncryptionTests
    {
        private readonly byte[] BYTE_TEXT = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        private const string DEFAULT_TEXT = "a quick brown fox jumped over the lazy dog 象形字 ";
        private const string DEFAULT_PASSWORD = "12345";
        private const string DEFAULT_IV = "initialvector123";
        private const string DEFAULT_SALT = "saltsalt";
        private const string DEFAULT_HASH_ALGORITHM = "SHA512";
        private const int SALT_LENGTH = 64;

        [Test]
        [Category("AesEncryption")]
        [TestCase(256)]
        [TestCase(192)]
        [TestCase(128)]
        public void AesEncryption_WithBytes_Passes(int keySize)
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, keySize, DEFAULT_HASH_ALGORITHM);
            byte[] decrypted = AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, keySize, DEFAULT_HASH_ALGORITHM);

            Assert.That(BYTE_TEXT.SequenceEqual(decrypted), Is.True);
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1,256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_BasicEncryptionWithBytesUsingAesParameters_Passes(int passes, int keySize)
        {
            var encryptor = new AesEncryption(DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT);
            byte[] decrypted = encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT);

            Assert.That(BYTE_TEXT.SequenceEqual(decrypted), Is.True);
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(256)]
        [TestCase(192)]
        [TestCase(128)]
        public void AesEncryption_BasicEncryptionWithStrings_Passes(int keySize)
        {
            string encrypted = AesEncryption.Encrypt(DEFAULT_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, keySize, DEFAULT_HASH_ALGORITHM);
            string decrypted = AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, keySize, DEFAULT_HASH_ALGORITHM);

            Assert.That((DEFAULT_TEXT == decrypted), Is.True);
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_BasicEncryptionWithStringsAesParameters_Passes(int passes, int keySize)
        {
            var encryptor = new AesEncryption(DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);

            string encrypted = encryptor.Encrypt(DEFAULT_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT);
            string decrypted = encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT);

            Assert.That((DEFAULT_TEXT == decrypted), Is.True);
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_IterationMismatchFailure_Throws(int passes, int keySize)
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);
            Assert.Throws<CryptographicException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes+1, keySize, DEFAULT_HASH_ALGORITHM));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256, 128)]
        [TestCase(100, 256, 128)]
        [TestCase(1000, 256, 128)]
        [TestCase(1, 192, 128)]
        [TestCase(100, 192, 128)]
        [TestCase(1000, 192, 128)]
        [TestCase(1, 128, 256)]
        [TestCase(100, 128, 256)]
        [TestCase(1000, 128, 256)]
        public void AesEncryption_KeySizeFailure_Throws(int passes, int keySize, int wrongKeySize)
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);
            Assert.Throws<CryptographicException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, wrongKeySize, DEFAULT_HASH_ALGORITHM));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_PasswordFailure_Throws(int passes, int keySize)
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);
            Assert.Throws<CryptographicException>(() => AesEncryption.Decrypt(encrypted, "foo", DEFAULT_SALT, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_WrongSaltFail_Throws(int passes, int keySize)
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);
            Assert.Throws<CryptographicException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, "fooffoof", DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_PasswordEmpty_Throws(int passes, int keySize)
        {
            Assert.Throws<ArgumentNullException>(() => AesEncryption.Encrypt(BYTE_TEXT, string.Empty, DEFAULT_SALT, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_TextEmpty_Throws(int passes, int keySize)
        {
            Assert.Throws<ArgumentNullException>(() => AesEncryption.Encrypt(string.Empty, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_SaltTooShort_Throws(int passes, int keySize)
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);
            Assert.Throws<ArgumentException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, "fooffoo", DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_WrongIv_Fails(int passes, int keySize)
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);
            byte[] decrypted = AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, "fooffooffooffoof", passes, keySize, DEFAULT_HASH_ALGORITHM);

            Assert.That(BYTE_TEXT.SequenceEqual(decrypted), Is.False);
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_IvTooShort_Throws(int passes, int keySize)
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);
            Assert.Throws<ArgumentException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, "fooffooffooffoo", passes, keySize, DEFAULT_HASH_ALGORITHM));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_IvTooLong_Throws(int passes, int keySize)
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);
            Assert.Throws<ArgumentException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, "fooffooffooffoof1", passes, keySize, DEFAULT_HASH_ALGORITHM));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(1, 256)]
        [TestCase(100, 256)]
        [TestCase(1000, 256)]
        [TestCase(1, 192)]
        [TestCase(100, 192)]
        [TestCase(1000, 192)]
        [TestCase(1, 128)]
        [TestCase(100, 128)]
        [TestCase(1000, 128)]
        public void AesEncryption_TestSaltLengthLongerThanMin_Passes(int passes, int keySize)
        {
            var encryptor = new AesEncryption();

            string test_salt = encryptor.GenerateSalt();

            Assert.That((test_salt.Length > SALT_LENGTH), Is.True);

            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, test_salt, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);
            byte[] decrypted = AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, test_salt, DEFAULT_IV, passes, keySize, DEFAULT_HASH_ALGORITHM);

            Assert.That((BYTE_TEXT.SequenceEqual(decrypted)), Is.True);
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_DefaultConstructor_RoundTrips()
        {
            var encryptor = new AesEncryption();
            string salt = encryptor.GenerateSalt();

            string encrypted = encryptor.Encrypt(DEFAULT_TEXT, DEFAULT_PASSWORD, salt);
            string decrypted = encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, salt);

            Assert.That(decrypted, Is.EqualTo(DEFAULT_TEXT));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase("SHA1")]
        [TestCase("SHA256")]
        [TestCase("SHA384")]
        [TestCase("SHA512")]
        public void AesEncryption_DifferentHashAlgorithms_RoundTrip(string hashAlgorithm)
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256, hashAlgorithm);
            byte[] decrypted = AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256, hashAlgorithm);

            Assert.That(BYTE_TEXT.SequenceEqual(decrypted), Is.True);
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_MismatchedHashAlgorithm_Throws()
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256, "SHA256");
            Assert.Throws<CryptographicException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256, "SHA512"));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_HashAlgorithmEmpty_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256, string.Empty));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(64)]
        [TestCase(128)]
        [TestCase(256)]
        public void AesEncryption_GenerateSaltWithLength_ReturnsRequestedLength(int length)
        {
            var encryptor = new AesEncryption();
            string salt = encryptor.GenerateSalt(length);
            byte[] saltBytes = Convert.FromBase64String(salt);

            Assert.That(saltBytes.Length, Is.EqualTo(length));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_GenerateSaltWithInvalidLength_Throws()
        {
            var encryptor = new AesEncryption();
            Assert.Throws<ArgumentException>(() => encryptor.GenerateSalt(0));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase(128, true)]
        [TestCase(192, true)]
        [TestCase(256, true)]
        [TestCase(64, false)]
        [TestCase(512, false)]
        public void AesEncryption_IsKeySizeValid_ReturnsExpectedResult(int keySize, bool expected)
        {
            Assert.That(AesEncryption.IsKeySizeValid(keySize), Is.EqualTo(expected));
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase("saltsalt", true)]
        [TestCase("short", false)]
        public void AesEncryption_IsSaltValidString_ReturnsExpectedResult(string salt, bool expected)
        {
            Assert.That(AesEncryption.IsSaltValid(salt), Is.EqualTo(expected));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_IsSaltValidBytes_ReturnsExpectedResult()
        {
            Assert.That(AesEncryption.IsSaltValid(new byte[8]), Is.True);
            Assert.That(AesEncryption.IsSaltValid(new byte[7]), Is.False);
        }

        [Test]
        [Category("AesEncryption")]
        [TestCase("initialvector123", true)]
        [TestCase("tooshort", false)]
        [TestCase("initialvector123extra", false)]
        public void AesEncryption_IsInitialVectorValidString_ReturnsExpectedResult(string iv, bool expected)
        {
            Assert.That(AesEncryption.IsInitialVectorValid(iv), Is.EqualTo(expected));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_IsInitialVectorValidBytes_ReturnsExpectedResult()
        {
            Assert.That(AesEncryption.IsInitialVectorValid(new byte[16]), Is.True);
            Assert.That(AesEncryption.IsInitialVectorValid(new byte[15]), Is.False);
        }
    }
}
