using System;
using System.Linq;
using System.Security.Cryptography;

using Encryption;
using NUnit.Framework;

namespace EncryptionUnitTests
{
    [TestFixture]
    public class AesEncryptionTests
    {
        private static byte[] byte_text = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
        private static string text = "a quick brown fox jumped over the lazy dog 象形字 ";
        private static string password = "12345";
        private static string iv = "initialvector123";
        private static string salt = "saltsalt";
        private static int salt_length = 64;

        [Test]
        [Category("AesEncryption")]
        public void WithBytes()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            byte[] decrypted = encryptor.Decrypt(encrypted, password, salt, iv, 1, 256);

            Assert.IsTrue(byte_text.SequenceEqual(decrypted));
        }

        [Test]
        [Category("AesEncryption")]
        public void BasicEncryptionWithBytesUsingAesParameters()
        {
            var encryptor = new AesEncryption(iv, 4000, 256);

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt);
            byte[] decrypted = encryptor.Decrypt(encrypted, password, salt);

            Assert.IsTrue(byte_text.SequenceEqual(decrypted));
        }

        [Test]
        [Category("AesEncryption")]
        public void BasicEncryptionWithStrings()
        {
            var encryptor = new AesEncryption();

            string encrypted = encryptor.Encrypt(text, password, salt, iv, 1, 256);
            string decrypted = encryptor.Decrypt(encrypted, password, salt, iv, 1, 256);

            Assert.IsTrue(text == decrypted);
        }

        [Test]
        [Category("AesEncryption")]
        public void BasicEncryptionWithStringsAesParameters()
        {
            var encryptor = new AesEncryption(iv, 4000, 256);

            string encrypted = encryptor.Encrypt(text, password, salt);
            string decrypted = encryptor.Decrypt(encrypted, password, salt);

            Assert.IsTrue(text == decrypted);
        }

        [Test]
        [Category("AesEncryption")]
        public void IterationMismatchFailure()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, password, salt, iv, 2, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void KeySizeFailure()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 128);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, password, salt, iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void PasswordFailure()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, "foo", salt, iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void SaltFailure()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, password, "fooffoof", iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void PasswordEmpty()
        {
            var encryptor = new AesEncryption();

            Assert.Throws<ArgumentException>(() => encryptor.Encrypt(byte_text, string.Empty, salt, iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void TextEmpty()
        {
            var encryptor = new AesEncryption();

            Assert.Throws<ArgumentException>(() => encryptor.Encrypt(string.Empty, password, salt, iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void SaltTooShortFailure()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<ArgumentException>(() => encryptor.Decrypt(encrypted, password, "fooffoo", iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void IvFailure()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            byte[] decrypted = encryptor.Decrypt(encrypted, password, salt, "fooffooffooffoof", 1, 256);

            Assert.IsFalse(byte_text.SequenceEqual(decrypted));
        }

        [Test]
        [Category("AesEncryption")]
        public void IvTooShortFailure()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<ArgumentException>(() => encryptor.Decrypt(encrypted, password, salt, "fooffooffooffoo", 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void IvTooLongFailure()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<ArgumentException>(() => encryptor.Decrypt(encrypted, password, salt, "fooffooffooffoof1", 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void TestSaltLength()
        {
            var encryptor = new AesEncryption();

            string test_salt = encryptor.GenerateSalt();

            Assert.IsTrue(test_salt.Length > salt_length);

            byte[] encrypted = encryptor.Encrypt(byte_text, password, test_salt, iv, 1, 256);
            byte[] decrypted = encryptor.Decrypt(encrypted, password, test_salt, iv, 1, 256);

            Assert.IsTrue(byte_text.SequenceEqual(decrypted));
        }
    }
}
