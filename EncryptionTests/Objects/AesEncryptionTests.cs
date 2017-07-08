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
            AesEncryption encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            byte[] decrypted = encryptor.Decrypt(encrypted, password, salt, iv, 1, 256);

            Assert.IsTrue(byte_text.SequenceEqual(decrypted));
        }

        [Test]
        [Category("AesEncryption")]
        public void BasicEncryptionWithBytesUsingAesParameters()
        {
            AesEncryption encryptor = new AesEncryption(iv, 4000, 256);

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt);
            byte[] decrypted = encryptor.Decrypt(encrypted, password, salt);

            Assert.IsTrue(byte_text.SequenceEqual(decrypted));
        }

        [Test]
        [Category("AesEncryption")]
        public void BasicEncryptionWithStrings()
        {
            AesEncryption encryptor = new AesEncryption();

            string encrypted = encryptor.Encrypt(text, password, salt, iv, 1, 256);
            string decrypted = encryptor.Decrypt(encrypted, password, salt, iv, 1, 256);

            Assert.IsTrue(text == decrypted);
        }

        [Test]
        [Category("AesEncryption")]
        public void BasicEncryptionWithStringsAesParameters()
        {
            AesEncryption encryptor = new AesEncryption(iv, 4000, 256);

            string encrypted = encryptor.Encrypt(text, password, salt);
            string decrypted = encryptor.Decrypt(encrypted, password, salt);

            Assert.IsTrue(text == decrypted);
        }

        [Test]
        [Category("AesEncryption")]
        public void IterationMismatchFailure()
        {
            AesEncryption encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, password, salt, iv, 2, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void KeySizeFailure()
        {
            AesEncryption encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 128);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, password, salt, iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void PasswordFailure()
        {
            AesEncryption encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, "foo", salt, iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void SaltFailure()
        {
            AesEncryption encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, password, "fooffoof", iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void PasswordEmpty()
        {
            AesEncryption encryptor = new AesEncryption();

            Assert.Throws<ArgumentException>(() => encryptor.Encrypt(byte_text, string.Empty, salt, iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void TextEmpty()
        {
            AesEncryption encryptor = new AesEncryption();

            Assert.Throws<ArgumentException>(() => encryptor.Encrypt(string.Empty, password, salt, iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void SaltTooShortFailure()
        {
            AesEncryption encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<ArgumentException>(() => encryptor.Decrypt(encrypted, password, "fooffoo", iv, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void IvFailure()
        {
            AesEncryption encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            byte[] decrypted = encryptor.Decrypt(encrypted, password, salt, "fooffooffooffoof", 1, 256);

            Assert.IsFalse(byte_text.SequenceEqual(decrypted));
        }

        [Test]
        [Category("AesEncryption")]
        public void IvTooShortFailure()
        {
            AesEncryption encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<ArgumentException>(() => encryptor.Decrypt(encrypted, password, salt, "fooffooffooffoo", 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void IvTooLongFailure()
        {
            AesEncryption encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(byte_text, password, salt, iv, 1, 256);
            Assert.Throws<ArgumentException>(() => encryptor.Decrypt(encrypted, password, salt, "fooffooffooffoof1", 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void TestSaltLength()
        {
            AesEncryption encryptor = new AesEncryption();

            string test_salt = encryptor.GenerateSalt();

            Assert.IsTrue(test_salt.Length > salt_length);

            byte[] encrypted = encryptor.Encrypt(byte_text, password, test_salt, iv, 1, 256);
            byte[] decrypted = encryptor.Decrypt(encrypted, password, test_salt, iv, 1, 256);

            Assert.IsTrue(byte_text.SequenceEqual(decrypted));
        }
    }
}
