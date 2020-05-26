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
        private readonly byte[] BYTE_TEXT = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
        private const string DEFAULT_TEXT = "a quick brown fox jumped over the lazy dog 象形字 ";
        private const string DEFAULT_PASSWORD = "12345";
        private const string DEFAULT_IV = "initialvector123";
        private const string DEFAULT_SALT = "saltsalt";
        private const int SALT_LENGTH = 64;

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_WithBytes()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256);
            byte[] decrypted = encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256);

            Assert.IsTrue(BYTE_TEXT.SequenceEqual(decrypted));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_BasicEncryptionWithBytesUsingAesParameters_Passes()
        {
            var encryptor = new AesEncryption(DEFAULT_IV, 4000, 256);

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT);
            byte[] decrypted = encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT);

            Assert.IsTrue(BYTE_TEXT.SequenceEqual(decrypted));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_BasicEncryptionWithStrings_Passes()
        {
            var encryptor = new AesEncryption();

            string encrypted = encryptor.Encrypt(DEFAULT_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256);
            string decrypted = encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256);

            Assert.IsTrue(DEFAULT_TEXT == decrypted);
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_BasicEncryptionWithStringsAesParameters_Passes()
        {
            var encryptor = new AesEncryption(DEFAULT_IV, 4000, 256);

            string encrypted = encryptor.Encrypt(DEFAULT_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT);
            string decrypted = encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT);

            Assert.IsTrue(DEFAULT_TEXT == decrypted);
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_IterationMismatchFailure_Throws()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 2, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_KeySizeFailure_Throws()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 128);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_PasswordFailure_Throws()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, "foo", DEFAULT_SALT, DEFAULT_IV, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_WrongSaltFail_Throws()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256);
            Assert.Throws<CryptographicException>(() => encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, "fooffoof", DEFAULT_IV, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_PasswordEmpty_Throws()
        {
            var encryptor = new AesEncryption();

            Assert.Throws<ArgumentException>(() => encryptor.Encrypt(BYTE_TEXT, string.Empty, DEFAULT_SALT, DEFAULT_IV, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_TextEmpty_Throws()
        {
            var encryptor = new AesEncryption();

            Assert.Throws<ArgumentException>(() => encryptor.Encrypt(string.Empty, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_SaltTooShort_Throws()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256);
            Assert.Throws<ArgumentException>(() => encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, "fooffoo", DEFAULT_IV, 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_WrongIv_Fails()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256);
            byte[] decrypted = encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, "fooffooffooffoof", 1, 256);

            Assert.IsFalse(BYTE_TEXT.SequenceEqual(decrypted));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_IvTooShort_Throws()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256);
            Assert.Throws<ArgumentException>(() => encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, "fooffooffooffoo", 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_IvTooLong_Throws()
        {
            var encryptor = new AesEncryption();

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, 256);
            Assert.Throws<ArgumentException>(() => encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, "fooffooffooffoof1", 1, 256));
        }

        [Test]
        [Category("AesEncryption")]
        public void AesEncryption_TestSaltLengthLongerThanMin_Passes()
        {
            var encryptor = new AesEncryption();

            string test_salt = encryptor.GenerateSalt();

            Assert.IsTrue(test_salt.Length > SALT_LENGTH);

            byte[] encrypted = encryptor.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, test_salt, DEFAULT_IV, 1, 256);
            byte[] decrypted = encryptor.Decrypt(encrypted, DEFAULT_PASSWORD, test_salt, DEFAULT_IV, 1, 256);

            Assert.IsTrue(BYTE_TEXT.SequenceEqual(decrypted));
        }
    }
}
