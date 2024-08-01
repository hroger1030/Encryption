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
        [TestCase(256)]
        [TestCase(192)]
        [TestCase(128)]
        public void AesEncryption_WithBytes_Passes(int keySize)
        {
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, keySize);
            byte[] decrypted = AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, keySize);

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
            var encryptor = new AesEncryption(DEFAULT_IV, passes, keySize);

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
            string encrypted = AesEncryption.Encrypt(DEFAULT_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, keySize);
            string decrypted = AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, 1, keySize);

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
            var encryptor = new AesEncryption(DEFAULT_IV, passes, keySize);

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
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize);
            Assert.Throws<CryptographicException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes+1, keySize));
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
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize);
            Assert.Throws<CryptographicException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, wrongKeySize));
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
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize);
            Assert.Throws<CryptographicException>(() => AesEncryption.Decrypt(encrypted, "foo", DEFAULT_SALT, DEFAULT_IV, passes, keySize));
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
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize);
            Assert.Throws<CryptographicException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, "fooffoof", DEFAULT_IV, passes, keySize));
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
            Assert.Throws<ArgumentNullException>(() => AesEncryption.Encrypt(BYTE_TEXT, string.Empty, DEFAULT_SALT, DEFAULT_IV, passes, keySize));
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
            Assert.Throws<ArgumentNullException>(() => AesEncryption.Encrypt(string.Empty, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize));
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
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize);
            Assert.Throws<ArgumentException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, "fooffoo", DEFAULT_IV, passes, keySize));
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
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize);
            byte[] decrypted = AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, "fooffooffooffoof", passes, keySize);

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
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize);
            Assert.Throws<ArgumentException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, "fooffooffooffoo", passes, keySize));
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
            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, DEFAULT_SALT, DEFAULT_IV, passes, keySize);
            Assert.Throws<ArgumentException>(() => AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, DEFAULT_SALT, "fooffooffooffoof1", passes, keySize));
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

            byte[] encrypted = AesEncryption.Encrypt(BYTE_TEXT, DEFAULT_PASSWORD, test_salt, DEFAULT_IV, passes, keySize);
            byte[] decrypted = AesEncryption.Decrypt(encrypted, DEFAULT_PASSWORD, test_salt, DEFAULT_IV, passes, keySize);

            Assert.That((BYTE_TEXT.SequenceEqual(decrypted)), Is.True);
        }
    }
}
