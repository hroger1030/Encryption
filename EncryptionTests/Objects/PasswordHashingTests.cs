using Encryption;
using NUnit.Framework;

namespace EncryptionUnitTests
{
    [TestFixture]
    public class PasswordHashingTests
    {
        private static string password1 = "12345";
        private static string password2 = "象形字象形字象形字";
        private static int iterations = 64;

        [Test]
        [Category("PasswordHashing")]
        public void TestHashComparison()
        {
            var encryptor = new PasswordHasher(iterations);

            string hash = encryptor.GenerateHash(password1);
            Assert.IsTrue(encryptor.Verify(password1, hash));
        }

        [Test]
        [Category("PasswordHashing")]
        public void TestHashComparisonWithUnicode()
        {
            var encryptor = new PasswordHasher(iterations);

            string hash = encryptor.GenerateHash(password2);
            Assert.IsTrue(encryptor.Verify(password2, hash));
        }

        [Test]
        [Category("PasswordHashing")]
        public void VerifySuccessiveHashesDiffer()
        {
            var encryptor = new PasswordHasher(iterations);

            string hash1 = encryptor.GenerateHash(password1);
            string hash2 = encryptor.GenerateHash(password1);

            Assert.IsTrue(hash1 != hash2);
        }

        [Test]
        [Category("PasswordHashing")]
        public void TestCaseSensitivity()
        {
            var password_hasher = new PasswordHasher(4);

            string buffer = password_hasher.GenerateHash("Foo");
            bool results = password_hasher.Verify("foo", buffer);

            Assert.IsFalse(results, "Hashes should not match");
        }
    }
}
