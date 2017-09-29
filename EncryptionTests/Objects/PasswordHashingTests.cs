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
        private static int hash_size = 128;
        private static int salt_size = 64;

        PasswordHasher _DefaultHasher;

        [OneTimeSetUp]
        public void Init()
        {
            _DefaultHasher = new PasswordHasher(hash_size, salt_size, iterations);
        }

        [Test]
        [Category("PasswordHashing")]
        public void TestHashComparison()
        {
            string hash = _DefaultHasher.GenerateHash(password1);
            Assert.IsTrue(_DefaultHasher.Verify(password1, hash));
        }

        [Test]
        [Category("PasswordHashing")]
        public void TestHashComparisonWithUnicode()
        {
            string hash = _DefaultHasher.GenerateHash(password2);
            Assert.IsTrue(_DefaultHasher.Verify(password2, hash));
        }

        [Test]
        [Category("PasswordHashing")]
        public void VerifySuccessiveHashesDiffer()
        {
            string hash1 = _DefaultHasher.GenerateHash(password1);
            string hash2 = _DefaultHasher.GenerateHash(password1);

            Assert.IsTrue(hash1 != hash2);
        }

        [Test]
        [Category("PasswordHashing")]
        public void TestCaseSensitivity()
        {
            string buffer = _DefaultHasher.GenerateHash("Foo");
            bool results = _DefaultHasher.Verify("foo", buffer);

            Assert.IsFalse(results, "Hashes should not match");
        }
    }
}
