using Encryption;
using NUnit.Framework;

namespace EncryptionUnitTests
{
    [TestFixture]
    public class PasswordHashingTests
    {
        private const string PASSWORD1 = "12345";
        private const string PASSWORD2 = "象形字象形字象形字";
        private const int ITERATIONS = 64;
        private const int HASH_SIZE = 128;
        private const int SALT_SIZE = 64;

        PasswordHasher _DefaultHasher;

        [OneTimeSetUp]
        public void Init()
        {
            _DefaultHasher = new PasswordHasher(HASH_SIZE, SALT_SIZE, ITERATIONS);
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_TestHashComparison_Passes()
        {
            string hash = _DefaultHasher.GenerateHash(PASSWORD1);
            Assert.IsTrue(_DefaultHasher.Verify(PASSWORD1, hash));
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_TestHashComparisonWithUnicode_Passes()
        {
            string hash = _DefaultHasher.GenerateHash(PASSWORD2);
            Assert.IsTrue(_DefaultHasher.Verify(PASSWORD2, hash));
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_VerifySuccessiveHashesDiffer_Passes()
        {
            string hash1 = _DefaultHasher.GenerateHash(PASSWORD1);
            string hash2 = _DefaultHasher.GenerateHash(PASSWORD1);

            Assert.IsTrue(hash1 != hash2);
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_TestCaseSensitivity_Fails()
        {
            string buffer = _DefaultHasher.GenerateHash("Foo");
            bool results = _DefaultHasher.Verify("foo", buffer);

            Assert.IsFalse(results, "Hashes should not match");
        }
    }
}
