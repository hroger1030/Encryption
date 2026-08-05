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
        private const string HASH_ALGORITHM = "SHA256";

        PasswordHasher _DefaultHasher;

        [OneTimeSetUp]
        public void Init()
        {
            _DefaultHasher = new PasswordHasher(HASH_SIZE, SALT_SIZE, ITERATIONS, HASH_ALGORITHM);
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_TestHashComparison_Passes()
        {
            string hash = _DefaultHasher.GenerateHash(PASSWORD1);
            Assert.That(_DefaultHasher.Verify(PASSWORD1, hash), Is.True);
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_TestHashComparisonWithUnicode_Passes()
        {
            string hash = _DefaultHasher.GenerateHash(PASSWORD2);
            Assert.That(_DefaultHasher.Verify(PASSWORD2, hash), Is.True);
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_VerifySuccessiveHashesDiffer_Passes()
        {
            string hash1 = _DefaultHasher.GenerateHash(PASSWORD1);
            string hash2 = _DefaultHasher.GenerateHash(PASSWORD1);

            Assert.That((hash1 != hash2), Is.True);
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_TestCaseSensitivity_Fails()
        {
            string buffer = _DefaultHasher.GenerateHash("Foo");
            bool results = _DefaultHasher.Verify("foo", buffer);

            Assert.That(results, Is.False, "Hashes should not match");
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_WrongPassword_Fails()
        {
            string hash = _DefaultHasher.GenerateHash(PASSWORD1);
            Assert.That(_DefaultHasher.Verify("wrong password", hash), Is.False);
        }

        [Test]
        [Category("PasswordHashing")]
        public async System.Threading.Tasks.Task PasswordHasher_GenerateHashAsyncAndVerifyAsync_Passes()
        {
            string hash = await _DefaultHasher.GenerateHashAsync(PASSWORD1);
            bool result = await _DefaultHasher.VerifyAsync(PASSWORD1, hash);

            Assert.That(result, Is.True);
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_GenerateHashNullOrEmpty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _DefaultHasher.GenerateHash(string.Empty));
            Assert.Throws<ArgumentException>(() => _DefaultHasher.GenerateHash(null));
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_VerifyNullOrEmptyPassword_Throws()
        {
            string hash = _DefaultHasher.GenerateHash(PASSWORD1);

            Assert.Throws<ArgumentException>(() => _DefaultHasher.Verify(string.Empty, hash));
            Assert.Throws<ArgumentException>(() => _DefaultHasher.Verify(null, hash));
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_VerifyNullOrEmptyHash_Throws()
        {
            Assert.Throws<ArgumentException>(() => _DefaultHasher.Verify(PASSWORD1, string.Empty));
            Assert.Throws<ArgumentException>(() => _DefaultHasher.Verify(PASSWORD1, null));
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_ConstructorHashSizeTooSmall_Throws()
        {
            Assert.Throws<ArgumentException>(() => new PasswordHasher(19, SALT_SIZE, ITERATIONS, HASH_ALGORITHM));
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_ConstructorSaltSizeTooSmall_Throws()
        {
            Assert.Throws<ArgumentException>(() => new PasswordHasher(HASH_SIZE, 15, ITERATIONS, HASH_ALGORITHM));
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_ConstructorIterationsTooSmall_Throws()
        {
            Assert.Throws<ArgumentException>(() => new PasswordHasher(HASH_SIZE, SALT_SIZE, 0, HASH_ALGORITHM));
        }

        [Test]
        [Category("PasswordHashing")]
        public void PasswordHasher_ConstructorHashAlgorithmEmpty_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new PasswordHasher(HASH_SIZE, SALT_SIZE, ITERATIONS, string.Empty));
        }
    }
}
