/*
The MIT License (MIT)

Copyright (c) 2007 Roger Hill

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

using System;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Encryption
{
    public class PasswordHasher : IPasswordHasher
    {
        // good reading
        //http://stackoverflow.com/questions/4181198/how-to-hash-a-password

        private const int MIN_HASH_SIZE = 20;
        private const int MIN_SALT_SIZE = 16;

        private readonly int _HashSize;
        private readonly int _SaltSize;
        private readonly int _Iterations;
        private readonly string _HashAlgorithm;

        public PasswordHasher(int hashSize, int saltSize, int iterations, string hashAlgorithm)
        {
            if (hashSize < MIN_HASH_SIZE)
                throw new ArgumentException("Hash size needs to be at least 20 bytes");

            if (saltSize < MIN_SALT_SIZE)
                throw new ArgumentException("Salt size needs to be at least 16 bytes");

            if (iterations < 1)
                throw new ArgumentException("Iterations cannot be less that 1");

            if (string.IsNullOrWhiteSpace(hashAlgorithm))
                throw new ArgumentNullException(nameof(hashAlgorithm), "hashAlgorithm is null or empty");

            _HashSize = hashSize;
            _SaltSize = saltSize;
            _Iterations = iterations;
            _HashAlgorithm = hashAlgorithm;
        }

        public string GenerateHash(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be null or empty");

            password = password.Trim();

            byte[] salt = new byte[_SaltSize];
            byte[] hash = new byte[_HashSize];

            // generate salt
            using (var crypto_provider = RandomNumberGenerator.Create())
            {
                crypto_provider.GetBytes(salt);
            }

            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, _Iterations, new HashAlgorithmName(_HashAlgorithm)))
            {
                hash = pbkdf2.GetBytes(_HashSize);
            }

            byte[] buffer = new byte[_HashSize + _SaltSize];
            Array.Copy(salt, 0, buffer, 0, _SaltSize);
            Array.Copy(hash, 0, buffer, _SaltSize, _HashSize);

            return Convert.ToBase64String(buffer);
        }

        public async Task<string> GenerateHashAsync(string password)
        {
            return await Task.FromResult(GenerateHash(password));
        }

        public bool Verify(string password, string hash)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be null or empty");

            if (string.IsNullOrWhiteSpace(hash))
                throw new ArgumentException("Hash cannot be null or empty");

            password = password.Trim();

            // Extract the bytes
            byte[] buffer = Convert.FromBase64String(hash);

            // extract salt
            byte[] salt = new byte[_SaltSize];
            Array.Copy(buffer, 0, salt, 0, _SaltSize);

            // extract old hash
            byte[] old_hash = new byte[_HashSize];
            Array.Copy(buffer, _SaltSize, old_hash, 0, _HashSize);

            // Compute the hash on the password the user entered
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, _Iterations, new HashAlgorithmName(_HashAlgorithm));
            byte[] new_hash = pbkdf2.GetBytes(_HashSize);

            for (int i = 0; i < _HashSize; i++)
            {
                if (old_hash[i] != new_hash[i])
                {
                    return false;
                }
            }

            return true;
        }

        public async Task<bool> VerifyAsync(string password, string hash)
        {
            return await Task.FromResult(Verify(password, hash));
        }
    }
}