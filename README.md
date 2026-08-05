# Encryption

A small C# library of cryptography helpers for .NET — AES (Rijndael) symmetric encryption, RSA
asymmetric encryption, one-way hashing (MD5/SHA1/SHA256/SHA384/SHA512/PBKDF2), salted password
hashing and verification, and a cryptographically secure random number generator. Each component
is exposed behind an interface so it can be injected and mocked in consuming code.

## Solution layout

| Project                                | Description                                                          |
| --------------------------------------- | ---------------------------------------------------------------------- |
| [Encryption](Encryption)               | The library itself. Namespace: `Encryption`.                          |
| [EncryptionTests](EncryptionTests)     | NUnit test suite for the library.                                     |

## File tree

Only the files that matter for using or extending the library are listed below; build output
(`bin`/`obj`) and IDE folders are omitted.

```
Encryption/
├── Encryption.sln
├── LICENSE.txt
├── CLAUDE.md
├── Encryption/                          # Library project (namespace: Encryption)
│   ├── Encryption.csproj
│   └── Objects/
│       ├── AesEncryption.cs             # Symmetric (AES/Rijndael) encrypt/decrypt, PBKDF2 key derivation
│       ├── RsaEncryption.cs             # Asymmetric (RSA) encrypt/decrypt and key-pair generation
│       ├── HashGenerator.cs             # Static one-way hash helpers (MD5, SHA1/256/384/512, PBKDF2)
│       ├── PasswordHasher.cs            # Salted password hashing and verification
│       ├── CryptoRng.cs                 # Cryptographically secure random values (ints, doubles, GUIDs, passwords)
│       └── Interfaces/
│           ├── ISymetricEncryptionProvider.cs
│           ├── IRsaEncryption.cs
│           ├── IPasswordHasher.cs
│           └── ICryptoRng.cs
└── EncryptionTests/                      # NUnit test project (namespace: EncryptionTests)
    ├── EncryptionTests.csproj
    └── Objects/
        ├── AesEncryptionTests.cs
        ├── RsaEncryptionTests.cs
        ├── HashGeneratorTests.cs
        ├── PasswordHashingTests.cs
        └── CryptoRngTests.cs
```

## Requirements

- .NET 10 SDK
- Windows (target platform)

## Building and testing

```
dotnet build
dotnet test
```

## Components

### AesEncryption (`Encryption/Objects/AesEncryption.cs`)

Implements `ISymetricEncryptionProvider`. Encrypts/decrypts strings or byte arrays using AES in CBC
mode, deriving the key from a password and salt via `Rfc2898DeriveBytes` (PBKDF2). Instance methods
use the initialization vector, iteration count, key size, and hash algorithm supplied to the
constructor (or the class defaults); static overloads let every parameter be passed explicitly.
Also exposes `GenerateSalt` and static validation helpers (`IsKeySizeValid`, `IsSaltValid`,
`IsInitialVectorValid`).

### RsaEncryption (`Encryption/Objects/RsaEncryption.cs`)

Implements `IRsaEncryption`. Wraps `RSACryptoServiceProvider` to encrypt/decrypt strings or byte
arrays with a public/private key pair (XML key format), and to generate new key pairs via
`GenerateKeys`. `IsValidKeySize` checks that a requested key size is a valid multiple of 8 bits.

### HashGenerator (`Encryption/Objects/HashGenerator.cs`)

Static one-way hashing helpers, each with a `string` and `byte[]` overload: `ComputeMD5Hash`,
`ComputeSHA160Hash`, `ComputeSHA256Hash`, `ComputeSHA384Hash`, `ComputeSHA512Hash`, and
`ComputePBKDF2Hash` (salted, iterated key derivation). All return a Base64-encoded hash.

### PasswordHasher (`Encryption/Objects/PasswordHasher.cs`)

Implements `IPasswordHasher`. Generates a random salt, derives a PBKDF2 hash of a password, and
stores salt + hash together as a single Base64 string via `GenerateHash`/`GenerateHashAsync`.
`Verify`/`VerifyAsync` re-derive the hash from a supplied password and compare it against the
stored value. Hash size, salt size, iteration count, and hash algorithm are configured through the
constructor.

### CryptoRng (`Encryption/Objects/CryptoRng.cs`)

Implements `ICryptoRng`. Wraps `RandomNumberGenerator` to produce cryptographically secure random
`int`, `uint`, `ulong`, `double`, `Guid`, and byte-array values, including ranged overloads
(`GenerateInt(min, max)`, `GenerateUint(min, max)`) and password/string generation
(`GeneratePassword`).

## Code examples

### AES encryption

```csharp
using Encryption;

ISymetricEncryptionProvider aes = new AesEncryption();

string salt = aes.GenerateSalt();
string cipherText = aes.Encrypt("plain text", "my password", salt);
string plainText = aes.Decrypt(cipherText, "my password", salt);
```

### RSA encryption

```csharp
using Encryption;

IRsaEncryption rsa = new RsaEncryption();

rsa.GenerateKeys(2048, out string publicKey, out string privateKey);
string cipherText = rsa.Encrypt("plain text", publicKey, 2048);
string plainText = rsa.DecryptText(cipherText, privateKey, 2048);
```

### Hashing

```csharp
using Encryption;

string hash = HashGenerator.ComputeSHA256Hash("some input");
```

### Password hashing

```csharp
using Encryption;

IPasswordHasher hasher = new PasswordHasher(hashSize: 20, saltSize: 16, iterations: 10000, hashAlgorithm: "SHA256");

string stored = hasher.GenerateHash("my password");
bool isValid = hasher.Verify("my password", stored);
```

### Cryptographically secure random values

```csharp
using Encryption;

ICryptoRng rng = new CryptoRng();

int roll = rng.GenerateInt(1, 100);
Guid id = rng.GenerateGuid();
string password = rng.GeneratePassword(16);
```

## License

This project is licensed under the [MIT License](LICENSE.txt).

In short: you can do anything you want with these files, short of removing the license or claiming them as your own.
Go crazy with them.

See [LICENSE.txt](LICENSE.txt) for the full, legally-binding text.
