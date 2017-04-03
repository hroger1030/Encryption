namespace Encryption
{
    public interface IPasswordHasher
    {
        string GenerateHash(string password);
        bool Verify(string password, string hash);
    }
}