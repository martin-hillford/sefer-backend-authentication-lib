namespace Sefer.Backend.Authentication.Lib;

public interface ITokenGenerator
{
    public string CreateToken(int userId, string userRole, DateTime expiration);

    public Token? Verify(string encryptedToken);
}