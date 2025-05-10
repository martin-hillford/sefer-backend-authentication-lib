namespace Sefer.Backend.Authentication.Lib;

public class TokenGenerator : ITokenGenerator
{
    private readonly IKeyProvider _keyProvider;

    public TokenGenerator(IKeyProvider keyProvider)
    {
        _keyProvider = keyProvider;
    }

    public string CreateToken(int userId, string userRole, DateTime expiration)
    {
        var tokenObject = new Token
        {
            ExpirationDateTime = expiration,
            SessionId = Guid.NewGuid(),
            UserId = userId,
            UserRole = userRole
        };

        return Encrypt(tokenObject);
    }

    public Token? Verify(string token)
    {
        try
        {
            var parts = token.Split('.');
            var bytes = Convert.FromBase64String(parts[0]);
            var json = Encoding.UTF8.GetString(bytes);

            var hash = Hash(json);
            if(hash != parts[1]) return null;

            var data = JsonSerializer.Deserialize<Token>(json);
            return data?.ExpirationDateTime >= DateTime.UtcNow ? data : null;
        }
        catch(Exception) { return null; }
    }

    private string Hash(string data)
    {
        using var sha384Hash = SHA384.Create();
        var value = data + _keyProvider.GetKey();
        var bytes = Encoding.UTF8.GetBytes(value);
        var hash = sha384Hash.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }

    private string Encrypt(Token data)
    {
        var json = JsonSerializer.Serialize(data);
        var bytes = Encoding.UTF8.GetBytes(json);
        var base64 = Convert.ToBase64String(bytes);
        return  $"{base64}.{Hash(json)}";
    }
}
