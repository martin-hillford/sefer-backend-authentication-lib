namespace Sefer.Backend.Authentication.Lib.Cryptography;

public static class Hashing
{
    public static string HashPassword(string password, string salt)
    {
        var saltBytes = Convert.FromBase64String(salt);
        var bytes = KeyDerivation.Pbkdf2(password, saltBytes, KeyDerivationPrf.HMACSHA512, 10000, 16);
        return Convert.ToBase64String(bytes);
    }

    public static string SHA512(string value)
    {
        var data = Encoding.UTF8.GetBytes(value);
        return SHA512(data);
    }

    public static string SHA512(byte[] data)
    {
        var bytes = System.Security.Cryptography.SHA512.HashData(data);
        return Convert.ToBase64String(bytes);
    }
}