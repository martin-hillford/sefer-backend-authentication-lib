using System.Security.Cryptography;

namespace Sefer.Backend.Authentication.Lib.Tests.Cryptography;

public static class Random
{
    /// <summary>
    /// Returns a random string of the given length.
    /// </summary>
    public static string GetString(int length)
    {
        var provider = RandomNumberGenerator.Create();
        var bytes = new byte[length * 2];
        provider.GetBytes(bytes);
        return BitConverter.ToString(bytes).Replace("-", "")[..length];
    }
}