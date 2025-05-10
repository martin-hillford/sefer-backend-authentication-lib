namespace Sefer.Backend.Authentication.Lib.Cryptography;

/// <summary>
/// The crypto service does need some
/// </summary>
public interface ISecurityOptions
{
    /// <summary>
    /// A key used for protecting data saved in some location
    /// </summary>
    public string DataProtectionKey { get; }

    /// <summary>
    /// A key used for protecting data transmitted in the url
    /// </summary>
    public string UrlProtectionKey { get; }

    /// <summary>
    /// The number of hours a token is valid
    /// </summary>
    public int TokenDurationInt { get; }

    /// <summary>
    /// Contains if a cookie can only be used in a secure context
    /// </summary>
    public bool SecureCookie { get; }
}
