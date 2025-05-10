namespace Sefer.Backend.Authentication.Lib.Tests.Cryptography;

[TestClass]
public class CryptographyServiceTest
{
    private const string DefaultSha512hash = "hDXOV5YNcpmeMNRBwxOHdLUoV3QnNZFNN3LzQMOYzqwgKSlFEbJw+Vi9WNs/qCnuUK+N0P+4YRtU6WL+3sKabQ==";

    [TestMethod]
    public void Test_Hash()
    {
        var service = CreateWithDefaults();
        var hash = service.Hash("4FmYDS2l86DY");

        // hash should return sha512(value + salt) in base64
        hash.Should().Be(DefaultSha512hash);
    }

    [TestMethod]
    public void Test_HashWithSalt()
    {
        var service = new CryptographyService(default!, default!);
        var hash = service.Hash("4FmYDS2l86DY", "m0dfafPq4otwm9Z3Jy7l5TavXBNkYA9UFyRqS3XwusNVKuSJ");

        // hash should return sha512(value + salt) in base64
        hash.Should().Be(DefaultSha512hash);
    }

    [TestMethod]
    [DataRow(DefaultSha512hash, true)]
    [DataRow("4FmYDS2l86DY", false)]
    public void Test_IsValidHash(string provided, bool expected)
    {
        var service = CreateWithDefaults();
        var isValid = service.IsValidHash(provided, "4FmYDS2l86DY");
        isValid.Should().Be(expected);
    }

    [TestMethod]
    public void Test_HashPasswordIsNotSha512()
    {
        var service = new CryptographyService(default!, default!);
        var hash = service.HashPassword("4FmYDS2l86DY", "m0dfafPq4otwm9Z3Jy7l5TavXBNkYA9UFyRqS3XwusNVKuSJ");
        hash.Should().NotBe(DefaultSha512hash);
    }

    [TestMethod]
    public void Test_Salt()
    {
        var service = new CryptographyService(default!, default!);
        var salt = service.Salt();
        var bytes = Convert.FromBase64String(salt);
        bytes.Length.Should().Be(64);
    }

    private static CryptographyService CreateWithDefaults()
    {
        var salt = "m0dfafPq4otwm9Z3Jy7l5TavXBNkYA9UFyRqS3XwusNVKuSJ";
        var options = new Mock<ISecurityOptions>();
        options.Setup(o => o.DataProtectionKey).Returns(salt);
        return new CryptographyService(default!, options.Object);
    }
}