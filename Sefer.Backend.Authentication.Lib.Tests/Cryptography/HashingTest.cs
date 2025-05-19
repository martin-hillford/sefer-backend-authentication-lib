namespace Sefer.Backend.Authentication.Lib.Tests.Cryptography;

[TestClass]
public class HashingTest
{

    [DataRow("is is a test","5cce3320767e20e4c1d3c767a8d715b769bf76572edbd59aff9334ceec191239")]
    [DataRow("is is another test","544275da4390ab4680d7459e3ce3f670da6c633fd87fc38fd98aaf299ea54826")]
    [TestMethod]
    public void Sha256Test(string data, string expected)
    {
        var hash = Hashing.Sha256(data);
        Assert.AreEqual(expected, hash);
    }
}