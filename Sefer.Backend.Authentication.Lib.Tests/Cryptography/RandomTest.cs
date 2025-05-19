using Random = Sefer.Backend.Authentication.Lib.Cryptography.Random;

namespace Sefer.Backend.Authentication.Lib.Tests.Cryptography;

[TestClass]
public class RandomTest
{

    [TestMethod]
    [DataRow(32), DataRow(16), DataRow(8), DataRow(19), DataRow(17), DataRow(45), DataRow(99)]
    public void GetStringTest(int length)
    {
        var random = Random.GetString(length);
        Assert.AreEqual(random.Length, length);
    }
}