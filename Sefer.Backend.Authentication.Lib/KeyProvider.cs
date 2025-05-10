namespace Sefer.Backend.Authentication.Lib;

public class KeyProvider(IConfiguration configuration) : IKeyProvider
{
    public string GetKey() => configuration.GetValue<string>("SharedKey")!;
}