namespace Sefer.Backend.Authentication.Lib.Tests.Util;

public static class Mocks
{
    public static TokenGenerator GetGenerator()
    {
        var keyProvider = new Mock<IKeyProvider>();
        keyProvider.Setup(k => k.GetKey()).Returns("shared-key");
        return new TokenGenerator(keyProvider.Object);
    }

    public static void VerifyAddSingleTon<TServiceType, TImplementationType>(this Mock<IServiceCollection> services) where TImplementationType : TServiceType
    {
        var serviceType = typeof(TServiceType);
        var implementationType = typeof(TImplementationType);

        services.Verify(s => s.Add(
            It.Is<ServiceDescriptor>
                (d =>  d.Lifetime == ServiceLifetime.Singleton && d.ServiceType == serviceType && d.ImplementationType == implementationType)
            ));
    }
}