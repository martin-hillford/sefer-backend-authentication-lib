namespace Sefer.Backend.Authentication.Lib.Tests;

public class CookieCollection : List<KeyValuePair<string, string>>, IRequestCookieCollection
{
    string IRequestCookieCollection.this[string key] =>
        this.Any(p => p.Key == key) ? this.First(p => p.Key == key).Value : null;

    int IRequestCookieCollection.Count => Count;

    ICollection<string> IRequestCookieCollection.Keys =>
        this.Select(v => v.Key).ToList();

    bool IRequestCookieCollection.ContainsKey(string key) => this.Any(p => p.Key == key);

    bool IRequestCookieCollection.TryGetValue(string key, out string value)
    {
        var contains = this.Any(p => p.Key == key);
        value = contains ? this.First(p => p.Key == key).Value : null;
        return contains;
    }
}