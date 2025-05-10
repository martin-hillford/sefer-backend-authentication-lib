namespace Sefer.Backend.Authentication.Lib;

public class Token
{
    public Guid SessionId { get; set; }

    public int UserId { get; set; }

    public string UserRole { get; set; } = string.Empty;

    public DateTime ExpirationDateTime { get; set; }

    [JsonIgnore]
    public string UniqueId => SessionId + UserId.ToString() + UserRole + ExpirationDateTime.ToString("yyyyMMddhhmm");
}