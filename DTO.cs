namespace WebApplication4
{
    public class CookieRequest
    {
        public string Cookies { get; set; }
        public string AndroidVersion { get; set; }
        public string DeviceManufacturer { get; set; }
        public string DeviceModel { get; set; }
    }

    public class AuthResponse
    {
        public string UserId { get; set; }
        public string AccessToken { get; set; }
    }
}
