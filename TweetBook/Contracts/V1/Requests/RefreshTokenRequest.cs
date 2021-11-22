namespace TweetBook.Contracts.V1.Requests
{
    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; }
        public string Token { get; set; }
    }
}