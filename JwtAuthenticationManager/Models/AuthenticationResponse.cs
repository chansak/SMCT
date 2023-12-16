namespace JwtAuthenticationManager.Models
{
    public class AuthenticationResponse
    {
        public string IdentityId { get; set; }
        public string Token { get; set; }
        public int ExpiresIn { get; set; }
    }
}
