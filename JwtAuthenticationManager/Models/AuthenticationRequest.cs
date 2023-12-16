namespace JwtAuthenticationManager.Models
{
    public class AuthenticationRequest
    {
        public string IdentityId { get; set; }
        public string OTP { get; set; }
    }
}
