namespace JwtAuthenticationManager.Models
{
    public class ListOfUsers {
        public List<AuthenticatedUser> Users { get; set; }
    }
    public class AuthenticatedUser
    {
        public string IdentityId { get; set;}
        public string OTP { get; set;}
        public string Role { get; set; }
    }
}