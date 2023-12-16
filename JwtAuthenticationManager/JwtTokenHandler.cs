using JwtAuthenticationManager.Helper;
using JwtAuthenticationManager.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using System.Text.Json;

namespace JwtAuthenticationManager
{
    public class JwtTokenHandler
    {
        public const string JWT_SECURITY_KEY = "yPkCqn4kSWLtaJwXvN2jGzpQRyTZ3gdXkt7FeBJP";
        private const int JWT_TOKEN_VALIDITY_MINS = 20;
        private List<AuthenticatedUser> _users;

        public JwtTokenHandler()
        {
            this._users = new List<AuthenticatedUser>();
        }
        public AuthenticationResponse? GenerateJwtToken(AuthenticationRequest authenticationRequest)
        {

            this._users.AddRange(JsonFileReader.Read<ListOfUsers>(@"users.json").Users);
            if (string.IsNullOrWhiteSpace(authenticationRequest.IdentityId) || string.IsNullOrWhiteSpace(authenticationRequest.OTP))
                return null;

            /* Validation */
            var userAccount = this._users.Where(x => x.IdentityId == authenticationRequest.IdentityId && x.OTP == authenticationRequest.OTP).FirstOrDefault();
            if (userAccount == null) return null;

            var tokenExpiryTimeStamp = DateTime.Now.AddMinutes(JWT_TOKEN_VALIDITY_MINS);
            var tokenKey = Encoding.ASCII.GetBytes(JWT_SECURITY_KEY);
            var claimsIdentity = new ClaimsIdentity(new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Name, authenticationRequest.IdentityId),
                new Claim("Role", userAccount.Role)
            });

            var signingCredentials = new SigningCredentials(
                new SymmetricSecurityKey(tokenKey),
                SecurityAlgorithms.HmacSha256Signature);

            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claimsIdentity,
                Expires = tokenExpiryTimeStamp,
                SigningCredentials = signingCredentials
            };

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var token = jwtSecurityTokenHandler.WriteToken(securityToken);
            ListOfUsers item = JsonFileReader.Read<ListOfUsers>(@"users.json");
            return new AuthenticationResponse
            {
                IdentityId = userAccount.IdentityId,
                ExpiresIn = (int)tokenExpiryTimeStamp.Subtract(DateTime.Now).TotalSeconds,
                Token = token
            };
        }
    }
}
