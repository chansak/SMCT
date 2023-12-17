using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JwtAuthenticationManager
{
    public static class CustomJwtAuthExtension
    {
        public static void AddCustomJwtAuthentication(this IServiceCollection services)
        {
            
            services.AddAuthentication(options =>
            {
                //Combining cookie and JWT bearer authentication for supporting both cookie-based authentication and token based authentication (modern)
                //options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;

                //OpenIdConnection
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
                .AddCookie(options =>
                {
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                    options.LoginPath = "/Account/Login";
                })
                .AddOpenIdConnect(options =>
                {
                    options.ClientId = "client_id";
                    options.ClientSecret = "client_secret";
                    options.Authority = String.Format("https://{0}.onelogin.com/oidc", "us");

                    options.ResponseType = "code";
                    options.GetClaimsFromUserInfoEndpoint = true;
                });
                //.AddJwtBearer(options =>
                //{
                //    options.RequireHttpsMetadata = false;
                //    options.SaveToken = true;
                //    options.TokenValidationParameters = new TokenValidationParameters
                //    {
                //        ValidateIssuerSigningKey = true,
                //        ValidateIssuer = true,
                //        ValidateAudience = true,
                //        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(JwtTokenHandler.JWT_SECURITY_KEY)),
                //        ValidateLifetime = true,
                //        ClockSkew = TimeSpan.Zero
                //    };
                //});
        }
    }
}
