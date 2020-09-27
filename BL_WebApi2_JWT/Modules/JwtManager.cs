using System;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;

namespace BL_WebApi2_JWT
{
    //PM> Install-Package System.IdentityModel.Tokens.Jwt
    public static class JwtManager
    {
        public const string Secret = "856FECBA3B06519C8DDDBC80BB080553"; // your symetric

        public static string GenerateToken(ClaimsIdentity identity, int expireMinutes = 30)
        {
            var symmetricKey = Convert.FromBase64String(Secret);
            var tokenHandler = new JwtSecurityTokenHandler();
            var now = DateTime.UtcNow;

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,         //Use parsed JWT Token (HttpModule Create this JWT)
                Expires = now.AddMinutes(expireMinutes),
                SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var stoken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(stoken);

            return token;
        }

        //not used
        public static ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

                if (jwtToken == null)
                    return null;

                var symmetricKey = Convert.FromBase64String(Secret);

                var validationParameters = new TokenValidationParameters()
                {
                   RequireExpirationTime = true,
                   ValidateIssuer = false,
                   ValidateAudience = false,
                   IssuerSigningKey = new SymmetricSecurityKey(symmetricKey)
                };

                SecurityToken securityToken;
                var principal = tokenHandler.ValidateToken(token, validationParameters, out securityToken);

                return principal;
            }

            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }
    }
}