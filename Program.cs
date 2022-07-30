using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace CSharpTokenGenerationDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            var tokenString = GenerateJSONWebToken("MyNameIsNikolaosBellias1967");
            using (var httpClient = new HttpClient())
            {
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenString);
                Console.WriteLine("Token = " + httpClient.DefaultRequestHeaders.Authorization);
            }
            // Console.WriteLine("Token = " + GenerateJSONWebToken("MyNameIsNikolaosBellias"));
        }

        private static string GenerateJSONWebToken(string key)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "http://localhost",
                audience: "http://localhost",
                expires: DateTime.Now.AddHours(3),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
