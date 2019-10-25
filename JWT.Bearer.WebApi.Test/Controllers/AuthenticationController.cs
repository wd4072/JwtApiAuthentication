using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JWT.Bearer.WebApi.Test.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private  IConfiguration _configuration { get; }
        public AuthenticationController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public IActionResult Post()
        {
            var authenticationHeader = Request.Headers["Authorization"].First();
            var key = authenticationHeader.Split(' ')[1];
            var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(key)).Split(':');
            var serverSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:ServerSecret"]));
            if (credentials[0] == "username" && credentials[1] == "password")
            {
                var result = new {token = GenerateToken(serverSecret)};
                return Ok(result);
            }

            return BadRequest();
        }

        private string GenerateToken(SymmetricSecurityKey key)
        {
            var now = DateTime.UtcNow;
            var issuer = _configuration["JWT:Issuer"];
            var audience = _configuration["JWT:Audience"];
            var identity = new ClaimsIdentity();
            var signingCredentials=new SigningCredentials(key,SecurityAlgorithms.HmacSha256);
            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateJwtSecurityToken(issuer, audience, identity, now,
                now.Add((TimeSpan.FromHours(1))), now, signingCredentials);
            var encodeJwt = handler.WriteToken(token);
            return encodeJwt;
        }
    }
}