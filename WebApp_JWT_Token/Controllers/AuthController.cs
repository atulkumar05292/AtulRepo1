using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace WebApp_JWT_Token.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        [HttpPost("token")]
        public IActionResult Token()  
        {
            var header = Request.Headers["Authorization"];

            if (header.ToString().StartsWith("Basic"))
            {
                var credValue = header.ToString().Substring("Basic ".Length).Trim();
                var userNameAndPassword = Encoding.UTF8.GetString(Convert.FromBase64String(credValue));
                var userNameAndPass = userNameAndPassword.Split(":");

                // Check in DB whether UserName and Password Exist.
                if (userNameAndPass[0] == "Admin" && userNameAndPass[1] == "1234")
                {
                    var claimsData = new[] { new Claim(ClaimTypes.Name, userNameAndPass[0]) };
                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("abcde1xryxerxrtxctuucucujiojo234"));
                    var SignInCred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

                    var token = new JwtSecurityToken(
                        issuer: "mysite.com",
                        audience: "mysite.com",
                        expires: DateTime.Now.AddMinutes(1),
                        claims: claimsData,
                        signingCredentials: SignInCred
                        );

                    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                    return Ok(tokenString);
                }
            }

            return BadRequest("Wrong request");
        }
    }
}