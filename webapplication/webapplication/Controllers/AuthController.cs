using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using webapplication.Models;

namespace webapplication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserContext _userContext;
        private readonly ITokenService _tokenService;

        public AuthController(UserContext loginModelContext, ITokenService tokenService)
        {
            _userContext = loginModelContext ?? throw new ArgumentNullException(nameof(_userContext));
            _tokenService = tokenService ?? throw new ArgumentNullException(nameof(_tokenService));
        }
        [HttpPost, Route("login")]
        public IActionResult Login([FromBody] LoginModel loginModel)
        {
            if (loginModel == null)
            {
                return BadRequest("Invalid client request");
            }

            var user = _userContext.LoginModels.FirstOrDefault(u => (u.UserName == loginModel.UserName) && (u.Password == loginModel.Password));

            if(user is null) return Unauthorized();

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, loginModel.UserName),
                new Claim(ClaimTypes.Role, "Operator")
            };

            var accessToken = _tokenService.GenerateAccessToken(claims);
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);

            _userContext.SaveChanges();

            return Ok(new{
                Token = accessToken,
                RefreshToken = refreshToken
            });
        }
    }
}