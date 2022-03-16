using System;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Route("api/[controller]")]
[ApiController]
public class TokenController : ControllerBase
{
    private readonly UserContext userContext;
    private readonly ITokenService tokenService;

    public TokenController(UserContext userContext, ITokenService tokenService)
    {
        this.userContext = userContext ?? throw new ArgumentNullException(nameof(userContext));
        this.tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
    }

    [HttpPost]
    [Route("refresh")]
    public IActionResult Refresh(TokenApiModel tokenApiModel)
    {
        if (tokenApiModel is null)
        {
            return BadRequest("Invalid client request");
        }

        string accessToken = tokenApiModel.AccessToken;
        string refreshToken = tokenApiModel.RefreshToken;

        var principal = tokenService.GetPrincipalFromExpiredToken(accessToken);
        var userName = principal.Identity.Name;

        var user = userContext.LoginModels.SingleOrDefault(u => u.UserName == userName);

        if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
        {
            return BadRequest("Invalid client request");
        }

        var newAccessToken = tokenService.GenerateAccessToken(principal.Claims);
        var newRefreshToken = tokenService.GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        userContext.SaveChanges();
        
        return new ObjectResult(new {
            accessToken = newAccessToken,
            refreshToken = newRefreshToken
        });
    }

    [HttpPost, Authorize]
    [Route("revoke")]
    public IActionResult Revoke(){
        var userName = User.Identity.Name;

        var user = userContext.LoginModels.SingleOrDefault(u => u.UserName == userName);

        if(user is null) return BadRequest();

        user.RefreshToken = null;
        userContext.SaveChanges();

        return NoContent();
    }
}