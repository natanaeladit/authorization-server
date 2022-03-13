using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Server.AspNetCore;
using server.Models;
using server.ViewModels;

namespace server.Controllers
{
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        public AuthenticationController(UserManager<User> userManager, 
            SignInManager<User> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [AllowAnonymous]
        [HttpPost("~/api/auth/register")]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new User
                {
                    UserName = model.Email,
                    Email = model.Email
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    return Ok();
                }
                else
                {
                    return BadRequest(new { general = result.Errors.Select(x => x.Description).ToArray() });
                }
            }
            else
            {
                return BadRequest(new
                {
                    general = ModelState.SelectMany(x => x.Value.Errors).Select(x => x.ErrorMessage).ToArray()
                });
            }
        }

        //[HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
        //public async Task<IActionResult> LogoutPost()
        //{
        //    await _signInManager.SignOutAsync();

        //    return SignOut(
        //        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        //        properties: new AuthenticationProperties
        //        {
        //            RedirectUri = "/"
        //        });
        //}
    }
}
