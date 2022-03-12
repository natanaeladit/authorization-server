using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Collections.Immutable;
using System.Security.Claims;
using server.Extensions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;

namespace server.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;

        public AuthorizationController(IOpenIddictApplicationManager applicationManager, IOpenIddictScopeManager scopeManager)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
        }

        [HttpPost("~/connect/token"), Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest();
            if (request?.IsClientCredentialsGrantType() == true)
            {
                var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
                if (application == null)
                {
                    throw new InvalidOperationException("The application details cannot be found in the database.");
                }

                var identity = new ClaimsIdentity(
                    TokenValidationParameters.DefaultAuthenticationType,
                    Claims.Name, Claims.Role);

                identity.AddClaim(Claims.Subject, await _applicationManager.GetClientIdAsync(application),
                    Destinations.AccessToken, Destinations.IdentityToken);

                identity.AddClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application),
                    Destinations.AccessToken, Destinations.IdentityToken);

                var principal = new ClaimsPrincipal(identity);
                principal.SetScopes(request.GetScopes());
                principal.SetResources(await _scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

                foreach (var claim in principal.Claims)
                {
                    claim.SetDestinations(GetDestinations(claim));
                }

                return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            throw new NotImplementedException("The specified grant type is not implemented.");
        }

        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo")]
        public async Task<IActionResult> Userinfo()
        {
            var claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

            return Ok(new
            {
                Name = claimsPrincipal.GetClaim(Claims.Name),
            });
        }

        private IEnumerable<string> GetDestinations(Claim claim)
        {
            return claim.Type switch
            {
                Claims.Name or
                Claims.Subject
                    => ImmutableArray.Create(Destinations.AccessToken, Destinations.IdentityToken),

                _ => ImmutableArray.Create(Destinations.AccessToken),
            };
        }
    }
}
