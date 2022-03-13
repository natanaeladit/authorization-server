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
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity;
using server.Models;

namespace server.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IOptions<IdentityOptions> _identityOptions;
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;

        public AuthorizationController(IOpenIddictApplicationManager applicationManager,
            IOpenIddictScopeManager scopeManager,
            IOptions<IdentityOptions> identityOptions,
            SignInManager<User> signInManager,
            UserManager<User> userManager)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
            _identityOptions = identityOptions;
            _signInManager = signInManager;
            _userManager = userManager;
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
            else if (request?.IsPasswordGrantType() == true)
            {
                var user = await _userManager.FindByNameAsync(request.Username);
                if (user == null)
                {
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = OpenIddictConstants.Errors.InvalidGrant,
                        ErrorDescription = "The username/password combination is invalid."
                    });
                }

                if (!await _signInManager.CanSignInAsync(user))
                {
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = OpenIddictConstants.Errors.InvalidGrant,
                        ErrorDescription = "The specified user is not allowed to sign in."
                    });
                }

                if (_userManager.SupportsUserTwoFactor && await _userManager.GetTwoFactorEnabledAsync(user))
                {
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = OpenIddictConstants.Errors.InvalidGrant,
                        ErrorDescription = "The specified user is not allowed to sign in."
                    });
                }

                if (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user))
                {
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = OpenIddictConstants.Errors.InvalidGrant,
                        ErrorDescription = "The username/password combination is invalid."
                    });
                }

                if (!await _userManager.CheckPasswordAsync(user, request.Password))
                {
                    if (_userManager.SupportsUserLockout)
                    {
                        await _userManager.AccessFailedAsync(user);
                    }

                    return BadRequest(new OpenIddictResponse
                    {
                        Error = OpenIddictConstants.Errors.InvalidGrant,
                        ErrorDescription = "The username/password combination is invalid."
                    });
                }

                if (_userManager.SupportsUserLockout)
                {
                    await _userManager.ResetAccessFailedCountAsync(user);
                }

                var ticket = await CreateTicketAsync(request, user);
                var result = SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
                return result;
            }
            else if (request?.IsRefreshTokenGrantType() == true)
            {
                var info = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                var user = await _signInManager.ValidateSecurityStampAsync(info.Principal);
                if (user == null)
                {
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = OpenIddictConstants.Errors.InvalidGrant,
                        ErrorDescription = "The refresh token is no longer valid."
                    });
                }

                if (!await _signInManager.CanSignInAsync(user))
                {
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = OpenIddictConstants.Errors.InvalidGrant,
                        ErrorDescription = "The user is no longer allowed to sign in."
                    });
                }

                var ticket = await CreateTicketAsync(request, user, info.Properties);

                return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            }

            return BadRequest(new OpenIddictResponse
            {
                Error = OpenIddictConstants.Errors.UnsupportedGrantType,
                ErrorDescription = "The specified grant type is not supported."
            });
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

        private async Task<AuthenticationTicket> CreateTicketAsync(OpenIddictRequest request,
            User user,
            AuthenticationProperties properties = null)
        {
            var principal = await _signInManager.CreateUserPrincipalAsync(user);

            var ticket = new AuthenticationTicket(principal,
                properties,
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            if (!request.IsRefreshTokenGrantType())
            {
                ticket.Principal.SetScopes(new[]
                {
                    OpenIddictConstants.Scopes.OpenId,
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.OfflineAccess,
                    OpenIddictConstants.Scopes.Roles,
                }.Intersect(request.GetScopes()));
            }

            ticket.Principal.SetResources("http://localhost:5000");

            foreach (var claim in principal.Claims)
            {
                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                if (claim.Type == _identityOptions.Value.ClaimsIdentity.SecurityStampClaimType)
                {
                    continue;
                }

                var destinations = new List<string>
                {
                    OpenIddictConstants.Destinations.AccessToken,
                };

                if ((claim.Type == OpenIddictConstants.Claims.Name && ticket.Principal.HasScope(OpenIddictConstants.Scopes.Profile)) ||
                    (claim.Type == OpenIddictConstants.Claims.Email && ticket.Principal.HasScope(OpenIddictConstants.Scopes.Email)) ||
                    (claim.Type == OpenIddictConstants.Claims.Role && ticket.Principal.HasScope(OpenIddictConstants.Scopes.Roles)))
                {
                    destinations.Add(OpenIddictConstants.Destinations.IdentityToken);
                }

                claim.SetDestinations(destinations);
            }

            return ticket;
        }
    }
}
