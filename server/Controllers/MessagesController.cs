using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;

namespace server.Controllers
{
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    [ApiController]
    public class MessagesController : ControllerBase
    {
        public JsonResult Get()
        {
            return new JsonResult(new List<string>() { "Welcome", "Thank you" });
        }
    }
}
