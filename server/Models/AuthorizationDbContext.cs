using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace server.Models
{
    public class AuthorizationDbContext : IdentityDbContext<User>
    {
        public AuthorizationDbContext(DbContextOptions options) : base(options) { }
    }
}
