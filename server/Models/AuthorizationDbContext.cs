using Microsoft.EntityFrameworkCore;

namespace server.Models
{
    public class AuthorizationDbContext : DbContext
    {
        public AuthorizationDbContext(DbContextOptions options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder) { }
    }
}
