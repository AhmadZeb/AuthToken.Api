using AuthToken.Api.Models.Employees;
using AuthToken.Api.Models.RegisterUser;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JwtJsonwebtoken.Contextes
{
    //2
    public class AuthDemoDbContext : IdentityDbContext<ApplicationUser>
    {
        public AuthDemoDbContext(DbContextOptions<AuthDemoDbContext> options) : base(options)
        {

        }
        public DbSet<Employee> Employees { get; set; }
    }
}
