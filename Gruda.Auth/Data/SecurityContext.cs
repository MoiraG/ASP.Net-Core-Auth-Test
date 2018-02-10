using Gruda.Auth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Gruda.Auth.Data
{
    public class SecurityContext : IdentityDbContext<ApplicationUser, IdentityRole, string>
    {
        public SecurityContext(DbContextOptions<SecurityContext> options) : base(options) { }

    }
}
