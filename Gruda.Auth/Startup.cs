using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using Gruda.Auth.Data;
using Gruda.Auth.Exceptions;
using Gruda.Auth.Models;
using Gruda.Auth.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Gruda.Auth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<JWTOptions>(Configuration.GetSection("JWTSettings"));
            services.Configure<Options.ResponseCompressionOptions>(Configuration.GetSection("ResponseCompressionOptions"));

            services.Configure<KestrelServerOptions>(options =>
            {
                options.AddServerHeader = false;
            });

            services.AddDbContext<SecurityContext>(options =>
                       options.UseSqlite(Configuration.GetConnectionString("SecurityConnection")));

            services
                .AddIdentity<ApplicationUser, IdentityRole>(options =>
                {
                    options.Password.RequireDigit = true;
                    options.Password.RequiredLength = 8;
                    options.Password.RequireNonAlphanumeric = true;
                    options.Password.RequireUppercase = true;
                    options.Password.RequireLowercase = true;
                    options.Password.RequiredUniqueChars = 2;

                    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
                    options.Lockout.MaxFailedAccessAttempts = 10;
                })
                .AddEntityFrameworkStores<SecurityContext>()
                .AddDefaultTokenProviders();

            services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(options =>
                {
                    options.RequireHttpsMetadata = false;
                    options.TokenValidationParameters = GetTokenValidationParameters();

                });

            services.AddResponseCompression();

            services.AddSingleton(InitializeAutoMapper());

            services.AddMvc();
        }



        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env,
            IOptions<ResponseCompressionOptions> responseCompressionOptionsContainer,
            IOptions<AdminUserOptions> userOptionsContainer)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseAuthentication();

            var responseCompressionOptions = responseCompressionOptionsContainer.Value;
            if (responseCompressionOptions.UseResponseCompression)
            {
                app.UseResponseCompression();
            }

            app.UseMvc();

            var serviceProvider = app.ApplicationServices.GetService<IServiceProvider>();
            SetUpRolesAndAdminUser(serviceProvider, userOptionsContainer.Value).Wait();
        }

        private TokenValidationParameters GetTokenValidationParameters()
        {
            return new TokenValidationParameters
            {
                // The signing key must match!
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Configuration.GetSection("JWTSettings:SecretKey").Value)),
                // Validate the JWT Issuer (iss) claim
                ValidateIssuer = true,
                ValidIssuer = Configuration.GetSection("JWTSettings:Issuer").Value,
                // Validate the JWT Audience (aud) claim
                ValidateAudience = true,
                ValidAudience = Configuration.GetSection("JWTSettings:Audience").Value,

                RequireExpirationTime = true,

                // Validate the token expiry
                ValidateLifetime = true,

                // This defines the maximum allowable clock skew when validating 
                // the lifetime. As we're creating the tokens locally and validating
                // them on the same machines which should have synchronised time,
                // this can be set to zero.
                ClockSkew = TimeSpan.FromMinutes(0)
            };
        }


        private IMapper InitializeAutoMapper()
        {
            var config = new AutoMapper.MapperConfiguration(cfg =>
            {
                cfg.CreateMap<ApplicationUser, ApplicationUserViewModel>();
            });

            var mapper = config.CreateMapper();

            return mapper;
        }

        private async Task SetUpRolesAndAdminUser(IServiceProvider serviceProvider, AdminUserOptions adminUserOptions)
        {
            IServiceScopeFactory scopeFactory = serviceProvider.GetRequiredService<IServiceScopeFactory>();

            using (IServiceScope scope = scopeFactory.CreateScope())
            {
                RoleManager<IdentityRole> roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                UserManager<ApplicationUser> userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

                await addRequiredRoles(roleManager);

                if (adminUserOptions.CreateAdminUser)
                    await addAdminUser(userManager);

            }

            async Task addRequiredRoles(RoleManager<IdentityRole> roleManager)
            {
                string[] requiredRoles = { "Admin" };

                foreach (string roleName in requiredRoles)
                {
                    var roleExist = await roleManager.RoleExistsAsync(roleName);
                    if (!roleExist)
                    {
                        IdentityResult result = await roleManager.CreateAsync(new IdentityRole(roleName));

                        if (!result.Succeeded)
                        {
                            aggregateErrors(result);
                        }

                    }
                }
            }

            async Task addAdminUser(UserManager<ApplicationUser> userManager)
            {
                string userName = adminUserOptions.UserName;
                string userEmail = adminUserOptions.UserName;
                string defaultPassword = adminUserOptions.DefaultPassword;

                ApplicationUser adminUser = await userManager.FindByNameAsync(userName);

                if (adminUser == null)
                {
                    adminUser = new ApplicationUser
                    {
                        UserName = userName,
                        Email = userEmail,
                    };

                    IdentityResult result = await userManager.CreateAsync(adminUser, defaultPassword);

                    if (result.Succeeded)
                    {
                        await userManager.AddToRoleAsync(adminUser, "Admin");
                    }
                    else
                    {
                        aggregateErrors(result);
                    }
                }
            }

            void aggregateErrors(IdentityResult result)
            {
                throw new AggregateException(result.Errors.Select(err =>
                {
                    var setupException = new AppSetupException(err.Description);
                    setupException.Data.Add("Code", err.Code);

                    return setupException;
                }));
            }
        }

    }
}
