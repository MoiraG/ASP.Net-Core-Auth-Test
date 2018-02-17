using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using Gruda.Auth.Models;
using Gruda.Auth.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Gruda.Auth.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly JWTOptions _jwtOptions;
        private readonly IMapper _modelMapper;

        public AccountController(UserManager<ApplicationUser> userManager,
                                    RoleManager<IdentityRole> roleManager,
                                    SignInManager<ApplicationUser> signInManager,
                                    IOptionsSnapshot<JWTOptions> jwtSettings,
                                    IMapper modelMapper)
        {
            this._userManager = userManager;
            this._roleManager = roleManager;
            this._signInManager = signInManager;
            this._modelMapper = modelMapper;
            this._jwtOptions = jwtSettings.Value ?? throw new ArgumentNullException("JWT Settings must be filled!");
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Credentials credentials)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(credentials.UserName, credentials.Password, isPersistent: false, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(credentials.UserName);

                    return Ok(new
                    {
                        access_token = await CreateAccessToken(user),
                        expires_in = (int)_jwtOptions.ExpiresInAsTimeStamp.TotalSeconds
                    });

                }
            }

            return BadRequest("Could not verify username and password");
        }
     
        [HttpPost("add-user")]
        public async Task<IActionResult> AddUser([FromBody] Credentials credentials)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = credentials.UserName, Email = credentials.Email, CreatedOn = DateTime.Now };
                var result = await _userManager.CreateAsync(user, credentials.Password);

                if (result.Succeeded)
                {
                    return CreatedAtAction(nameof(GetUserById), new { id = user.Id }, _modelMapper.Map<ApplicationUserViewModel>(user));
                }

            }

            return BadRequest("Could not add User");
        }

        [HttpGet("get-user/{id}", Name = "GetUserById")]
        public async Task<IActionResult> GetUserById(string id)
        {
            var user = await _userManager.FindByIdAsync(id);

            if (user != null)
            {
                return Ok(_modelMapper.Map<ApplicationUserViewModel>(user));
            }

            return NotFound("Could not find User");
        }

        [HttpDelete("delete-user/{id}")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);

            if (user != null)
            {
                var result = await _userManager.DeleteAsync(user);
                return NoContent();
            }

            return BadRequest("Could not delete User");
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return NoContent();
        }

        private async Task<string> CreateAccessToken(ApplicationUser user)
        {
            var now = DateTime.UtcNow;

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var userClaims = await _userManager.GetClaimsAsync(user);
            var userRoles = await _userManager.GetRolesAsync(user);

            foreach (var roleName in userRoles)
            {
                userClaims.Add(new Claim(ClaimTypes.Role, roleName));
                if (_roleManager.SupportsRoleClaims)
                {
                    var role = await _roleManager.FindByNameAsync(roleName);
                    if (role != null)
                    {
                        userClaims.Union(await _roleManager.GetClaimsAsync(role));
                    }
                }
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                claims: claims.Union(userClaims),
                notBefore: now,
                expires: now.Add(_jwtOptions.ExpiresInAsTimeStamp),
                signingCredentials: creds
                ));

        }
    }
}