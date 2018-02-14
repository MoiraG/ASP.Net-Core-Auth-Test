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
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly JWTSettings _jwtSettings;
        private readonly IMapper _modelMapper;

        public AccountController(UserManager<ApplicationUser> userManager,
                                    SignInManager<ApplicationUser> signInManager,
                                    IOptionsSnapshot<JWTSettings> jwtSettings,
                                    IMapper modelMapper)
        {
            this._userManager = userManager;
            this._signInManager = signInManager;
            this._modelMapper = modelMapper;
            this._jwtSettings = jwtSettings.Value ?? throw new ArgumentNullException("JWT Settings must be filled!");
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
                        expires_in = (int)_jwtSettings.ExpiresInAsTimeStamp.TotalSeconds
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

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: userClaims.Union(claims),
                notBefore: now,
                expires: now.Add(_jwtSettings.ExpiresInAsTimeStamp),
                signingCredentials: creds
                ));

        }
    }
}