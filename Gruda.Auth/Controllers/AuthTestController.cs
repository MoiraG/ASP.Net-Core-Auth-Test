using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Gruda.Auth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Gruda.Auth.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/AuthTest")]
    public class AuthTestController : Controller
    {
        // GET: api/AuthTest
        [HttpGet]
        public IActionResult Get()
        {
            var name = User.Identity.Name;
            var id = User.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;

            return Ok(new
            {
                UserName = name,
                Id = id
            });
        }

        // GET: api/AuthTest/5
        [HttpGet("{id}", Name = "Get")]
        public string Get(int id)
        {
            return "value";
        }
        
        // POST: api/AuthTest
        [HttpPost]
        public void Post([FromBody]string value)
        {
        }
        
        // PUT: api/AuthTest/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody]string value)
        {
        }
        
        // DELETE: api/ApiWithActions/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
