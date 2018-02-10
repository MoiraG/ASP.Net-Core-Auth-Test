using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Gruda.Auth.Options;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Gruda.Auth.Controllers
{
    [Route("api/[controller]")]
    public class ValuesController : Controller
    {
        private readonly JWTSettings settings;

        public ValuesController(IOptions<JWTSettings> settings)
        {
            this.settings = settings.Value;
        }

        // GET api/values
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/values/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return settings.Audience;
        }

        // POST api/values
        [HttpPost]
        public void Post([FromBody]string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
