using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Gruda.Auth.Options
{
    public class AdminUserOptions
    {
        public string UserName { get; set; }
        public string UserEmail { get; set; }
        public string DefaultPassword { get; set; }
        public bool CreateAdminUser { get; set; }
    }
}
