using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Gruda.Auth.Models
{
    public class ApplicationUserViewModel
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public DateTime? CreatedOn { get; set; }
        public DateTime? ModifiedOn { get; set; }
    }
}
