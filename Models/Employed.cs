using System;
using System.Collections.Generic;

namespace AuthServiceDavivienda.Models
{
    public partial class Employed
    {
        public string Identification { get; set; } = null!;
        public string FirstName { get; set; } = null!;
        public string LastName { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string EncryptedPass { get; set; } = null!;
        public string CurrentIp { get; set; } = null!;
        public DateTime CreatedAt { get; set; }
        public DateTime UpdateAt { get; set; }
        public int State { get; set; }
    }
}
