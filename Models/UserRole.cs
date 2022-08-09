using System;
using System.Collections.Generic;

namespace AuthServiceDavivienda.Models
{
    public partial class UserRole
    {
        public int Id { get; set; }
        public int RoleId { get; set; }
        public string UserIdentity { get; set; } = null!;
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }
}
