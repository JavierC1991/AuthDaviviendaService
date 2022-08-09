using System;
using System.Collections.Generic;

namespace AuthServiceDavivienda.Models
{
    public partial class Role
    {
        public int Id { get; set; }
        public string ShortName { get; set; } = null!;
        public string Description { get; set; } = null!;
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}
