using System;
using System.Collections.Generic;

namespace AuthServiceDavivienda.Models
{
    public partial class UserToken
    {
        public int Id { get; set; }
        public string? UserIdentity { get; set; }
        public string? HashToken { get; set; }
        public DateTime? LastToken { get; set; }
        public DateTime? CurrentToken { get; set; }
    }
}
