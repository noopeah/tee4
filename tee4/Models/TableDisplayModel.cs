using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace tee4.Models
{
    public class TableDisplayModel
    {
        public TableDisplayModel(List<ApplicationUser> users)
        {
            this.Users = users;
        }
        public List<ApplicationUser> Users { get; set; }
    }
}