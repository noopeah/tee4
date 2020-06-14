using tee4.Models;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;
using System;
using System.Threading.Tasks;
using System.Web.UI;
using System.Web.Security;
using System.Data.Entity;
using Microsoft.AspNet.Identity;
using System.Web;
using Microsoft.AspNet.Identity.Owin;

namespace tee4.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private ApplicationDbContext UsersContext;
        public HomeController()
        {
            UsersContext = new ApplicationDbContext();
        }
        public ActionResult Users()
        {
            if (UsersContext.Users.Where(u => u.UserName == HttpContext.User.Identity.Name).Any()
                && UsersContext.Users.Where(u => u.UserName == HttpContext.User.Identity.Name).FirstOrDefault().LockoutEndDateUtc == null)
                return View(new TableDisplayModel(UsersContext.Users.ToList()));
            else return RedirectToAction("Login", "Account");
        }

        [HttpPost]
        public async Task<ActionResult> Delete(IEnumerable<string> usersToBan)
        {
            UsersContext.Users.Where(u => usersToBan.Contains(u.Id))
                .ToList()
                .ForEach(x =>
                {
                    UsersContext.Users.Remove(x);
                });
            foreach (var id in usersToBan) await HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>().UpdateSecurityStampAsync(id);
            UsersContext.SaveChanges();
            return RedirectToAction("Users", "Home");
        }   

        [HttpPost]
        public async Task<ActionResult>Ban(IEnumerable<string> usersToBan)
        {
            UsersContext.Users.Where(u => usersToBan.Contains(u.Id))
                .ToList()
                .ForEach(x => {
                    x.LockoutEndDateUtc = DateTime.Now;
                });
            foreach (var id in usersToBan) await HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>().UpdateSecurityStampAsync(id);
            UsersContext.SaveChanges();
            return RedirectToAction("Users", "Home");
        }

        [HttpPost]
        public ActionResult Forgive(IEnumerable<string> usersToBan)
        {
            UsersContext.Users.Where(u => usersToBan.Contains(u.Id))
                .ToList()
                .ForEach(x =>
                {
                    x.LockoutEndDateUtc = null;
                });
            UsersContext.SaveChanges();
            return RedirectToAction("Users", "Home");
        }
    }
}




/*
 
if (Page.User.Identity.IsAuthenticated)         
{             
    MembershipUser user = Membership.GetUser(Page.User.Identity.Name);             
    if (!user.IsApproved)             
    {                 
        HttpContext.Current.Session.Abandon();                 
        FormsAuthentication.SignOut();                 
        Response.Redirect("Default.aspx");             
    }
}
 
 
 */
