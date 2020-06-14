using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(tee4.Startup))]
namespace tee4
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
