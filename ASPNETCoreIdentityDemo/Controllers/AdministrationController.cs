using Microsoft.AspNetCore.Identity;

namespace ASPNETCoreIdentityDemo.Controllers
{
    public class AdministrationController
    {
        // DI RoleManager
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdministrationController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }
    }
}
