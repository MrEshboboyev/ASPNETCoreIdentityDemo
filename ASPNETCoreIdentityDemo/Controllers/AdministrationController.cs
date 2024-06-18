using ASPNETCoreIdentityDemo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ASPNETCoreIdentityDemo.Controllers
{
    public class AdministrationController : Controller
    {
        // DI RoleManager
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdministrationController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }

        #region Role Create
        [HttpGet]
        public IActionResult CreateRole()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole(CreateRoleViewModel model)
        {
            if(ModelState.IsValid)
            {
                bool roleExists = await _roleManager.RoleExistsAsync(model.RoleName);   

                if(roleExists)
                {
                    ModelState.AddModelError("", $"Role {model.RoleName} already exists");
                }
                else
                {
                    var role = new IdentityRole
                    {
                        Name = model.RoleName
                    };

                    var result = await _roleManager.CreateAsync(role);

                    if(result.Succeeded)
                    {
                        return RedirectToAction("Index", "Home");
                    }

                    foreach(var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }

            return View(model);
        }

        #endregion
    }
}
