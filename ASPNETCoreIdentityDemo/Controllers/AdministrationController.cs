using ASPNETCoreIdentityDemo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

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
            if (ModelState.IsValid)
            {
                bool roleExists = await _roleManager.RoleExistsAsync(model.RoleName);

                if (roleExists)
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

                    if (result.Succeeded)
                    {
                        return RedirectToAction("Index", "Home");
                    }

                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }

            return View(model);
        }

        #endregion

        #region Roles list
        [HttpGet]
        public async Task<IActionResult> ListRoles()
        {
            List<IdentityRole> roles = await _roleManager.Roles.ToListAsync();
            return View(roles);
        }
        #endregion

        #region Role Edit
        [HttpGet]
        public async Task<IActionResult> EditRole(string roleId)
        {
            IdentityRole role = await _roleManager.FindByIdAsync(roleId);

            if (role == null)
            {
                return View("Error");
            }

            var model = new EditRoleViewModel
            {
                Id = role.Id,
                RoleName = role.Name
            };

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> EditRole(EditRoleViewModel model)
        {
            if (ModelState.IsValid)
            {
                var role = await _roleManager.FindByIdAsync(model.Id);

                if (role == null)
                {
                    ModelState.AddModelError("", $"Role with Id = {model.Id} is not found");
                }
                else
                {
                    role.Name = model.RoleName;
                    // if needed, other fields updated here

                    var result = await _roleManager.UpdateAsync(role);
                    if (result.Succeeded)
                    {
                        return RedirectToAction("ListRoles");
                    }

                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }

            return View(model);
        }
        #endregion

        #region Role Delete
        [HttpPost]
        public async Task<IActionResult> DeleteRole(string roleId)
        {
            var role = await _roleManager.FindByIdAsync(roleId);

            if (role == null)
            {
                ModelState.AddModelError("", $"Role with ID = {roleId} is not found");
                return View("Error");
            }
            var result = await _roleManager.DeleteAsync(role);

            if (result.Succeeded)
            {
                return RedirectToAction("ListRoles");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return RedirectToAction("ListRoles", await _roleManager.Roles.ToListAsync());
        }
        #endregion
    }
}
