using ASPNETCoreIdentityDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace ASPNETCoreIdentityDemo.Controllers
{
    [Authorize(Roles = "Admin, Moderator")]
    public class AdministrationController : Controller
    {
        // DI RoleManager
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public AdministrationController(RoleManager<ApplicationRole> roleManager, UserManager<ApplicationUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
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
                    ApplicationRole role = new ApplicationRole
                    {
                        Name = model.RoleName,
                        Description = model.Description
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
            List<ApplicationRole> roles = await _roleManager.Roles.ToListAsync();
            return View(roles);
        }
        #endregion

        #region Role Edit
        [HttpGet]
        public async Task<IActionResult> EditRole(string roleId)
        {
            ApplicationRole role = await _roleManager.FindByIdAsync(roleId);

            if (role == null)
            {
                return View("Error");
            }

            var model = new EditRoleViewModel
            {
                Id = role.Id,
                RoleName = role.Name,
                Description= role.Description,
                Users = new List<string>()
            };

            // added users in this role for display in view
            foreach(var user in _userManager.Users.ToList())
            {
                // if in this role user
                if(await _userManager.IsInRoleAsync(user, role.Name))
                {
                    model.Users.Add(user.UserName);
                }
            }

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> EditRole(EditRoleViewModel model)
        {
            if (ModelState.IsValid)
            {
                ApplicationRole role = await _roleManager.FindByIdAsync(model.Id);

                if (role == null)
                {
                    ModelState.AddModelError("", $"Role with Id = {model.Id} is not found");
                }
                else
                {
                    role.Name = model.RoleName;
                    role.Description = model.Description;
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
            else
            {
                try
                {
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
                catch(DbUpdateException ex)
                {
                    // Log the exception to a file. 
                    ViewBag.Error = ex.Message;
                    // Pass the ErrorTitle and ErrorMessage that you want to show to the user using ViewBag.
                    // The Error view retrieves this data from the ViewBag and displays to the user.
                    ViewBag.ErrorTitle = $"{role.Name} Role is in Use";
                    ViewBag.ErrorMessage = $"{role.Name} Role cannot be deleted as there are users in this role. If you want to delete this role, please remove the users from the role and then try to delete";
                    return View("Error");
                    throw; 
                }
            }
        }
        #endregion

        #region Edit Users In Role
        [HttpGet]
        public async Task<IActionResult> EditUsersInRole(string roleId)
        {
            ViewBag.RoleId = roleId;

            var role = await _roleManager.FindByIdAsync(roleId);

            if (role == null)
            {
                ViewBag.ErrorMessage = $"Role with Id = {roleId} cannot be found";
                return View("NotFound");
            }

            ViewBag.RollName = role.Name;
            var model = new List<UserRoleViewModel>();

            foreach (var user in _userManager.Users.ToList())
            {
                var userRoleViewModel = new UserRoleViewModel()
                {
                    UserId = user.Id,
                    UserName = user.UserName
                };

                if (await _userManager.IsInRoleAsync(user, role.Name))
                {
                    userRoleViewModel.IsSelected = true;
                }
                else
                {
                    userRoleViewModel.IsSelected = false;
                }

                model.Add(userRoleViewModel);
            }

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> EditUsersInRole(List<UserRoleViewModel> model, string roleId)
        {
            // check role exists
            var role = await _roleManager.FindByIdAsync(roleId);

            if (role == null)
            {
                ViewBag.ErrorMessage = $"Role with Id = {roleId} cannot be found";
                return View("NotFound");
            }

            for (int i = 0; i < model.Count; i++)
            {
                var user = await _userManager.FindByIdAsync(model[i].UserId);

                IdentityResult? result;

                if (model[i].IsSelected && !(await _userManager.IsInRoleAsync(user, role.Name)))
                {
                    // if user is selected and User is not already in this role
                    result = await _userManager.AddToRoleAsync(user, role.Name);
                }
                else if (!model[i].IsSelected && await _userManager.IsInRoleAsync(user, role.Name))
                {
                    result = await _userManager.RemoveFromRoleAsync(user, role.Name);   
                }
                else
                {
                    continue;
                }

                if(result.Succeeded)
                {
                    if (i < model.Count - 1)
                    {
                        continue;
                    }
                    else
                    {
                        return RedirectToAction("EditRole", new {roleId = roleId});
                    }
                }
            }

            return RedirectToAction("EditRole", new { roleId = roleId });
        }
        #endregion

        #region List Users
        [HttpGet]
        public IActionResult ListUsers()
        {
            var users = _userManager.Users.ToList();
            return View(users);
        }
        #endregion

        #region Edit User
        [HttpGet]
        public async Task<IActionResult> EditUser(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if(user == null)
            {
                ViewBag.ErrorMessage = $"User with ID = {userId} cannot be found";
                return View("NotFound");
            }

            var claims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            var model = new EditUserViewModel
            {
                Id = userId,
                UserName = user.UserName,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Claims = claims.Select(c => c.Value).ToList(),
                Roles = roles
            };
             
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> EditUser(EditUserViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.Id);

            if(user == null)
            {
                ViewBag.ErrorMessage = $"User with ID = {model.Id} cannot be found";
                return View("NotFound");
            }

            // update properties in database for user
            user.Email= model.Email;
            user.UserName = model.UserName;
            user.FirstName = model.FirstName;
            user.LastName = model.LastName;

            var result = await _userManager.UpdateAsync(user);

            if(result.Succeeded)
            {
                return RedirectToAction("ListUsers");
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }
            return View(model);
        }
        #endregion

        #region Delete User
        [HttpPost]
        public async Task<IActionResult> DeleteUser(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                ViewBag.ErrorMessage = $"User with Id = {userId} cannot be found";
                return View("NotFound");
            }
            else
            {
                var result = await _userManager.DeleteAsync(user);

                if (result.Succeeded)
                {
                    return RedirectToAction("ListUsers");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }

                return View("ListUsers");
            }
        }
        #endregion

        #region Manage User Role
        [HttpGet]
        public async Task<IActionResult> ManageUserRoles(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                ViewBag.ErrorMessage = $"User with Id = {userId} cannot be found";
                return View("NotFound");
            }

            // sending UserId and UserName using ViewBag
            ViewBag.UserId = user.Id;
            ViewBag.UserName = user.UserName;

            var model = new List<UserRolesViewModel>();


            foreach(var role in _roleManager.Roles.ToList())
            {
                var userRolesViewModel = new UserRolesViewModel
                {
                    RoleId = role.Id,
                    RoleName = role.Name,
                    Description = role.Description
                };

                if(await _userManager.IsInRoleAsync(user, role.Name))
                {
                    userRolesViewModel.IsSelected = true;
                }
                else
                {
                    userRolesViewModel.IsSelected = false;
                }

                model.Add(userRolesViewModel);
            }

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> ManageUserRoles(List<UserRolesViewModel> model, string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if(user == null)
            {
                ViewBag.ErrorMessage = $"User with Id = {userId} cannot be found";
                return View("NotFound");
            }

            // get all roles
            var roles = await _userManager.GetRolesAsync(user);

            // removing all roles from this user
            var result = await _userManager.RemoveFromRolesAsync(user, roles);

            if(!result.Succeeded)
            {
                ModelState.AddModelError("", "Cannot remove user existing roles");
                return View(model);
            }

            List<string> RolesToBeAssigned = model.Where(r => r.IsSelected).Select(role => role.RoleName).ToList();
            
            if(RolesToBeAssigned.Any())
            {
                // any checkbox selected in view
                result = await _userManager.AddToRolesAsync(user, RolesToBeAssigned);

                if(!result.Succeeded)
                {
                    ModelState.AddModelError("", "Cannot Add Selected Roles to User");
                    return View(model);
                }
            }

            // return EditUser action with "userId" argument
            return RedirectToAction("EditUser", new { userId = userId });
        }
        #endregion

        #region Manage User Claims
        [HttpGet]
        public async Task<IActionResult> ManageUserClaims(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if(user == null)
            {
                ViewBag.ErrorMessage = $"User with Id = {userId} cannot be found";
                return View("NotFound");
            }

            // sending UserName to view
            ViewBag.UserName = user.UserName;

            var model = new UserClaimsViewModel
            {
                UserId = userId
            };

            // get all claims of this user from database
            var existingUserClaims = await _userManager.GetClaimsAsync(user);

            foreach (var claim in ClaimsStore.GetAllClaims())
            {
                // create UserClaim to add sending model List<UserClaim>
                UserClaim userClaim = new UserClaim
                {
                    ClaimType = claim.Type
                };

                if (existingUserClaims.Any(c => c.Type == claim.Type))
                {
                    userClaim.IsSelected = true;
                }

                // adding prepared userClaim added to model claims
                model.Claims.Add(userClaim);
            }

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> ManageUserClaims(UserClaimsViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            if (user == null)
            {
                ViewBag.ErrorMessage = $"User with Id = {model.UserId} cannot be found";
                return View("NotFound");
            }

            var claims = await _userManager.GetClaimsAsync(user);
            var result = await _userManager.RemoveClaimsAsync(user, claims);

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Cannot remove user existing claims");
                return View(model);
            }

            var allSelectedClaims = model.Claims.Where(c => c.IsSelected)
                .Select(c => new Claim(c.ClaimType, c.ClaimType)).ToList();

            if (allSelectedClaims.Any())
            {
                // adding claims this user
                result = await _userManager.AddClaimsAsync(user, allSelectedClaims);

                if(!result.Succeeded)
                {
                    ModelState.AddModelError("", "Cannot add selected claims to user");
                    return View(model);
                }
            }

            return RedirectToAction("EditUser", new { userId = model.UserId });
        }
        #endregion
    }
}
