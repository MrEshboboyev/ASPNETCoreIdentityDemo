using ASPNETCoreIdentityDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace ASPNETCoreIdentityDemo.Controllers
{
    public class AccountController : Controller
    {
        //DI identity classes
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;

        // emailSender instance
        private readonly ISenderEmail _emailSender;

        // SMSSender instance
        private readonly ISMSSender _smsSender;

        public AccountController(SignInManager<ApplicationUser> signInManager,
            RoleManager<ApplicationRole> roleManager,
            UserManager<ApplicationUser> userManager,
            ISenderEmail emailSender,
            ISMSSender smsSender)
        {
            _signInManager = signInManager;
            _roleManager = roleManager;
            _userManager = userManager;
            _emailSender = emailSender;
            _smsSender = smsSender;
        }

        #region Register
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    UserName = model.Email,
                    Email = model.Email,
                    PhoneNumber = model.PhoneNumber
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                // logged this user
                if (result.Succeeded)
                {
                    // sending confirmation link to this user email
                    await SendConfirmationEmail(model.Email, user);

                    // redirect to ListRoles user as "Admin"
                    if (_signInManager.IsSignedIn(User) && User.IsInRole("Admin"))
                    {
                        return RedirectToAction("ListUsers", "Administration");
                    }

                    // if this user is not admin, redirect user to "RegistrationSuccessful"
                    return View("RegistrationSuccessful");
                }

                // any errors displayed
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return View(model);
        }
        #endregion

        #region Login
        [HttpGet]
        public async Task<IActionResult> Login(string? ReturnUrl = null)
        {
            LoginViewModel model = new LoginViewModel()
            {
                ReturnUrl = ReturnUrl,
                ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
            };
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model, string? ReturnUrl)
        {
            model.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (ModelState.IsValid)
            {
                // find this user
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null && !user.EmailConfirmed && (await _userManager.CheckPasswordAsync(user, model.Password)))
                {
                    ModelState.AddModelError(string.Empty, "Email not confirmed yet");
                    return View(model);
                }

                // The last boolean parameter lockoutOnFailure indicates if the account should be locked on failed login attempt. 
                // On every failed login attempt AccessFailedCount column value in AspNetUsers table is incremented by 1. 
                // When the AccessFailedCount reaches the configured MaxFailedAccessAttempts which in our case is 5,
                // the account will be locked and LockoutEnd column is populated.
                // After the account is lockedout, even if we provide the correct username and password,
                // PasswordSignInAsync() method returns Lockedout result and
                // the login will not be allowed for the duration the account is locked.

                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password,
                    model.RememberMe, lockoutOnFailure: true);

                if (result.Succeeded)
                {
                    if(user?.LastPasswordChangedDate.AddDays(90) < DateTime.Now)
                    {
                        // Password has expired
                        // Redirect user to change password view
                        return View("PasswordExpired");
                    }

                    if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
                    {
                        return Redirect(ReturnUrl);
                    }
                    else
                    {
                        return RedirectToAction(nameof(HomeController.Index), "Home");
                    }
                }
                if (result.RequiresTwoFactor)
                {
                    // Handle two-factor authentication case
                    // Generate 2FA token, send that mobile number and email
                    // and redirect 2FA verification View

                    var TwoFactorAuthenticationToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                    // sending SMS
                    await _smsSender.SendSmsAsync(user.PhoneNumber, 
                        $"Your 2FA token is {TwoFactorAuthenticationToken}");

                    // sending email
                    await _emailSender.SendEmailAsync(user.Email, "2FA Token", 
                        $"Your 2FA token is {TwoFactorAuthenticationToken}", false);

                    return RedirectToAction("VerifyTwoFactorToken", "Account",
                        new { model.Email, ReturnUrl, model.RememberMe, TwoFactorAuthenticationToken });
                }
                else if (result.IsLockedOut)
                {
                    //It's important to inform users when their account is locked.
                    //This can be done through the UI or by sending an email notification.
                    await SendAccountLockedEmail(model.Email);
                    return View("AccountLocked");
                }
                else
                {
                    // Handle Failure 
                    // Get the number of failed attempts
                    var attemptsLeft = _userManager.Options.Lockout.MaxFailedAccessAttempts -
                        await _userManager.GetAccessFailedCountAsync(user);

                    ModelState.AddModelError(string.Empty, $"Invalid login attempt. Remaining Attempts : {attemptsLeft}");
                    return View(model);
                }
            }

            return View(model);
        }
        #endregion

        #region Logout
        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        #endregion

        #region Email
        [AllowAnonymous]
        [HttpPost]
        [HttpGet]
        public async Task<IActionResult> IsEmailAvailable(string Email)
        {
            // Check if the email id is already use in Database
            var user = await _userManager.FindByEmailAsync(Email);

            if (user == null)
            {
                return Json(true);
            }
            else
            {
                return Json($"Email {Email} is already in use");
            }
        }
        #endregion

        #region Access Denied
        [HttpGet]
        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }
        #endregion

        #region External Login
        [AllowAnonymous]
        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl)
        {
            //This call will generate a URL that directs to the ExternalLoginCallback action method in the Account controller
            //with a route parameter of ReturnUrl set to the value of returnUrl.
            var redirectUrl = Url.Action(action: "ExternalLoginCallback", controller: "Account",
                values: new { ReturnUrl = returnUrl });

            // Configure the redirect URL, provider and other properties
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            //This will redirect the user to the external provider's login page
            return new ChallengeResult(provider, properties);
        }

        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string? returnUrl, string? remoteError)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            LoginViewModel loginViewModel = new LoginViewModel
            {
                ReturnUrl = returnUrl,
                ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
            };

            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");

                return View("Login", loginViewModel);
            }

            // Get the login information about the user from the external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                ModelState.AddModelError(string.Empty, "Error loading external login information.");

                return View("Login", loginViewModel);
            }

            // Email Confirmation Section
            // Get the email claim from external login provider (Google, Facebook etc)
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            ApplicationUser? user;

            if (email != null)
            {
                // Find the user
                user = await _userManager.FindByEmailAsync(email);

                // If the user exists in our database and email is not confirmed,
                // display login view with validation error
                if (user != null && !user.EmailConfirmed)
                {
                    ModelState.AddModelError(string.Empty, "Email not confirmed yet");
                    return View("Login", loginViewModel);
                }
            }

            // If the user already has a login (i.e., if there is a record in AspNetUserLogins table)
            // then sign-in the user with this external login provider
            var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider,
                info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

            if (signInResult.Succeeded)
            {
                return LocalRedirect(returnUrl);
            }

            // If there is no record in AspNetUserLogins table, the user may not have a local account
            else
            {
                if (email != null)
                {
                    // Create a new user without password if we do not have a user already
                    user = await _userManager.FindByEmailAsync(email);

                    if (user == null)
                    {
                        user = new ApplicationUser
                        {
                            UserName = info.Principal.FindFirstValue(ClaimTypes.Email),
                            Email = info.Principal.FindFirstValue(ClaimTypes.Email),
                            FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName),
                            LastName = info.Principal.FindFirstValue(ClaimTypes.Surname),
                        };

                        //This will create a new user into the AspNetUsers table without password
                        await _userManager.CreateAsync(user);
                    }

                    // Add a login (i.e., insert a row for the user in AspNetUserLogins table)
                    await _userManager.AddLoginAsync(user, info);

                    //Then send the Confirmation Email to the User
                    await SendConfirmationEmail(email, user);

                    //Redirect the user to the Successful Registration Page
                    return View("RegistrationSuccessful");
                }

                // If we cannot find the user email we cannot continue
                ViewBag.ErrorTitle = $"Email claim not received from: {info.LoginProvider}";
                ViewBag.ErrorMessage = "Please contact support on info@dotnettutorials.net";

                return View("Error");
            }
        }
        #endregion

        #region Send Confirmation Email
        private async Task SendConfirmationEmail(string? email, ApplicationUser? user)
        {
            // Generate token
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            // Build the Confirmation Link which must include the CallBack URL
            var ConfirmationLink = Url.Action("ConfirmEmail", "Account",
                new { UserId = user.Id, Token = token }, protocol: HttpContext.Request.Scheme);

            // Send the Confirmation Link to the User Email Id
            await _emailSender.SendEmailAsync(email, "Confirm Your Email",
                $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(ConfirmationLink)}'>clicking here</a>.", true);
        }
        #endregion

        #region Confirm Email
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string UserId, string Token)
        {
            if (UserId == null || Token == null)
            {
                ViewBag.Message = "The link is Invalid or Expired";
            }

            // find user
            var user = await _userManager.FindByIdAsync(UserId);
            if (user == null)
            {
                ViewBag.Message = $"The User ID {UserId} is Invalid";
                return View("NotFound");
            }

            // Call the ConfirmEmailAsync method which will mark the Email is Confirmed
            var result = await _userManager.ConfirmEmailAsync(user, Token);
            if (result.Succeeded)
            {
                ViewBag.Message = "Thank you for confirming your email";
                return View();
            }

            ViewBag.Message = "Email cannot be confirmed";
            return View();
        }
        #endregion

        #region Resend Confirmation Email
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResendConfirmationEmail(bool isResend = true)
        {
            if (isResend)
            {
                ViewBag.Message = "Resend Confirmation Email";
            }
            else
            {
                ViewBag.Message = "Send Confirmation Email";
            }

            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResendConfirmationEmail(string Email)
        {
            var user = await _userManager.FindByEmailAsync(Email);

            if (user == null || await _userManager.IsEmailConfirmedAsync(user))
            {
                // Handle the situation when the user does not exist or Email already confirmed.
                // For security, don't reveal that the user does not exist or Email is already confirmed
                return View("ConfirmationEmailSent");
            }

            // if is not confirmed
            await SendConfirmationEmail(Email, user);

            return View("ConfirmationEmailSent");
        }
        #endregion

        #region Forgot Password
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                // find this user by email
                var user = await _userManager.FindByEmailAsync(model.Email);

                // checking user was found and email is confirmed
                if (user != null && await _userManager.IsEmailConfirmedAsync(user))
                {
                    await SendForgotPasswordAsync(model.Email, user);

                    return RedirectToAction("ForgotPasswordConfirmation", "Account");
                }


                return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            return View(model);
        }
        #endregion

        #region Send Forgot Password Email
        private async Task SendForgotPasswordAsync(string? email, ApplicationUser? user)
        {
            // Generate the reset Password Token 
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // save the token into the AspNetUserTokens database table 
            await _userManager.SetAuthenticationTokenAsync(user, "ResetPassword",
                "ResetPasswordToken", token);

            // build the password reset link
            var passwordResetLink = Url.Action("ResetPassword", "Account",
                new { Email = email, Token = token }, protocol: HttpContext.Request.Scheme);

            // send the confirmation email to the User Email Id
            await _emailSender.SendEmailAsync(email, "Reset Your Password",
                $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(passwordResetLink)}'>clicking here</a>.", true);
        }
        #endregion

        #region Forgot Password Confirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }
        #endregion

        #region Reset Password
        public IActionResult ResetPassword(string Token, string Email)
        {
            // if token or email null, errors added ViewBag
            if (Token == null || Email == null)
            {
                ViewBag.ErrorTitle = "Invalid Password Reset Token";
                ViewBag.ErrorMessage = "The Link is Expired or Invalid";
                return View("Error");
            }
            else
            {
                ResetPasswordViewModel model = new ResetPasswordViewModel();
                model.Token = Token;
                model.Email = Email;
                return View(model);
            }
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                // find user by email
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    // reset password
                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

                    if (result.Succeeded)
                    {
                        // Upon successful password reset and if the account is lockedout,
                        // set the account lockout end date to current UTC date time, 
                        // so the user can login with the new password
                        if (await _userManager.IsLockedOutAsync(user))
                        {
                            await _userManager.SetLockoutEndDateAsync(user,
                                DateTimeOffset.UtcNow);
                        }

                        // Once the Password is Reset, remove the token from the database
                        await _userManager.RemoveAuthenticationTokenAsync(user, "ResetPassword", "ResetPasswordToken");

                        return RedirectToAction("ResetPasswordConfirmation", "Account");
                    }

                    // display errors 
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }

                    return View(model);
                }

                // avoid attacks
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }

            // display validation error
            return View(model);
        }
        #endregion

        #region Reset Password Confirmation
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }
        #endregion

        #region Change Password
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            // check user
            var user = await _userManager.GetUserAsync(User);

            var userHasPassword = await _userManager.HasPasswordAsync(user);

            // if user already has password, action change password
            if (!userHasPassword)
            {
                return RedirectToAction("AddPassword", "Account");
            }
            // if user has not password, to AddPassword view
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                // find the user
                var user = await _userManager.GetUserAsync(User);

                if (user == null)
                {
                    return RedirectToAction("Login", "Account");
                }

                // ChangePasswordAsync
                var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);

                if (!result.Succeeded)
                {
                    // display errors
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }

                // upon successfully changing refresh sign-in cookie
                await _signInManager.RefreshSignInAsync(user);

                // return ChangePasswordConfirmation view
                return RedirectToAction("ChangePasswordConfirmation", "Account");
            }

            // model is not valid
            return View(model);
        }
        #endregion

        #region Change Password Confirmation
        public IActionResult ChangePasswordConfirmation()
        {
            return View();
        }
        #endregion

        #region Add Password
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> AddPassword()
        {
            // check user
            var user = await _userManager.GetUserAsync(User);

            var userHasPassword = await _userManager.HasPasswordAsync(user);

            // if user already has password, action change password
            if (userHasPassword)
            {
                return RedirectToAction("ChangePassword", "Account");
            }
            // if user has not password, to AddPassword view
            return View();
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> AddPassword(AddPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                // find user
                var user = await _userManager.GetUserAsync(User);

                if (user == null)
                {
                    ModelState.AddModelError(string.Empty, "Unable to load user");
                    return View();
                }

                // add password this authorized user
                var result = await _userManager.AddPasswordAsync(user, model.NewPassword);

                // handle the failure scenario
                if (!result.Succeeded)
                {
                    // display errors
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    return View();
                }

                // handle success scenario
                // refresh the authentication cookie to store the updated user information
                await _signInManager.RefreshSignInAsync(user);

                // redirect AddPasswordConfirmation action
                return RedirectToAction("AddPasswordConfirmation", "Account");
            }

            return View();
        }
        #endregion

        #region Add Password Confirmation
        public IActionResult AddPasswordConfirmation()
        {
            return View();
        }
        #endregion

        #region Send Account Locked Email
        private async Task SendAccountLockedEmail(string? email)
        {
            // Send the confirmation email to the User Id
            await _emailSender.SendEmailAsync(email, "Account Locked",
                "Your account is locked Due to multiple invalid Attempts", true);
        }
        #endregion

        #region Confirm Phone Number
        public async Task<IActionResult> ConfirmPhoneNumber()
        {
            // find a user
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with Id = '{_userManager.GetUserId(User)}'");
            }

            // user was found , create model confirm phone number
            ConfirmPhoneNumberViewModel model = new ConfirmPhoneNumberViewModel
            {
                PhoneNumber = user.PhoneNumber
            };

            return View(model);
        }
        #endregion

        #region Send Phone Verification Code
        [Authorize]
        [HttpPost]
        public async Task<IActionResult> SendPhoneVerificationCode(ConfirmPhoneNumberViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                {
                    return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
                }

                //Generate the Token
                var token = await _userManager.GenerateChangePhoneNumberTokenAsync(user, model.PhoneNumber);

                // Code to send the token via SMS 
                var result = await _smsSender.SendSmsAsync(model.PhoneNumber, token);

                if (result)
                {
                    // Save or pass the phone number for later verification
                    TempData["PhoneNumber"] = model.PhoneNumber;

                    // Redirect to verification view
                    return RedirectToAction("VerifyPhoneNumber", "Account");
                 };
            }
            else
            {
                ViewBag.ErrorTitle = "Unable to send SMS";
                ViewBag.ErrorMessage = "Please try after some time";
                return RedirectToAction("Error");
            }

            return View(model);
        }
        #endregion

        #region Verify Phone Number
        [Authorize]
        [HttpGet]
        public IActionResult VerifyPhoneNumber()
        {
            TempData["PhoneNumber"] = TempData["PhoneNumber"] as string;
            return View();
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> VerifyPhoneNumber(string token)
        {
            var phoneNumber = TempData["PhoneNumber"] as string;
            var user = await _userManager.GetUserAsync(User);

            var result = await _userManager.VerifyChangePhoneNumberTokenAsync(user, token, phoneNumber);

            if (result)
            {
                // Update User's PhoneNumber and PhoneNumberConfirmed
                user.PhoneNumber = phoneNumber;
                user.PhoneNumberConfirmed = true;
                await _userManager.UpdateAsync(user);

                // return success page
                return View("PhoneVerificationSuccessful");
            }
            else
            {
                // Handle Verification Failure
                ViewBag.ErrorTitle = "Verification Failed";
                ViewBag.ErrorMessage = "Either the Token expired or you entered an invalid Token";
                return RedirectToAction("Error");
            }
        }
        #endregion

        #region Phone Verification Successful
        [Authorize]
        [HttpGet]
        public IActionResult PhoneVerificationSuccessful()
        {
            return View();
        }
        #endregion

        #region Manage Two Factor Authentication
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> ManageTwoFactorAuthentication()
        {
            var user = await _userManager.GetUserAsync(User);
            if(user == null)
            {
                return NotFound($"Unable to load user with ID = '{_userManager.GetUserId(User)}'");
            }

            // First , we need check email and number confirmed
            if(!user.EmailConfirmed || !user.PhoneNumberConfirmed)
            {
                ViewBag.ErrorTitle = "You cannot enable/disable Two Factor Authentication";
                ViewBag.ErrorMessage = "Your Phone Number or email not Confirmed yet";
                return View("Error");
            }

            string message;
            if(user.TwoFactorEnabled)
            {
                message = "Disable 2FA";
            }
            else
            {
                message = "Enable 2FA";
            }

            // Generate token for 2FA
            var TwoFactorToken = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultProvider);

            // Sending the token Email Id and Mobile Number

            // sending SMS 
            var result = await _smsSender.SendSmsAsync(user.PhoneNumber, $"Your token to {message} is {TwoFactorToken}");

            // sending token to the email
            await _emailSender.SendEmailAsync(user.Email, $"Your token to {message} is {TwoFactorToken}", TwoFactorToken, false);

            return View();
        }


        [HttpPost]
        [Authorize]
        public async Task<IActionResult> ManageTwoFactorAuthentication(string token)
        {
            // find user
            var user = await _userManager.GetUserAsync(User);
            if(user == null)
            {
                return NotFound($"Unable to load user with ID = '{_userManager.GetUserId(User)}'");
            }

            // check token is valid
            var result = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultProvider, token);

            if(result)
            {
                // Handle valid token scenario
                if (user.TwoFactorEnabled)
                {
                    user.TwoFactorEnabled = false;
                    ViewBag.Message = "You have successfully disabled Two Factor Authentication";
                }
                else
                {
                    user.TwoFactorEnabled = true;
                    ViewBag.Message = "You have successfully enabled Two Factor Authentication";
                }

                // update database for this user
                await _userManager.UpdateAsync(user);

                return View("TwoFactorAuthenticationSuccessful");
            }
            else
            {
                // Handle invalid token scenario
                ViewBag.ErrorTitle = "Unable to Enable/Disable Two Factor Authentication";
                ViewBag.ErrorMessage = "Either the Token is Expired or you entered some wrong information";
                return View("Error");
            }
        }
        #endregion

        #region Verify Two Factor Token
        [HttpGet]
        [AllowAnonymous]
        public IActionResult VerifyTwoFactorToken(string email, string returnUrl, bool rememberMe, 
            string twoFactorAuthenticationToken)
        {
            VerifyTwoFactorTokenViewModel model = new VerifyTwoFactorTokenViewModel
            {
                Email = email,
                ReturnUrl = returnUrl,
                RememberMe = rememberMe,
                TwoFactorCode = twoFactorAuthenticationToken
            };

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyTwoFactorToken(VerifyTwoFactorTokenViewModel model)
        {
            if(!ModelState.IsValid)
            {
                return View(model);
            }

            // find the user by email
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid Login Attempt.");
                return View(model);
            }

            // Validate 2FA Token
            var result = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", model.TwoFactorCode);
            if (result)
            {
                // Handle success scenario
                // Sign in the user and redirect
                await _signInManager.SignInAsync(user, isPersistent: model.RememberMe);

                // Check if the ReturnUrl is not null and is a local Url
                if (model.ReturnUrl != null && Url.IsLocalUrl(model.ReturnUrl))
                {
                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // Redirect to the Default page
                    return RedirectToAction("Index", "Home");
                }
            }

            // handle failure scenario
            ModelState.AddModelError(string.Empty, "Invalid verification code");

            return View(model);
        }
        #endregion
    }
}
