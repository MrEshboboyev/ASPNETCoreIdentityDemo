using ASPNETCoreIdentityDemo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// configure identity
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(
    options =>
    {
        // Password  settings
        options.Password.RequireDigit = true;
        options.Password.RequiredLength = 8;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireUppercase = false;
        options.Password.RequireLowercase = false;
        options.Password.RequiredUniqueChars = 4;

        // RequireConfirmedEmail set to true
        options.SignIn.RequireConfirmedEmail = true;

        // Lockout settings
        options.Lockout.AllowedForNewUsers = true; // Lockout new users
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30); // Lockout duration
        options.Lockout.MaxFailedAccessAttempts = 5; // number of failed attempts allowed
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// adding db connection
builder.Services.AddDbContext<ApplicationDbContext>(option =>
{
    option.UseNpgsql(builder.Configuration.GetConnectionString("IdentityConnection"));
});

// Configure the Application Cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    // default LoginPath = "/Account/Login"
    options.LoginPath = "/Account/Login";
    
    // default AccessDeniedPath = "/Account/AccessDenied"
    options.AccessDeniedPath = "/Account/AccessDenied";
});

// add authentication for external providers
var GoogleClientId = builder.Configuration["Google:AppId"];
var GoogleClientSecret = builder.Configuration["Google:AppSecret"];

var MicrosoftClientId = builder.Configuration["Microsoft:AppId"];
var MicrosoftClientSecret = builder.Configuration["Microsoft:AppSecret"];

var FacebookClientId = builder.Configuration["Facebook:AppId"];
var FacebookClientSecret = builder.Configuration["Facebook:AppSecret"];

builder.Services.AddAuthentication()
.AddGoogle(options =>
{
    options.ClientId = GoogleClientId;
    options.ClientSecret = GoogleClientSecret;
    // You can set other options as needed.
})
.AddMicrosoftAccount(microsoftOptions =>
{
    microsoftOptions.ClientId = MicrosoftClientId;
    microsoftOptions.ClientSecret = MicrosoftClientSecret;
})
.AddFacebook(facebookOptions =>
{
    facebookOptions.ClientId = FacebookClientId;
    facebookOptions.ClientSecret = FacebookClientSecret;
});

// adding authorization for claim policy
builder.Services.AddAuthorization(option =>
{
    option.AddPolicy("DeleteRolePolicy", policy => policy.RequireClaim("Delete Role"));
    option.AddPolicy("EditRolePolicy", policy => policy.RequireClaim("Edit Role"));
});

// adding email service lifetime
builder.Services.AddTransient<ISenderEmail, EmailSender>();

// Configure Token LifeSpan
builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    // Set Token lifespan to 2 hours
    options.TokenLifespan = TimeSpan.FromHours(2);
});

// add lifetime for SMS Service
builder.Services.AddTransient<ISMSSender, SMSSender>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseStatusCodePagesWithReExecute("/Error/{0}");
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// add Authentication
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
