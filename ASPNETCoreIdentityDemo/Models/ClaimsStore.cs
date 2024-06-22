using System.Security.Claims;

namespace ASPNETCoreIdentityDemo.Models
{
    public static class ClaimsStore
    {
        // getting all claims
        public static List<Claim> GetAllClaims()
        {
            return new List<Claim>
            {
                // other claims added, as you needed
                new Claim("Create Role", "Create Role"),
                new Claim("Edit Role", "Edit Role"),
                new Claim("Delete Role", "Delete Role")
            };
        }
    }
}
