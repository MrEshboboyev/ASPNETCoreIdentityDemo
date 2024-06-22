namespace ASPNETCoreIdentityDemo.Models
{
    public class UserClaimsViewModel
    {
        public UserClaimsViewModel()
        {
            // avoid NullReferenceException, initialize new List for Claims field
            Claims = new List<UserClaim>(); 
        }

        public string UserId { get; set; }
        public List<UserClaim> Claims { get; set; }
    }
}
