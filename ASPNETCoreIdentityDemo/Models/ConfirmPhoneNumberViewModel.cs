using System.ComponentModel.DataAnnotations;

namespace ASPNETCoreIdentityDemo.Models
{
    public class ConfirmPhoneNumberViewModel
    {
        [Phone(ErrorMessage = "Please Enter a Valid Phone Number")]
        [Required(ErrorMessage = "Please Enter Phone Number")]
        [Display(Name = "Phone Number")]
        public string PhoneNumber { get; set; }
    }
}
