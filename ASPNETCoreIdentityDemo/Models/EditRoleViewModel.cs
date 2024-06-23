﻿using System.ComponentModel.DataAnnotations;

namespace ASPNETCoreIdentityDemo.Models
{
    public class EditRoleViewModel
    {
        [Required]
        public string Id { get; set; }
        [Required(ErrorMessage = "Role Name is required")]
        public string RoleName { get; set; }
        public string? Description { get; set; }

        public List<string>? Users { get; set; }
        public List<string>? Claims { get; set; }
    }
}
