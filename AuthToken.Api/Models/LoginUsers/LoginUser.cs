using System.ComponentModel.DataAnnotations;

namespace AuthToken.Api.Models.LoginUsers
{
    //1
    public class LoginUser
    {
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
    }
}
