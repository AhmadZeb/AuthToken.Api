using AuthToken.Api.Models.LoginUsers;
using AuthToken.Api.Models.RefreshToken;
using AuthToken.Api.Models.RegisterUser;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
namespace AuthToken.Api.Services
{
    //9
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
        }

        public async Task<RegisterStatusResponse> RegisterUser(RegisterUserData model, string role)
        {
            try
            {
                RegisterStatusResponse _statusResponse = new();
              
                var userExists = await _userManager.FindByNameAsync(model.Username);
                if (userExists != null) {
                    _statusResponse.StatusCode = 0;
                    _statusResponse.StatusMessage = "User already exists";
                    return _statusResponse;
                }

                ApplicationUser user = new()
                {
                    Email = model.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = model.Username,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                };
                var result = await _userManager.CreateAsync(user, model.Password); 
                if (!result.Succeeded)
                {
                    _statusResponse.StatusCode = 0;
                    _statusResponse.StatusMessage = "User creation failed! Please check user details and try again";
                    return _statusResponse;
               
                   
                }
                //Add Role
                if (!await _roleManager.RoleExistsAsync(role))
                    await _roleManager.CreateAsync(new IdentityRole(role));

                if (await _roleManager.RoleExistsAsync(role))
                    await _userManager.AddToRoleAsync(user, role);
                //Add Role
                _statusResponse.StatusMessage = "User created successfully!";
                return _statusResponse;

            }
            catch (Exception ex)
            {

                throw ex;
            }

        }

        public async Task<RefreshTokenModel> Login(LoginUser model)
        {
            try
            {
                RefreshTokenModel _TokenViewModel = new();
                //Check User  Email 
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    _TokenViewModel.StatusCode = 0;
                    _TokenViewModel.StatusMessage = "Invalid username";
                    return _TokenViewModel;
                }
                // Check User Password
                if (!await _userManager.CheckPasswordAsync(user, model.Password))
                {
                    _TokenViewModel.StatusCode = 0;
                    _TokenViewModel.StatusMessage = "Invalid password";
                    return _TokenViewModel;
                }
                //Check User Role
                var userRoles = await _userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                 {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(ClaimTypes.Role,"Admin"),
                    new Claim("Date", DateTime.Now.ToString()),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())

                   //new Claim(ClaimTypes.Name, user.UserName),
                   //new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                 };
                //Add User Role Claim
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                _TokenViewModel.AccessToken = GenerateTokenString(authClaims);
                _TokenViewModel.RefreshToken = GenerateRefreshToken();
                _TokenViewModel.StatusCode = 1;
                _TokenViewModel.StatusMessage = "Success";

                //Get Refresh Token
                var _RefreshTokenValidityInDays = Convert.ToInt64(_config["Jwt:RefreshTokenValidityInDays"]);
                user.RefreshToken = _TokenViewModel.RefreshToken;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(_RefreshTokenValidityInDays);
                //Update User
                await _userManager.UpdateAsync(user);


                return _TokenViewModel;
            }
            catch (Exception ex)
            {

                throw ex;
            }

        }

        //RefreshToken
        public async Task<RefreshTokenModel> GetRefreshToken(GetRefreshTokenViewModel model)
        {
            RefreshTokenModel _TokenViewModel = new();
            var principal = GetPrincipalFromExpiredToken(model.AccessToken);
            string username = principal.Identity.Name;
            var user = await _userManager.FindByNameAsync(username);

            if (user == null || user.RefreshToken != model.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                _TokenViewModel.StatusCode = 0;
                _TokenViewModel.StatusMessage = "Invalid access token or refresh token";
                return _TokenViewModel;
            }

            var authClaims = new List<Claim>
            {
                 new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                 new Claim(JwtRegisteredClaimNames.Email, user.Email),
                 new Claim(ClaimTypes.Role,"Admin"),
                 new Claim("Date", DateTime.Now.ToString()),
                 new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                //new Claim(ClaimTypes.Email,user.Email),
                
               //new Claim(ClaimTypes.Name, user.UserName),
              // new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };
            var newAccessToken = GenerateTokenString(authClaims);
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);

            _TokenViewModel.StatusCode = 1;
            _TokenViewModel.StatusMessage = "Success";
            _TokenViewModel.AccessToken = newAccessToken;
            _TokenViewModel.RefreshToken = newRefreshToken;
            return _TokenViewModel;
        }

        private  string GenerateTokenString(IEnumerable<Claim> claims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var _TokenExpiryTimeInHour = Convert.ToInt64(_config["Jwt:TokenExpiryTimeInHour"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = _config["Jwt:Issuer"],
                Audience = _config["Jwt:Audience"],
                //Expires = DateTime.UtcNow.AddHours(_TokenExpiryTimeInHour),
                Expires = DateTime.UtcNow.AddMinutes(1),
                SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256),
                Subject = new ClaimsIdentity(claims)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }

        //RefreshToken
    }
}
