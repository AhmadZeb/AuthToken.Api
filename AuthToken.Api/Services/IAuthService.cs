using AuthToken.Api.Models.LoginUsers;
using AuthToken.Api.Models.RefreshToken;
using AuthToken.Api.Models.RegisterUser;

namespace AuthToken.Api.Services
{
    //8
    public interface IAuthService
    {
        // string GenerateTokenString(LoginUser user);
        Task<RefreshTokenModel> Login(LoginUser user);
        Task<RegisterStatusResponse> RegisterUser(RegisterUserData user, string role);
        Task<RefreshTokenModel> GetRefreshToken(GetRefreshTokenViewModel model);

    }
}
