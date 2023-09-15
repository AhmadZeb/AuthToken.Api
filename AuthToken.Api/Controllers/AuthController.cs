using AuthToken.Api.Models.LoginUsers;
using AuthToken.Api.Models.RegisterUser;
using AuthToken.Api.Models.Roles;
using AuthToken.Api.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Win32;

namespace AuthToken.Api.Controllers
{
    //10
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;
        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> RegisterUser(RegisterUserData user)
        {
            try
            {
                var _statusResponse = new RegisterStatusResponse();
                if (!ModelState.IsValid)
                    return BadRequest("Invalid payload");

                var statusResponse = await _authService.RegisterUser(user, UserRoles.Admin);
                if (statusResponse.StatusMessage == "User created successfully!")
                {
                    _statusResponse.StatusCode = statusResponse.StatusCode;
                    _statusResponse.StatusMessage = statusResponse.StatusMessage;
                    return Ok(_statusResponse);
                }
                return BadRequest("Something went worng");

            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginUser user)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest();
                }
                var result = await _authService.Login(user);
                if (result.StatusMessage == "Success")
                {
                    //var tokenString = _authService.GenerateTokenString(user);
                    return Ok(result);
                }
                return BadRequest();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
    }
}
