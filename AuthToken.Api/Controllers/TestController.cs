using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthToken.Api.Controllers
{
    //11
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class TestController : ControllerBase
    {
        [HttpGet]
        public string Get()
        {
            return "You hit me!";
        }
    }
}
