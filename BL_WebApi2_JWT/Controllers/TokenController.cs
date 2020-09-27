using System.Net;
using System.Web.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using BL_WebApi2_JWT.Modules;
using BL_WebApi2_JWT.Models;


namespace BL_WebApi2_JWT.Controllers
{
    //JWT Token generation module
    public class TokenController : ApiController
    {
        //GET http://localhost:25419/api/token      -- HttpModule: Authorization Header
        [AllowAnonymous]
        [HttpGet]
        [Route("api/Token")]
        public string Get()
        {
            var identity = (ClaimsIdentity)HttpContext.Current.User.Identity;
            return JwtManager.GenerateToken(identity);
            //return JwtManager.GenerateToken(identity.Name);
        }

        //GET http://localhost:25419/api/token?username=Davolio&password=Nancy
        [AllowAnonymous]
        [HttpGet]
        [Route("api/GetToken")]
        public string Get(string username, string password)
        {
            EmployeeRepository.GetEmployeeIdentity(username, password);

            if (CheckUser(username, password))
            {
                var identity = (ClaimsIdentity)HttpContext.Current.User.Identity;
                return JwtManager.GenerateToken(identity);
            }
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }

        public bool CheckUser(string username, string password)
        {
            // should check in the database
            return true;
        }
    }
}
