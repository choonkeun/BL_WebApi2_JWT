using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using BL_WebApi2_JWT.Filters;
using System.Web;

namespace BL_WebApi2_JWT.Controllers
{
    public class DataController : ApiController
    {
        [AllowAnonymous]
        [HttpGet]
        [Route("api/data/forall")]
        public IHttpActionResult Get()
        {
            return Ok("Now server time is: " + DateTime.Now.ToString());
        }

        [JwtAuthentication]
        [HttpGet]
        [Route("api/data/authenticate")]
        public IHttpActionResult GetForAuthenticate()
        {
            var identity = (ClaimsIdentity)HttpContext.Current.User.Identity;   //readonly
            return Ok("Hello " + identity.Name);
        }

        /// <summary>
        /// [JwtAuthentication] will parse input JWT Token and get Principle Claims and Roles
        /// but You need to have [Authorize(Roles = "myRole")] if you want to filter by Roles
        /// // http://www.jerriepelser.com/blog/using-roles-with-the-jwt-middleware/
        /// </summary>
        /// <returns></returns>
        [JwtAuthentication]
        [Authorize(Roles = "myRole")]
        [HttpGet]
        [Route("api/data/authorize")]
        public IHttpActionResult GetForAdmin()
        {
            var identity = (ClaimsIdentity)HttpContext.Current.User.Identity;
            var roles = identity.Claims
                        .Where(c => c.Type == ClaimTypes.Role)
                        .Select(c => c.Value);
            return Ok("Hello " + identity.Name + " Role: " + string.Join(",", roles.ToList()));
        }
    }
}
