using System;
using System.Net.Http.Headers;
using System.Text;
using System.Web;
using System.Security.Claims;
using System.Net;
using BL_WebApi2_JWT.Models;


namespace BL_WebApi2_JWT.Modules
{

    //<system.webServer>
    //  <modules>
    //    <add name="BasicIHttpModule" type="BL_WebApi2_JWT.Modules.BasicIHttpModule"/>
    //  </modules>
    
    public class BasicIHttpModule : IHttpModule
    {
        private const string Realm = "BL_WebApi2_JWT";
        public void Init(HttpApplication context)
        {
            // Register event handlers
            context.AuthenticateRequest += OnApplicationAuthenticateRequest;
            context.EndRequest += OnApplicationEndRequest;
        }

        private static void OnApplicationAuthenticateRequest(object sender, EventArgs e)
        {
            var request = HttpContext.Current.Request;
            var authHeader = request.Headers["Authorization"];
            if (authHeader != null)
            {
                var authHeaderVal = AuthenticationHeaderValue.Parse(authHeader);

                // RFC 2617 sec 1.2, "scheme" name is case-insensitive
                if (authHeaderVal.Scheme.Equals("basic", StringComparison.OrdinalIgnoreCase) && authHeaderVal.Parameter != null)
                {
                    AuthenticateUser(authHeaderVal.Parameter);
                }
            }
        }

        private static bool AuthenticateUser(string credentials)
        {
            try
            {
                var encoding = Encoding.GetEncoding("iso-8859-1");
                credentials = encoding.GetString(Convert.FromBase64String(credentials));
            }
            //catch (Exception ex)
            catch (Exception)
            {
                //errorMessage = ex.Message;
                HttpContext.Current.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                return false;
            }

            var credentialsArray = credentials.Split(':');
            var username = credentialsArray[0];
            var password = credentialsArray[1];

            /* REPLACE THIS WITH REAL AUTHENTICATION
            ----------------------------------------------
            if (!(username == "user" && password == "pass"))
            {
                return false;
            }
            var identity = new GenericIdentity(username);
            SetPrincipal(new GenericPrincipal(identity, null));
            return true;
            ----------------------------------------------*/

            var ei = EmployeeRepository.GetEmployeeIdentity(username, password);
            if (!ei) return false;

            var identity = (ClaimsIdentity)HttpContext.Current.User.Identity;
            return identity.Name.Length > 0 ? true : false;

        }

        // If the request was unauthorized, add the WWW-Authenticate header to the response.
        private static void OnApplicationEndRequest(object sender, EventArgs e)
        {
            var response = HttpContext.Current.Response;
            if (response.StatusCode == 400)
            {
                response.Status = "400 Bad Request";
                //response.Headers.Add("Message", errorMessage);
                response.ContentType = "text/html";
            }
            if (response.StatusCode == 401)
            {
                response.Headers.Add("WWW-Authenticate", string.Format("Basic realm=\"{0}\"", Realm));
                response.Status = "401 Authorization Required";
                response.ContentType = "text/html";
            }
        }

        public void Dispose()
        {
        }
    }


}