using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;

namespace BL_WebApi2_JWT.Filters
{
    //PM> Install-Package Microsoft.AspNet.WebApi.Core -Version 5.2.3 --> IAuthenticationFilter
    public class JwtAuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        public string Realm { get; set; }
        public bool AllowMultiple = false;

        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var request = context.Request;
            var authorization = request.Headers.Authorization;

            if (authorization == null || authorization.Scheme.ToLower() != "bearer")
                return;

            if (string.IsNullOrEmpty(authorization.Parameter))
            {
                //Way 1
                HttpContext.Current.Response.StatusCode = 401;
                HttpContext.Current.Response.Write("Missing Jwt Token");
                //context.ErrorResult = new AuthenticationFailureResult("Missing Jwt Token", request);
                return;
            }

            var token = authorization.Parameter;
            var principal = await AuthenticateJwtToken(token);

            if (principal == null)
            {
                //Way 2
                context.ErrorResult = new AuthenticationFailureResult("Invalid token", request);
            }
            else
                context.Principal = principal;
        }

        //context.ErrorResult = new AuthenticationFailureResult(new { Error = true, Message = "Token is invalid" }, request);
        public class AuthenticationFailureResult : IHttpActionResult
        {
            public AuthenticationFailureResult(object jsonContent, HttpRequestMessage request)
            {
                JsonContent = jsonContent;
                Request = request;
            }
            public HttpRequestMessage Request { get; private set; }
            public Object JsonContent { get; private set; }
            public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
            {
                return Task.FromResult(Execute());
            }
            private HttpResponseMessage Execute()
            {
                HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                response.RequestMessage = Request;
                response.Content = new ObjectContent(JsonContent.GetType(), JsonContent, new JsonMediaTypeFormatter());
                return response;
            }
        }

        private static bool ValidateToken(string token, out string username)
        {
            username = null;

            var simplePrinciple = JwtManager.GetPrincipal(token);
            var identity = simplePrinciple.Identity as ClaimsIdentity;

            if (identity == null)
                return false;

            if (!identity.IsAuthenticated)
                return false;

            var usernameClaim = identity.FindFirst(ClaimTypes.Name);
            username = usernameClaim == null ? "" : usernameClaim.Value;

            if (string.IsNullOrEmpty(username))
                return false;

            // More validate to check whether username exists in system
            return true;
        }

        protected Task<IPrincipal> AuthenticateJwtToken(string token)
        {
            var simplePrinciple = JwtManager.GetPrincipal(token);
            var identity = simplePrinciple.Identity as ClaimsIdentity;

            if (identity == null) return null;
            if (!identity.IsAuthenticated) return null;

            IPrincipal user = new ClaimsPrincipal(identity);    //Use parsed JWT Token (HttpModule Create this JWT)
            return Task.FromResult(user);
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            context.Result = new ResultWithChallenge(context.Result);
            return Task.FromResult(0);
        }

        public class ResultWithChallenge : IHttpActionResult
        {
            private readonly IHttpActionResult next;

            public ResultWithChallenge(IHttpActionResult next)
            {
                this.next = next;
            }

            public async Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
            {
                var response = await next.ExecuteAsync(cancellationToken);
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Basic", "realm=BL_WebApi2_JWT"));
                }

                return response;
            }
        }

        bool IFilter.AllowMultiple
        {
            get { throw new NotImplementedException(); }
        }
    }
}
