using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Http;

namespace BL_WebApi2_JWT
{
    public class Global : HttpApplication
    {
        void Application_Start(object sender, EventArgs e)
        {
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            //RouteConfig.RegisterRoutes(RouteTable.Routes);            
        }
    }
}