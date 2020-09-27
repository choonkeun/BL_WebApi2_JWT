using System.Web;
using System.Web.Mvc;

namespace BL_WebApi2_BasicAuth
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
