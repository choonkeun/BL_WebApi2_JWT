using System;
using System.Data;
using System.Data.SqlClient;
using System.Security.Principal;
using System.Web;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using DL_ADONet_BASE;

namespace BL_WebApi2_JWT.Models
{
    public class EmployeeRepository
    {
        static string conStr = string.Empty;

        static EmployeeRepository() 
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            AppDomain.CurrentDomain.SetData("DataDirectory", baseDir);
            conStr = System.Configuration.ConfigurationManager.ConnectionStrings["ConnString"].ConnectionString;
        }

        public static Employee GetEmployeeByUserName(string ConnString, string userName, string password)
        {
            using (SqlCommand cmd = new SqlCommand())
            {
                Employee employee = new Employee();
                string sql = string.Empty;
                sql += " select top 1 * from [employees] ";
                sql += " where lastName=@lastName AND firstName=@firstName;";

                cmd.CommandTimeout = 50;
                cmd.CommandType = CommandType.Text;
                cmd.CommandText = sql;
                cmd.Parameters.AddWithValue("@lastName", userName);     //Davolio
                cmd.Parameters.AddWithValue("@firstName", password);    //Nancy
                DataTable dt = DataAccessLayer.GetDataTable(ConnString, cmd);
                foreach (DataRow dr in dt.Rows)
                {
                    employee = new Employee
                    {
                        EmployeeID = Convert.ToInt32(dr["EmployeeID"] == System.DBNull.Value ? 0 : dr["EmployeeID"]),
                        LastName = Convert.ToString(dr["LastName"] == System.DBNull.Value ? String.Empty : dr["LastName"]),
                        FirstName = Convert.ToString(dr["FirstName"] == System.DBNull.Value ? String.Empty : dr["FirstName"]),
                        Title = Convert.ToString(dr["Title"] == System.DBNull.Value ? String.Empty : dr["Title"]),
                        BirthDate = Convert.ToDateTime(dr["BirthDate"] == System.DBNull.Value ? DateTime.MinValue : dr["BirthDate"]),
                        HireDate = Convert.ToDateTime(dr["HireDate"] == System.DBNull.Value ? DateTime.MinValue : dr["HireDate"]),
                        Address = Convert.ToString(dr["Address"] == System.DBNull.Value ? String.Empty : dr["Address"]),
                        City = Convert.ToString(dr["City"] == System.DBNull.Value ? String.Empty : dr["City"]),
                        Region = Convert.ToString(dr["Region"] == System.DBNull.Value ? String.Empty : dr["Region"]),
                        PostalCode = Convert.ToString(dr["PostalCode"] == System.DBNull.Value ? String.Empty : dr["PostalCode"]),
                        Country = Convert.ToString(dr["Country"] == System.DBNull.Value ? String.Empty : dr["Country"]),
                        HomePhone = Convert.ToString(dr["HomePhone"] == System.DBNull.Value ? String.Empty : dr["HomePhone"]),
                        Extension = Convert.ToString(dr["Extension"] == System.DBNull.Value ? String.Empty : dr["Extension"]),
                        ReportsTo = Convert.ToInt32(dr["ReportsTo"] == System.DBNull.Value ? 0 : dr["ReportsTo"]),
                        Notes = Convert.ToString(dr["Notes"] == System.DBNull.Value ? String.Empty : dr["Notes"])
                    };
                }
                return employee;
            }
        }
        public static bool GetEmployeeIdentity(string username, string password)
        //public static GenericPrincipal GetEmployeeIdentity(string username, string password)
        {
            Employee employee = EmployeeRepository.GetEmployeeByUserName(conStr, username, password);

            var claims = new List<Claim>();

            //user not found
            if (employee.EmployeeID == 0)
            {
                HttpContext.Current.Response.StatusCode = 401;  //HttpStatusCode.Unauthorized

                claims.Add(new Claim(ClaimTypes.Name, ""));
                var identity = new ClaimsIdentity(claims, "Basic");
                SetPrincipal(new GenericPrincipal(identity, null));
                return false;
            }

            if (employee.ReportsTo <= 2)  //myRole(1 or 2)
            {
                claims.Add(new Claim(ClaimTypes.Role, "myRole"));
                claims.Add(new Claim(ClaimTypes.Name, username));
                claims.Add(new Claim("username", username));
                claims.Add(new Claim("title", employee.Title));
                var identity = new ClaimsIdentity(claims, "Bearer");
                SetPrincipal(new GenericPrincipal(identity, null));
            }
            else if (employee.ReportsTo <= 4)  //user(3 or 4), part time(5)
            {
                claims.Add(new Claim(ClaimTypes.Role, "user"));
                claims.Add(new Claim(ClaimTypes.Name, username));
                claims.Add(new Claim("username", username));
                claims.Add(new Claim("title", employee.Title));
                var identity = new ClaimsIdentity(claims, "Bearer");
                SetPrincipal(new GenericPrincipal(identity, null));
            }
            else
            {
                claims.Add(new Claim(ClaimTypes.Role, "visitor"));
                claims.Add(new Claim(ClaimTypes.Name, username));
                claims.Add(new Claim("username", username));
                var identity = new ClaimsIdentity(claims, "Basic");
                SetPrincipal(new GenericPrincipal(identity, null));
            }
            return true;
        }
        private static void SetPrincipal(IPrincipal principal)
        {
            Thread.CurrentPrincipal = principal;
            if (HttpContext.Current != null)
            {
                HttpContext.Current.User = principal;
            }
        }

    }
}