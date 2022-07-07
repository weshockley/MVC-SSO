using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Web;
using System.Web.Mvc;

namespace MVC_SSO.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult SignIn()
        {
                var url =
                "https://login.microsoftonline.com/<Tenat ID>/oauth2/" +
                "?client_id=client ID" +
                "&response_type=code" +
                "&scope=openid profile read write offline_access" +
                "&redirect_uri=https://localhost:44303/CallBack" +
                "&nonce=" + "nonce";

            return Redirect(url);

        }


        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}