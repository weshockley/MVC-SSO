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
                "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/" +
                "?client_id=cdbcce09-5216-4d9a-8e67-0b2170306526" +
                "&response_type=code" +
                "&scope=user:read" +
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