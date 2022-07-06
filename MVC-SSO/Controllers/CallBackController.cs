using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace MVC_SSO.Controllers
{
    public class CallBackController : Controller
    {
        // GET: CallBack
        public ActionResult Index()
        {
            ViewBag.Code = Request.QueryString["code"] ?? "none";

           return View();
        }



    }
}