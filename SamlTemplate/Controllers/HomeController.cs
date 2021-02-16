using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;

using Microsoft.AspNetCore.Authentication.Cookies;

using SamlTemplate.Models;

namespace SamlTemplate.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        private readonly IConfiguration _configuration;

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
        {
            _logger = logger;

            _configuration = configuration;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult AuthorizedPage()
        {
            return View();
        }
  
        public IActionResult Privacy()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public ActionResult ExternalLogin(string provider = "Saml2", string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            if (returnUrl == null || Url.IsLocalUrl(returnUrl))
            {
                // Request a redirect to the external login provider.
                var redirectUrl = Url.Action("ExternalLoginCallback", "Home", new { ReturnUrl = returnUrl });
                var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
                properties.Items["LoginProviderKey"] = provider;
                return Challenge(properties, provider);
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("ExternalLoginCallback")]
        public IActionResult ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (Url.IsLocalUrl(returnUrl)) //e.g. user returning to confirm email
            {
                return LocalRedirect(returnUrl);
            }

            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("Logout")]
        public async Task Logout(string returnUrl = null, string remoteError = null)
        {
            // Remove All Session Cookies.

            var _dateString = DateTime.Now.AddDays(-1).ToString("ddd, dd MMM yyyy HH:mm:00") + " GMT";

            if (HttpContext.Request.Cookies.Count > 0)
            {
                var siteCookies = HttpContext.Request.Cookies.Where(c => c.Key.Contains(".AspNetCore.") || c.Key.Contains("Microsoft.Authentication"));

                foreach (var cookie in siteCookies)
                {
                    Response.Cookies.Delete(cookie.Key);
                }
            }

            foreach (var cookie in Request.Cookies)
            {
                HttpContext.Response.Headers.Append(@"Set-Cookie", $"{cookie.Key}=reset; path=/; httponly=true; SameSite=none; Secure=true; expires={_dateString};");

                Response.Cookies.Delete(cookie.Key);
            }
            
            
            var result = await HttpContext.AuthenticateAsync();
            var properties = result.Properties;
            var provider = properties.Items[".AuthScheme"];
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(provider, properties);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
