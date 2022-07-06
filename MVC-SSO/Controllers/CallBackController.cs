using IdentityModel;
//using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Net.Http;
using IdentityModel.Client;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

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

        [HttpPost]
        [ActionName("Index")]
        public async Task<ActionResult> GetToken()
        {
         
            var code = Request.QueryString["code"];

            var client = new HttpClient();

            var response = await client.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
            {
                Address = "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token",

                ClientId = "cdbcce09-5216-4d9a-8e67-0b2170306526",
                ClientSecret = "Dx-8Q~dj98cIeu1V~V2wEcznjS7QLrD87otXkdzQ",
                Code = code,
                RedirectUri = "https://localhost:44303/CallBack",

                // optional PKCE parameter
               // CodeVerifier = "xyz"
            });


          //  await ValidateResponseAndSignInAsync(response, "nonce");

            if (!string.IsNullOrEmpty(response.IdentityToken))
            {
                ViewBag.IdentityTokenParsed = ParseJwt(response.IdentityToken);
            }
            if (!string.IsNullOrEmpty(response.AccessToken))
            {
                ViewBag.AccessTokenParsed = ParseJwt(response.AccessToken);
            }

            return View("Token", response);
        }

        private async Task ValidateResponseAndSignInAsync(TokenResponse response, string nonce)
        {
            if (!string.IsNullOrWhiteSpace(response.IdentityToken))
            {
               // var tokenClaims = ValidateToken(response.IdentityToken, nonce);
                var claims = new List<Claim>();

                if (!string.IsNullOrWhiteSpace(response.AccessToken))
                {
                   // claims.AddRange(await GetUserInfoClaimsAsync(response.AccessToken));

                    claims.Add(new Claim("access_token", response.AccessToken));
                    claims.Add(new Claim("expires_at", (DateTime.UtcNow.ToEpochTime() + response.ExpiresIn).ToDateTimeFromEpoch().ToString()));
                }

                if (!string.IsNullOrWhiteSpace(response.RefreshToken))
                {
                    claims.Add(new Claim("refresh_token", response.RefreshToken));
                }

                var id = new ClaimsIdentity(claims, "Cookies");
               
            }
        }

     //   private List<Claim> ValidateToken(string token, string nonce)
     //   {
     //       var certString = "MIIDBTCCAfGgAwIBAgIQNQb+T2ncIrNA6cKvUA1GWTAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB0RldlJvb3QwHhcNMTAwMTIwMjIwMDAwWhcNMjAwMTIwMjIwMDAwWjAVMRMwEQYDVQQDEwppZHNydjN0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqnTksBdxOiOlsmRNd+mMS2M3o1IDpK4uAr0T4/YqO3zYHAGAWTwsq4ms+NWynqY5HaB4EThNxuq2GWC5JKpO1YirOrwS97B5x9LJyHXPsdJcSikEI9BxOkl6WLQ0UzPxHdYTLpR4/O+0ILAlXw8NU4+jB4AP8Sn9YGYJ5w0fLw5YmWioXeWvocz1wHrZdJPxS8XnqHXwMUozVzQj+x6daOv5FmrHU1r9/bbp0a1GLv4BbTtSh4kMyz1hXylho0EvPg5p9YIKStbNAW9eNWvv5R8HN7PPei21AsUqxekK0oW9jnEdHewckToX7x5zULWKwwZIksll0XnVczVgy7fCFwIDAQABo1wwWjATBgNVHSUEDDAKBggrBgEFBQcDATBDBgNVHQEEPDA6gBDSFgDaV+Q2d2191r6A38tBoRQwEjEQMA4GA1UEAxMHRGV2Um9vdIIQLFk7exPNg41NRNaeNu0I9jAJBgUrDgMCHQUAA4IBAQBUnMSZxY5xosMEW6Mz4WEAjNoNv2QvqNmk23RMZGMgr516ROeWS5D3RlTNyU8FkstNCC4maDM3E0Bi4bbzW3AwrpbluqtcyMN3Pivqdxx+zKWKiORJqqLIvN8CT1fVPxxXb/e9GOdaR8eXSmB0PgNUhM4IjgNkwBbvWC9F/lzvwjlQgciR7d4GfXPYsE1vf8tmdQaY8/PtdAkExmbrb9MihdggSoGXlELrPA91Yce+fiRcKY3rQlNWVd4DOoJ/cPXsXwry8pWjNCo5JD8Q+RQ5yZEy7YPoifwemLhTdsBz3hlZr28oCGJ3kbnpW0xGvQb3VHSTVVbeei0CfXoW6iz1";
     //       var cert = new X509Certificate2(Convert.FromBase64String(certString));

     //       var parameters = new TokenValidationParameters
     //       {
     //           ValidAudience = "codeclient",
     //           ValidIssuer = "",
     //           //IssuerSigningKey = new X509SecurityToken(cert)
     //       };

     //SecurityToken jwt;
     //       var principal = new JwtSecurityTokenHandler().ValidateToken(token, parameters, out jwt);

     //       // validate nonce
     //       var nonceClaim = principal.FindFirst("nonce");

     //       if (!string.Equals(nonceClaim.Value, nonce, StringComparison.Ordinal))
     //       {
     //           throw new Exception("invalid nonce");
     //       }

     //       return principal.Claims.ToList();
     //   }

        //private async Task<IEnumerable<Claim>> GetUserInfoClaimsAsync(string accessToken)
        //{
        //    var userInfoClient = new UserInfoClient(new Uri(Constants.UserInfoEndpoint), accessToken);

        //    var userInfo = await userInfoClient.GetAsync();

        //    var claims = new List<Claim>();
        //    userInfo.Claims.ToList().ForEach(ui => claims.Add(new Claim(ui.Item1, ui.Item2)));

        //    return claims;
        //}

        private string ParseJwt(string token)
        {
            if (!token.Contains("."))
            {
                return token;
            }

            var parts = token.Split('.');
            var part = Encoding.UTF8.GetString(Base64Url.Decode(parts[1]));

            var jwt = JObject.Parse(part);
            return jwt.ToString();
        }

    }
}