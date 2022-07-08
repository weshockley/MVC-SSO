using IdentityModel;
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
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

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
                Address = "https://login.microsoftonline.com/<Tenat ID>/oauth2/v2.0/token",

                ClientId = "<client ID>",
                ClientSecret = "<client Secret>",
                Code = code,
                RedirectUri = "https://localhost:44303/CallBack",

                // optional PKCE parameter
               // CodeVerifier = "xyz"
            });
           

            await ValidateResponseAndSignInAsync(response, "nonce");

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
                string stsDiscoveryEndpoint = "https://login.microsoftonline.com/<Tenant ID>/v2.0/.well-known/openid-configuration";

                var configManager = new Microsoft.IdentityModel.Protocols.ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());

                OpenIdConnectConfiguration config = await configManager.GetConfigurationAsync();
                List<Microsoft.IdentityModel.Tokens.SecurityKey> keys = config.SigningKeys.ToList();

                var tokenClaims = ValidateToken(response.IdentityToken, nonce, keys);
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

         private List<Claim> ValidateToken(string token, string nonce, List<Microsoft.IdentityModel.Tokens.SecurityKey> keys)
        {
            //keys are retrieved from open id config -> jwks_uri. 

            var parameters = new TokenValidationParameters
            {
                ValidAudience = "<client ID>",
                ValidIssuer = "https://login.microsoftonline.com/<Tenant id>/v2.0",
                IssuerSigningKeys = keys
            };

            Microsoft.IdentityModel.Tokens.SecurityToken jwt;
            var principal = new JwtSecurityTokenHandler().ValidateToken(token, parameters, out jwt);

            
            return principal.Claims.ToList();
        }

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