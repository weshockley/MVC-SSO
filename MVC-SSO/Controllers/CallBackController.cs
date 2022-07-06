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
                var tokenClaims = ValidateToken(response.IdentityToken, nonce);
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

         private List<Claim> ValidateToken(string token, string nonce)
     
        {
            var certstring = "miidbtccafggawibagiqnqb+t2ncirna6ckvua1gwtajbgurdgmchquambixedaobgnvbamtb0rldljvb3qwhhcnmtawmtiwmjiwmdawwhcnmjawmtiwmjiwmdawwjavmrmweqydvqqdewppzhnydjn0zxn0miibijanbgkqhkig9w0baqefaaocaq8amiibcgkcaqeaqntksbdxoiolsmrnd+mms2m3o1idpk4uar0t4/yqo3zyhagawtwsq4ms+nwynqy5hab4ethnxuq2gwc5jkpo1yirorws97b5x9ljyhxpsdjcsikei9bxokl6wlq0uzpxhdytlpr4/o+0ilalxw8nu4+jb4ap8sn9ygyj5w0flw5ymwioxewvocz1whrzdjpxs8xnqhxwmuozvzqj+x6daov5fmrhu1r9/bbp0a1glv4bbttsh4kmyz1hxylho0evpg5p9yikstbnaw9enwvv5r8hn7ppei21asuqxekk0ow9jnedhewcktox7x5zulwkwwziksll0xnvczvgy7fcfwidaqabo1wwwjatbgnvhsueddakbggrbgefbqcdatbdbgnvhqeepda6gbdsfgdav+q2d2191r6a38tborqwejeqma4ga1ueaxmhrgv2um9vdiiqlfk7expng41nrnaenu0i9jajbgurdgmchquaa4ibaqbunmszxy5xosmew6mz4weajnonv2qvqnmk23rmzgmgr516roews5d3rltnyu8fkstncc4madm3e0bi4bbzw3awrpbluqtcymn3pivqdxx+zkwkiorjqqlivn8ct1fvpxxxb/e9godar8exsmb0pgnuhm4ijgnkwbbvwc9f/lzvwjlqgcir7d4gfxpyse1vf8tmdqay8/ptdakexmbrb9mihdggsogxlelrpa91yce+fircky3rqlnwvd4dooj/cpxsxwry8pwjnco5jd8q+rq5yzey7ypoifwemlhtdsbz3hlzr28ocgj3kbnpw0xgvqb3vhstvvbeei0cfxow6iz1";
            X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(certstring));
            Microsoft.IdentityModel.Tokens.SecurityKey key = new X509SecurityKey(cert);

            var parameters = new TokenValidationParameters
            {
                ValidAudience = "cdbcce09-5216-4d9a-8e67-0b2170306526",
                ValidIssuer = "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0",
                IssuerSigningKey = key
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