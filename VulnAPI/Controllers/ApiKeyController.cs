using DotNet.RateLimiter.ActionFilters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace VulnAPI.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class ApiKeyController : ControllerBase
    {
        private readonly static string SecurityKey = "n[K)2?U)8)]BP{b:PVZzNhTKegTQJdMNPtdmmec]H?z;QFu]724{$?T%#GSizvUUu]D@qN:k,V,h@8y=3:f?Cq_zYJ.*u,BNZ}NGkR=(M,S!.]@hAM@j{24]c75,xRDP3j";

        public ApiKeyController(){}

        [HttpGet(Name = "GetApiKey")]
        [RateLimit(PeriodInSec = 60, Limit = 1)]
        public ApiKeyResponse Get(string cpfCnpj, string nome, string email)
        {
            var apiKeyResponse = new ApiKeyResponse();
            string token = string.Empty;
            string tipo = "Client";
            string sistema = "WebApp";

            var msgsContext = new StringBuilder();
            msgsContext.AppendFormat("Nome: {0}; ", nome);
            msgsContext.AppendFormat("Cpf/Cnpj: {0}; ", cpfCnpj);
            msgsContext.AppendFormat("E-mail: {0}; ", email);
            msgsContext.AppendFormat("Tipo: {0}; ", tipo);
            msgsContext.AppendFormat("Sistema: {0}; ", sistema);
            try
            {
                var Claims = GetClains(nome, cpfCnpj, email, tipo, sistema);
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecurityKey));
                var Creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var jwtSecurityToken = new JwtSecurityToken(
                    issuer: "Emissor",
                    audience: "Parceiro",
                    claims: Claims,
                    expires: DateTime.Now.AddSeconds(30),
                    //expires: DateTime.Now.AddHours(2),
                    signingCredentials: Creds
                );

                apiKeyResponse.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

                //apiKeyResponse.Token = encryptToken = Encrypt(token);

                apiKeyResponse.Success = true;
            }
            catch (Exception)
            {
                apiKeyResponse.Success = false;
                throw;
            }
            return apiKeyResponse;
        }

        private Claim[] GetClains(string nome, string cpf, string email, string tipo, string sistema)
        {
            var Claims = new[]
            {
                    new Claim (ClaimTypes.Name, nome),
                    new Claim (ClaimTypes.Sid, cpf),
                    new Claim (ClaimTypes.Email, email),
                    new Claim (ClaimTypes.Role, tipo),
                    new Claim (ClaimTypes.System, sistema)
            };

            return Claims;
        }

        [HttpPost(Name = "ValidaToken")]
        [RateLimit(PeriodInSec = 60, Limit = 3)]
        public ValidaTokenResponse ValidaToken([FromBody] ValidaTokenRequest request)
        {
            var tokenResponse = new ValidaTokenResponse();
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var validations = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true, // assinaura
                    ValidateLifetime = true, // Existe expiração no token
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidIssuer = "Emissor",
                    ValidAudience = "Parceiro",
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecurityKey))
                    //,RequireExpirationTime = true
                };

                SecurityToken validatedToken;
                IPrincipal principal = handler.ValidateToken(request.Token, validations, out validatedToken);
                //return (ClaimsIdentity)principal.Identity;

                tokenResponse.Success = true;
            }
            catch (Exception)
            {
                tokenResponse.Success = false;
                throw;
            }
           
            return tokenResponse;
        }

        public static string Encrypt(string clearText)
        {

            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(SecurityKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return clearText;
        }

        private static string Decrypt(string cipherText)
        {
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(SecurityKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }

        /*
        public string GetTokenCriptografado(string nome, string cpf, string email, string qtdapolice, string corretora, string area)
        {
            var Claims = GetClains(nome, cpf, email, qtdapolice, corretora, area);
            var handler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "liberty",
                Audience = "liberty",
                //Expires = DateTime.Now.AddHours(2),
                Subject = new ClaimsIdentity(Claims),
                EncryptingCredentials = new X509EncryptingCredentials(new X509Certificate2(@"C:\Users\Eldergor\ca.crt"))
            };

            return handler.CreateEncodedJwt(tokenDescriptor);
        }
        */

        /*
        private ClaimsIdentity ValidaTokenCriptografado(string Token)
        {
            var handler = new JwtSecurityTokenHandler();
            var validations = new TokenValidationParameters
            {
                ValidAudience = "liberty",
                ValidIssuer = "liberty",
                RequireSignedTokens = false,
                TokenDecryptionKey = new X509SecurityKey(new X509Certificate2("key_private.pfx", "idsrv3test"))
            };

            SecurityToken validatedToken;
            IPrincipal principal = handler.ValidateToken(Token, validations, out validatedToken);
            return (ClaimsIdentity)principal.Identity;
        }*/
    }
}
