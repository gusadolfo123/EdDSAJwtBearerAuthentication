using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
    public static class EdDSATokenHandler
    {
        public static string CreateToken(Dictionary<string, object> payload, string edDSAPrivateKey)
        {
            var headerValues = new Dictionary<string, object>
            {
                { "type", "JWT" },
                { "alg", "EdDSA" }
            };

            string header = JsonSerializer.Serialize(headerValues);
            string payloadSerialize = JsonSerializer.Serialize(payload);
            
            header = Base64UrlEncode(header);
            payloadSerialize = Base64UrlEncode(payloadSerialize);

            // obtener la firma del token
            string signature = GetJWTSignature(header, payloadSerialize, edDSAPrivateKey);

            return $"{header}.{payload}.{signature}";
        }

        public static string CreateToken(
            string edDSAPrivateKey, 
            string issuer = null, 
            string audience = null,
            IEnumerable<Claim> claims = null,
            string[] roles = null,
            DateTime? expires = null)
        {
            var payload = new Dictionary<string, object>
            {

            };

            var headerValues = new Dictionary<string, object>
            {
                { "type", "JWT" },
                { "alg", "EdDSA" }
            };

            string header = JsonSerializer.Serialize(headerValues);
            string payloadSerialize = JsonSerializer.Serialize(payload);

            header = Base64UrlEncode(header);
            payloadSerialize = Base64UrlEncode(payloadSerialize);

            // obtener la firma del token
            string signature = GetJWTSignature(header, payloadSerialize, edDSAPrivateKey);

            return $"{header}.{payload}.{signature}";
        }

        private static string GetJWTSignature(string header, string payloadSerialize, string edDSAPrivateKey)
        {
            throw new NotImplementedException();
        }

        private static string Base64UrlEncode(string header)
        {
            return null;
        }
    }
}
