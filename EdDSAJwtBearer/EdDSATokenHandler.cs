using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

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
            var payload = new Dictionary<string, object>();

            if (claims != null)
            {
                foreach (var item in claims)
                {
                    payload.TryAdd(item.Type, item.Value);
                }
            }

            if (issuer != null)
                payload.Add("iss", issuer);

            if (audience != null)
                payload.Add("aud", audience);

            if (expires != null)
                payload.Add("exp", new DateTimeOffset(expires.Value).ToUnixTimeSeconds());

            if (roles != null && roles.Length > 0)
                payload.Add("role", roles);

        
            return CreateToken(payload, edDSAPrivateKey);
        }

        public static string GetJWTSignature(string header, string payload, string edDSAPrivateKey) 
        {
            var signatureData = $"{header}.{payload}";
            var signatureBytes = Encoding.UTF8.GetBytes(signatureData);
            var signer = new Ed25519Signer();
            signer.Init(true, GetDerDecodedAsymemetricPrivateKeyParameter(edDSAPrivateKey));
            signer.BlockUpdate(signatureBytes, 0, signatureBytes.Length);

            return Base64UrlEncode(signer.GenerateSignature());
        }

        private static AsymmetricKeyParameter GetDerDecodedAsymemetricPrivateKeyParameter(string edDSAPrivateKey)
        { 
            return PrivateKeyFactory.CreateKey(Convert.FromBase64String(edDSAPrivateKey));
        }

        private static AsymmetricKeyParameter GetDerDecodedAsymemetricPublicKeyParameter(string edDSAPublicKey)  
        { 
            return PublicKeyFactory.CreateKey(Convert.FromBase64String(edDSAPublicKey));
        }

        private static AsymmetricCipherKeyPair GetDerDecodedAsymmetricCipherKeyPair(EdDSAKeys keys)
        {
            var privateKey = GetDerDecodedAsymemetricPrivateKeyParameter(keys.Private);
            var publicKey = GetDerDecodedAsymemetricPublicKeyParameter(keys.Public);
             
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        private static EdDSAKeys GetDerEncodedAsymmetricCipherKeyPair(AsymmetricCipherKeyPair keys)  
        {
            var privateKey = GetDerDecodedAsymemetricPrivateKeyParameter(keys.Private);
            var publicKey = GetDerDecodedAsymemetricPublicKeyParameter(keys.Public);

            return new EdDSAKeys(publicKey, privateKey);
        }

        public static string Base64UrlEncode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg);
            s = s.Split('=')[0];
            s = s.Replace('+', '-');
            s = s.Replace('/', '_');
            return s;
        }

        public static string Base64UrlEncode(string data)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            return Base64UrlEncode(dataBytes);
        }

        public static byte[] Base64UrlDecode(string arg)
        { 
            string s = arg; 
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default:
                    throw new Exception("Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }
    }
}
