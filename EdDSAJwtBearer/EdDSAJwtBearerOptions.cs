using Microsoft.AspNetCore.Authentication;

namespace EdDSAJwtBearer
{
    public class EdDSAJwtBearerOptions : AuthenticationSchemeOptions
    {
        public string PublicSigninKey { get; set; } // obligatorio 
        public bool ValidateIssuer { get; set; }
        public string ValidIssuer { get; set; } // url del servidor que genera los tokens generalmente el que genera el token
        public bool ValidateAudience { get; set; } // a quien va a estar dirigido el token
        public string ValidAudience { get; set; } // url a quien va dirigido el token
        public bool ValidateLifeTime { get; set; }
        public bool SaveToken { get; set; }
    }
}
