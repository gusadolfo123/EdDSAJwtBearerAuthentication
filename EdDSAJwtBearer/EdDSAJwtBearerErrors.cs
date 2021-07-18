using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
    public static class EdDSAJwtBearerErrors
    {
        public const string ValidIssuerRequired = "Valid issuer is required when ValidateIssuer is true";
        public const string ValidAudienceRequired = "Valid audience is required when ValidateAudience is true";
        
        public const string InvalidToken = "(001) Invalid Bearer Authentication token";
        public const string InvalidIssuer = "(002) Invalid Issuer";
        public const string InvalidAudeience = "(003) Invalid audience";
        public const string ExpiredToken = "(004) Invalid Token";

    }
}
