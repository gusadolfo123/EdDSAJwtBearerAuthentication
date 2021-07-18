using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
    public class EdDSAJwtBearerPostConfigureOptions : IPostConfigureOptions<EdDSAJwtBearerOptions>
    {
        public void PostConfigure(string name, EdDSAJwtBearerOptions options)
        {
            if (options.ValidateIssuer && string.IsNullOrWhiteSpace(options.ValidIssuer))
                throw new InvalidOperationException(EdDSAJwtBearerErrors.ValidIssuerRequired);

            if (options.ValidateAudience && string.IsNullOrWhiteSpace(options.ValidAudience))
                throw new InvalidOperationException(EdDSAJwtBearerErrors.ValidAudienceRequired);

             
        }
    }
}
