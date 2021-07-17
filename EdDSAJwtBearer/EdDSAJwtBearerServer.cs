using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Claims;

namespace EdDSAJwtBearer
{
    public class EdDSAJwtBearerServer
    { 
        public EdDSAJwtBearerServerOptions EdDSAJwtBearerServerOptions { get; set; }

        public EdDSAJwtBearerServer()
        {
        }

        public EdDSAJwtBearerServer(EdDSAJwtBearerServerOptions options)
        {
            EdDSAJwtBearerServerOptions = options;
        }


    }
}
