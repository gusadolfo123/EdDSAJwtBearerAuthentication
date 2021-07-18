using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
    public class EdDSAJwtBearerAuthenticationHandler : AuthenticationHandler<EdDSAJwtBearerOptions>
    {
        public EdDSAJwtBearerAuthenticationHandler(
            IOptionsMonitor<EdDSAJwtBearerOptions> options, 
            ILoggerFactory logger, 
            UrlEncoder encoder, 
            ISystemClock clock) : base(options, logger, encoder, clock)
        {

        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            AuthenticateResult result = AuthenticateResult.NoResult(); 

            // responsable de crear la identidad del usuario
            if (Request.Headers.ContainsKey("Authorization"))
            {
                if (AuthenticationHeaderValue.TryParse(Request.Headers["Authorization"], 
                    out var headerValue))
                {
                    if ("Bearer".Equals(headerValue.Scheme, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {                             
                            string error = string.Empty; 
                            string token = headerValue.Parameter;
                            
                            if (TryGetPayloadWithTokenValidation(token, this.Options, out var payload, out error))
                            {
                                List<Claim> claims = payload.Where(c => c.Key != "role")
                                    .Select(c => new Claim(c.Key, $"{c.Value}")).ToList();

                                if (payload.TryGetValue("role", out object Roles))
                                {
                                    // Deserializar el arreglo JSON
                                    string[] rolesArray = JsonSerializer.Deserialize<string[]>(Roles.ToString());
                                    if (rolesArray != null)
                                    {
                                        // Agregar los roles del usuario a la lista de Claims
                                        foreach (var Role in rolesArray)
                                        { 
                                            claims.Add(new Claim("role", Role.ToString()));
                                        }
                                    }
                                }

                                ClaimsIdentity identity = new ClaimsIdentity(
                                    // Claims con información del usuario
                                    claims,
                                    // Nombre del esquema de autenticación
                                    Scheme.Name,
                                    // Nombre del Claim que representa al Claim "name"
                                    "firstName",
                                    // Nombre del Claim que será utilizado para identificar un rol de usuario
                                    "role"
                                    );

                                ClaimsPrincipal principal = new ClaimsPrincipal(identity);

                                // creacion ticker de autenticacion
                                AuthenticationTicket ticket;

                                // ¿Las opciones de configuración indican guardar el Token?
                                if (Options.SaveToken)
                                {
                                    // Almacenar el Token en una instancia de 
                                    // AuthenticationProperties.
                                    var properties = new AuthenticationProperties();
                                    properties.StoreTokens(new AuthenticationToken[]
                                    {
                                        new AuthenticationToken{Name="access_token", Value=token}
                                    }); 

                                    // Crear el Ticket 
                                    ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
                                }
                                else
                                {
                                    // Crear el Ticket sin AuthenticationProperties.
                                    ticket = new AuthenticationTicket(principal, Scheme.Name);
                                }

                                result = AuthenticateResult.Success(ticket);
                                 
                            }
                            else
                            {
                                result = AuthenticateResult.Fail(error);
                            }
                        }
                        catch (Exception)
                        {
                            result = AuthenticateResult.Fail(EdDSAJwtBearerErrors.InvalidToken);
                        }
                    }
                }
            }

            return Task.FromResult(result);
        }

        private bool TryGetPayloadWithTokenValidation(
            string token, 
            EdDSAJwtBearerOptions options,
            out Dictionary<string, object> 
            payload, out string error)
        {
            bool IsValid = false;
            payload = default;
            error = string.Empty;

            // Lógica de validación
            try
            {
                if (EdDSATokenHandler.TryGetPayloadFromToken(token, options.PublicSigninKey, out payload))
                {
                    IsValid = true;
                    object Value;
                    if (options.ValidateIssuer)
                    {
                        // Debemos validar el emisor.
                        // El valor se debe encontrar en el Claim "iss"
                        IsValid = payload.TryGetValue("iss", out Value);
                        if (IsValid)
                        {
                            // Se encontró el Claim "iss"
                            // Compararlo con el emisor válido.
                            IsValid = options.ValidIssuer.Equals(Value.ToString(),
                            StringComparison.OrdinalIgnoreCase);
                        }

                        // Si la validación no fue exitosa
                        // devolver el mensaje de emisor no válido.
                        if (!IsValid) error = EdDSAJwtBearerErrors.InvalidIssuer;

                        if (IsValid && options.ValidateAudience)
                        {
                            // Debemos validar la audiencia.
                            // El valor se encuentra en el Claim "aud"
                            IsValid = payload.TryGetValue("aud", out Value);
                            if (IsValid)
                            {
                                string[] Audiences = Value.ToString().Split(",");
                                IsValid = Audiences.Contains(options.ValidAudience);
                            }
                            if (!IsValid) error = EdDSAJwtBearerErrors.InvalidAudeience;
                        }

                        if (IsValid && options.ValidateLifeTime)
                        {
                            // Debemos validar la expiración del Token.
                            // El valor se encuentra en el Claim "exp".
                            IsValid = payload.TryGetValue("exp", out Value);
                            if (IsValid)
                            {
                                long ExpirationTime = Convert.ToInt64(Value.ToString());
                                IsValid = ExpirationTime >
                                new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds();
                            }
                            if (!IsValid) error = EdDSAJwtBearerErrors.ExpiredToken;
                        }
                    }
                }
                else
                {
                    error = EdDSAJwtBearerErrors.InvalidToken;
                }
            }
            catch
            {
                IsValid = false;
                error = EdDSAJwtBearerErrors.InvalidToken;
            }


            return IsValid;
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            // Indica al cliente que se requiere el método de autenticación Bearer.
            Response.Headers["WWW-Authenticate"] = "Bearer";
            await base.HandleChallengeAsync(properties);
        }



    }
}
