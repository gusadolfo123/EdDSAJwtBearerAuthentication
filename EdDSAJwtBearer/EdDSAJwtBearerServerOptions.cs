namespace EdDSAJwtBearer
{
    /// <summary>
    /// Opciones del servidor que creara los tokens de manera asimetrica
    /// </summary>
    public class EdDSAJwtBearerServerOptions
    {
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public string PrivateSigningKey { get; set; }
        public string PublicSigningKey { get; set; }
    }
}
