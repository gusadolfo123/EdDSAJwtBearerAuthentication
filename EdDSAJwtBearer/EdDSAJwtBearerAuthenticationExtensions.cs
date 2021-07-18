using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;

namespace EdDSAJwtBearer
{
    public static class EdDSAJwtBearerAuthenticationExtensions
    {
        public static AuthenticationBuilder AddEdDSAJwtBearer(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            Action<EdDSAJwtBearerOptions> configureOptions)
        {
            builder.Services
                .AddSingleton<IPostConfigureOptions<EdDSAJwtBearerOptions>, EdDSAJwtBearerPostConfigureOptions>();
            
            builder.Services.AddAuthentication()
                .AddScheme<EdDSAJwtBearerOptions, EdDSAJwtBearerAuthenticationHandler>(
                    authenticationScheme, configureOptions);
            
            return builder;
        }

        public static AuthenticationBuilder AddEdDSAJwtBearer(
            this AuthenticationBuilder builder,
            Action<EdDSAJwtBearerOptions> configureOptions)
        {
            return AddEdDSAJwtBearer(builder,
                 EdDSAJwtBearerDefaults.AuthenticationScheme,
                 configureOptions);
        }

        public static AuthenticationBuilder AddEdDSAJwtBearer(
            this AuthenticationBuilder builder,
            string authenticationScheme)
        {
            return AddEdDSAJwtBearer(builder,
            authenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddEdDSAJwtBearer(
            this AuthenticationBuilder builder)
        {
            return AddEdDSAJwtBearer(builder,
            EdDSAJwtBearerDefaults.AuthenticationScheme, _ => { });
        }

        public static IServiceCollection AddEdDSAJwtBearerServer(
            this IServiceCollection services,
            EdDSAJwtBearerServerOptions options)
        {
            services.AddSingleton<EdDSAJwtBearerServer>(new EdDSAJwtBearerServer(options));
            return services;
        }

        public static IServiceCollection AddEdDSAJwtBearerServer(
            this IServiceCollection services,
            Action<EdDSAJwtBearerServerOptions> configureOptions)
        {
            EdDSAJwtBearerServerOptions Options = new EdDSAJwtBearerServerOptions();
            configureOptions(Options);
            return AddEdDSAJwtBearerServer(services, Options);
        }
    }
}
