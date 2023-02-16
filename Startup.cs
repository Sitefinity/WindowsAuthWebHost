using IdentityServer.WindowsAuthentication.Configuration;
using Microsoft.Owin;
using Owin;
using Configuration;
using System.Configuration;
using System;
using System.Threading.Tasks;
using IdentityServer.WindowsAuthentication.Services;

[assembly: OwinStartup(typeof(WindowsAuthWebHost.Startup))]

namespace WindowsAuthWebHost
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var appSettings = ConfigurationManager.AppSettings;
            var idpReplyUrl = appSettings[IdpReplyUrlParam];
            if (string.IsNullOrEmpty(idpReplyUrl))
                throw new ArgumentException("Please set the IdpReplyUrl parameter");

            var idpRealm = appSettings[IdpRealmParam];
            if (string.IsNullOrEmpty(idpRealm))
                throw new ArgumentException("Please set the IdpRealm parameter");

            app.UseWindowsAuthenticationService(new WindowsAuthenticationOptions
            {
                IdpReplyUrl = idpReplyUrl,
                SigningCertificate = Certificate.Load(),
                EnableOAuth2Endpoint = false,
                IdpRealm = idpRealm,
                CustomClaimsProvider = new DefaultCustomClaimsProvider()
            });
        }

        private const string IdpReplyUrlParam = "IdpReplyUrl";
        private const string IdpRealmParam = "IdpRealm";
    }
}

public class DefaultCustomClaimsProvider : ICustomClaimsProvider
{
    /// <summary>
    /// Claims transforms logic
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns></returns>
    public Task TransformAsync(CustomClaimsProviderContext context)
    {        
        context.OutgoingSubject.AddClaims(context.WindowsPrincipal.Claims);        
        return Task.FromResult(0);
    }
}