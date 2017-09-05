using System;
using System.Threading.Tasks;
using Microsoft.Owin.Security.MicrosoftAccount;
using System.Security.Claims;
using IdentityServer3.Core;

namespace EmbeddedMvc
{
    internal class MSProvider : MicrosoftAccountAuthenticationProvider
    {
        public override Task Authenticated(MicrosoftAccountAuthenticatedContext context)
        {
            // In some cases (hotmail.com and others) the email is empty, but the email is in the userPrincipalName. 
            // Override with this. See https://github.com/aspnet/AspNetKatana/issues/107
            if (string.IsNullOrEmpty(context.Email) && context.User.GetValue("userPrincipalName") != null)
            {
                context.Identity.AddClaim(new Claim(Constants.ClaimTypes.Email, context.User.GetValue("userPrincipalName").ToString()));
            }
            return base.Authenticated(context);
            
        }
    }
}