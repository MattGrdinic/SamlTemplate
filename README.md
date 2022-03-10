# CoreSAML2 SSO Middleware
This project implements the SAML2 login protocol for .NET Core clients. It was forked form the excellent https://github.com/dina-heidar/saml2-authentication, with small changes made to better handle *Manage Engines's* *ADSelfService Plus* implementation, as well as support dynamic providers such as https://github.com/Aguafrommars/DynamicAuthProviders. While ManageEngine and AD FS were our target systems, this library should work well with just about any Saml Idp. It has been tested on .NET Core 3.1 and .NET 6.
Note: This project does not yet support Single Logout (e.g, identity provider initiated logout). 

*ManageEngine can be downloaded and installed for free on your local machine. This makes local testing a snap.*

Most users will want the Nuget packge, which can be found by searching within Visual Studio for *CoreSAML2*. Visit the project's page here: https://www.nuget.org/packages/CoreSAML2/1.0.2

## SAML SSO Overview
In short: someone visits a location on your site you've designated as private. Seeing this, ASP.NET Core is wired *by us* to process this request as an authentication  "challenge". The challenge is to see if we have a universally agreed upon set of credentials for this system. If we possess those credentials the middleware let's us pass. If not, the middleware redirects the user to an Identity Provider (IdP) and presents a log in. If we pass this login on the external site, we're redirected back to the original site (what's called the Service Provider or SP) and can now access the originally requested resource. SSO is, really, just a bunch of redirects and XML processing.

## Sample Application
In addition to being a stand-along package, this Github project serves as a quick way to see the package implemented within a "real" application. The sample app includes CoreSAML2 as a *dependency*, meaning you have full source code access for debugging calls made within the library, and so on. To try this method simply download the source, update the appsettings.json file, and run.

## Nuget Users
For Nuget users, start by installing the CoreSAML2 Nuget package within your package manager, or from the command line: 

PM> `Install-Package CoreSAML2 -Version 1.0.0`

Next, create two folders in **wwwroot** called `Certificates` and `Certificates_Local`.

If using *ManageEngine*, your administrator will provide you with the `certificate.pem` and `metadata.xml` files for the given application -- place those into the proper `Certificate*` folder. We've created two folders here for easier testing but you do not need to follow this by any means. So long as your `appsettings.json` file is pointing to the correct location we'll be fine. One other quick note: Some SSO providers will simply provide a public URL to the metadata.xml location. That's ok as well, just make sure this location is properly defined in the `appsettings.json` file. 

Speaking of which, let's set that file up now...

Open `appsettings.json` and add this block just after the top of the opening brace:

```cs
"AppConfiguration": {
    "ServiceProvider": {
      "Certificate": "wwwroot/Certificates_Local/certificate.pem",
      "EntityId": "http://Dev-636:8888/iamapps/ssologin/custom_saml_app/70957d10ccd0dc54406244eefab27010079f12ad", // Change Both To Your IdP Instance.
      "LogoutUrl": "http://Dev-636:8888/iamapps/ssologout/custom_saml_app/70957d10ccd0dc54406244eefab27010079f12ad"
    },
    "IdentityProvider": {
      "MetadataAddress": "wwwroot/Certificates_Local/metadata.xml"
    }
  },
  ```
Critically, we must modify the *EntityId* and *LogoutUrl* parts to match our IdP's values. If using ManageEngine, these values are provided under Application > Configured Applications for Password Sync/Single Sign On > IdP Details.

As noted above, we can install ManageEngine locally, and if so, the values shown above will be very similar to what yours will be -- the difference being the computer name near the front and the identifier part at the end. Of course in production settings these values will almost always be simple URL's to your public SSO endpoint.

Next, take note of the `Certificate` and `MetadataAddress` values. 

For ManageEngine these values can simply be the files your administrator provided and you placed into the Certificates folder. However, for some SSO providers you'll actually need to use a URL, not the physical location of a file.

Finally, if using this in a containerized application please note Docker seems to remove all files outside of wwwroot. This is why we've added these files here.

Next, open Startup.cs and within *ConfigureServices*, add the following code:

```cs
// Authentication Middleware.

services.AddAuthentication(sharedOptions =>
{
    sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
}).AddSamlCore(options =>
{
    options.CallbackPath = "/Home"; // Assertion Consumer Service Url

    // SignOutPath- The endpoint for the idp to perform its signout action. default is "/signedout"
    options.SignOutPath = "/Logout";

    // EntityId (REQUIRED) - The Relying Party Identifier e.g. https://my.la.gov.local
    options.ServiceProvider.EntityId = Configuration["AppConfiguration:ServiceProvider:EntityId"];

    // There are two ways to provide Federation Metadata:

    // Option 1 - A FederationMetadata.xml already exists for your application.
    // In this case provide a URL or path to the metadata file.
    options.MetadataAddress = Configuration["AppConfiguration:IdentityProvider:MetadataAddress"];

    // Option 2: Have the middleware create the metadata file for you default is false.
    options.CreateMetadataFile = false;

    // If you want to specify the filename and path for the generated metadata file do so below:
    options.DefaultMetadataFileName = "metadata";
    options.DefaultMetadataFolderLocation = "Certificates";

    options.WantAuthnRequestsSigned = false;
    options.WantSignoutRequestsSigned = false;

    options.RequireMessageSigned = true;
    options.WantAssertionsSigned = false;

    // When true, allows for Personally Identifiable Information in error messages (In this case, keys). 
    options.EnablePIILogging = false;

    // (REQUIRED IF) signing AuthnRequest with Sp certificate to Idp. The value here is the certificate serial number.
    //if the certificate is in the project. make sure the path to to is correct. 
    //password value is needed to access private keys for signature and decryption.
    options.ServiceProvider.X509Certificate2 = new X509Certificate2(Configuration["AppConfiguration:ServiceProvider:Certificate"]);

    //if you want to search in cert store - can be used for production
    //options.ServiceProvider.X509Certificate2 = new Cryptography.X509Certificates.Extension.X509Certificate2(
    //    Configuration["AppConfiguration:ServiceProvider:CertificateSerialNumber"],
    //    StoreName.My,
    //    StoreLocation.LocalMachine,
    //    X509FindType.FindBySerialNumber);

    // Force Authentication (optional) - Is authentication required?
    options.ForceAuthn = true;

    // Service Provider Properties (optional) - These set the appropriate tags in the metadata.xml file
    options.ServiceProvider.ServiceName = "SSO";
    options.ServiceProvider.Language = "en-US";
    options.ServiceProvider.OrganizationDisplayName = "Org Name";
    options.ServiceProvider.OrganizationName = "Org Name";
    options.ServiceProvider.OrganizationURL = "https://sample.com";
    options.ServiceProvider.ContactPerson = new ContactType()
    {
        Company = "Company Name",
        GivenName = "Your Name",
        EmailAddress = new[] { "noone@noreply.com" },
        contactType = ContactTypeType.technical,
        TelephoneNumber = new[] { "" }
    };

    //Events - Modify events below if you want to log errors, add custom claims, etc.

    options.Events.OnRemoteFailure = context =>
    {
        return Task.FromResult(0);
    };

    options.Events.OnTicketReceived = context =>
    {
        // Process Custom Claims. For Us That Means Cleaning Up Identity.Name.

        var identity = context.Principal.Identity as ClaimsIdentity;

        var claims = context.Principal.Claims;

        if (claims.Any(c => c.Type == "first_name") && claims.Any(c => c.Type == "last_name"))
        {
            var first_name = claims.FirstOrDefault(c => c.Type == "first_name").Value;

            var last_name = claims.FirstOrDefault(c => c.Type == "last_name").Value;

            var name = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);

            identity.TryRemoveClaim(name);

            identity.AddClaim(new Claim(ClaimTypes.Name, first_name + " " + last_name));
        }

        return Task.FromResult(0);
    };
})

.AddCookie(opt =>
{
    opt.LoginPath = "/Home/ExternalLogin";
    opt.Cookie.SameSite = SameSiteMode.None;
    opt.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});
```

Immediately after adding this you'll almost certainly get several errors -- to fix simply mouse over the error and hover for a moment, and when the *Show potential fixes* menu displays select the top-most item for each.

You'll notice several areas where we can provide custom input values. You'll also note several options that control how the middleware processes requests. Again, we'e tried to provide sane values for ManageEngine, so small tweaks may be needed for other providers.

Next, just above *app.UseAuthorization();* in the *configure()* method, add:

```cs
app.UseAuthentication();
```

We're almost done!

Next, we need to add action methods to sign us in and out. These can go in almost any controller, for now we'll add them to `HomeController`:

```cs
[HttpGet]
[AllowAnonymous]
public ActionResult ExternalLogin(string provider = "Saml2", string returnUrl = null)
{
    // Request a redirect to the external login provider.
    if (returnUrl == null || Url.IsLocalUrl(returnUrl))
    {
        // Request a redirect to the external login provider.
        var redirectUrl = Url.Action("ExternalLoginCallback", "Home", new { ReturnUrl = returnUrl });
        var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
        properties.Items["LoginProviderKey"] = provider;
        return Challenge(properties, provider);
    }
    return RedirectToAction("Index", "Home");
}

[HttpGet]
[AllowAnonymous]
[Route("ExternalLoginCallback")]
public IActionResult ExternalLoginCallback(string returnUrl = null, string remoteError = null)
{
    if (Url.IsLocalUrl(returnUrl)) //e.g. user returning to confirm email
    {
        return LocalRedirect(returnUrl);
    }

    return RedirectToAction("Index", "Home");
}

[HttpGet]
[AllowAnonymous]
[Route("Logout")]
public async Task Logout(string returnUrl = null, string remoteError = null)
{
    // Remove All Session Cookies.

    var _dateString = DateTime.Now.AddDays(-1).ToString("ddd, dd MMM yyyy HH:mm:00") + " GMT";

    if (HttpContext.Request.Cookies.Count > 0)
    {
        var siteCookies = HttpContext.Request.Cookies.Where(c => c.Key.Contains(".AspNetCore.") || c.Key.Contains("Microsoft.Authentication"));

        foreach (var cookie in siteCookies)
        {
            Response.Cookies.Delete(cookie.Key);
        }
    }

    foreach (var cookie in Request.Cookies)
    {
        HttpContext.Response.Headers.Append(@"Set-Cookie", $"{cookie.Key}=reset; path=/; httponly=true; SameSite=none; Secure=true; expires={_dateString};");

        Response.Cookies.Delete(cookie.Key);
    }
            
    // The most important part!  
    var result = await HttpContext.AuthenticateAsync();
    var properties = result.Properties;
    var provider = properties.Items[".AuthScheme"];
    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await HttpContext.SignOutAsync(provider, properties);
}

```
As with above you'll no doubt get several errors after pasting that in -- no worries, just mouse over and select the recommended fix as before.

*Quick developer note here: Those last lines are the most important, as they're the ones that actually handle the logout process on the middleware's end.*

At this point we're ready to test our SSO implementation! To do so, select one of your current action methods (we'll use Privacy() in the HomeController), and decorate the method with the [Authorize] attribute. 

Build and run the project, and try visiting the page we added the auth attribute to. If all goes well you'll be redirected to the SSO provider.
