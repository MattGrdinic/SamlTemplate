using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

using Models;
using System.Security.Cryptography.X509Certificates;
using CoreSaml.AspNetCore.Authentication.Saml2.Metadata;
using System.Security.Claims;

namespace SamlTemplate
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            // Session Support - Occasionally Throwing `CryptographicException` Warnings, Keep An Eye On.

            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(5);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.None;
            });

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

                // (REQUIRED IF) signing AuthnRequest with Sp certificate to Idp. The value here is the certifcate serial number.
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
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseSession();

            app.UseHttpsRedirection();

            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
