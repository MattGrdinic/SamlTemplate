﻿//MIT License

//Copyright (c) 2018 Dina Heidar

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;

namespace CoreSaml.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso cref="RemoteAuthenticationHandler{Saml2Options}" />
    /// <seealso cref="IAuthenticationSignOutHandler" />
    public class Saml2Handler : RemoteAuthenticationHandler<Saml2Options>, IAuthenticationSignOutHandler
    {
        /// <summary>
        /// The correlation property
        /// </summary>
        private const string CorrelationProperty = ".xsrf";
        /// <summary>
        /// The configuration
        /// </summary>
        private Saml2Configuration _configuration;
        /// <summary>
        /// The saml2 service
        /// </summary>
        private readonly ISaml2Service _saml2Service;

        protected XmlDocument _xmlDoc;

        protected XmlNamespaceManager _xmlNameSpaceManager; //we need this one to run our XPath queries on the SAML XML

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2Handler" /> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="logger">The logger.</param>
        /// <param name="encoder">The encoder.</param>
        /// <param name="clock">The clock.</param>
        /// <param name="saml2Service">The saml2 service.</param>
        public Saml2Handler(
            IOptionsMonitor<Saml2Options> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ISaml2Service saml2Service
            )
           :
            base(options, logger, encoder, clock)
        {
            _saml2Service = saml2Service;
        }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new Saml2Events Events
        {
            get { return (Saml2Events)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        /// Creates a new instance of the events instance.
        /// </summary>
        /// <returns>
        /// A new instance of the events instance.
        /// </returns>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new Saml2Events());

        /// <summary>
        /// Handles the request asynchronous.
        /// </summary>
        /// <returns></returns>
        public override Task<bool> HandleRequestAsync()
        {
            if (Request.Path.Value.EndsWith(Options.SignOutPath, StringComparison.OrdinalIgnoreCase))
            {  // We've received a remote sign-out request
                return HandleRemoteSignOutAsync();
            }
            return base.HandleRequestAsync();
        }
        /// <summary>
        /// Override this method to deal with 401 challenge concerns, if an authentication scheme in question
        /// deals an authentication interaction as part of it's request flow. (like adding a response header, or
        /// changing the 401 result to 302 of a login page or external sign-in location.)
        /// </summary>
        /// <param name="properties"></param>
        /// <returns>
        /// A Task.
        /// </returns>
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (Options.Configuration == null)
            {
                Options.Configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
            }

            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            //string assertionHostUrl = new Uri(CurrentUri).Scheme + "://" + new Uri(CurrentUri).Authority;
            var sendAssertionTo = new Uri(new Uri(CurrentUri), Options.CallbackPath).AbsoluteUri;

            //prepare AuthnRequest ID, assertion Url and Relay State to prepare for Idp call 
            string authnRequestId = "id" + Guid.NewGuid().ToString("N");
            string assertionConsumerServiceUrl = sendAssertionTo;

            GenerateCorrelationId(properties);
            string relayState = Options.StateDataFormat.Protect(properties);

            //cleanup and remove existing cookies
            CookieOptions deleteCookieOptions = Options.RequestCookieId.Build(Context, Clock.UtcNow);
            Response.DeleteAllRequestIdCookies(Context.Request, deleteCookieOptions);

            //create and append new response cookie
            Options.RequestCookieId.Name = Options.AuthenticationScheme + relayState;
            Response.Cookies.Append(Options.RequestCookieId.Name, authnRequestId, Options.RequestCookieId.Build(Context));

            //create authnrequest call
            string authnRequest = _saml2Service.CreateAuthnRequest(Options, authnRequestId, relayState, assertionConsumerServiceUrl);

            //call idp
            Response.Redirect(authnRequest);
        }

        //response from identity provider hits here
        /// <summary>
        /// Authenticate the user identity with the identity provider.
        /// The method process the request on the endpoint defined by CallbackPath.
        /// </summary>
        /// <returns></returns>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small.
            if (HttpMethods.IsPost(Request.Method)
              && !string.IsNullOrEmpty(Request.ContentType)
              // May have media/type; charset=utf-8, allow partial match.
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead &&
              Request.Path.Value.EndsWith(Options.CallbackPath, StringComparison.OrdinalIgnoreCase))
            {
                return await HandleSignIn();
            }
            else
            {
                return HandleRequestResult.Fail("an error occured");
            }
        }

        //returns namespace manager, we need one b/c MS says so... Otherwise XPath doesnt work in an XML doc with namespaces
        //see https://stackoverflow.com/questions/7178111/why-is-xmlnamespacemanager-necessary
        private XmlNamespaceManager GetNamespaceManager()
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(_xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            return manager;
        }

        private bool ValidateSignatureReference(SignedXml signedXml)
        {
            if (signedXml.SignedInfo.References.Count != 1) //no ref at all
                return false;

            var reference = (Reference)signedXml.SignedInfo.References[0];
            var id = reference.Uri.Substring(1);

            var idElement = signedXml.GetIdElement(_xmlDoc, id);

            if (idElement == _xmlDoc.DocumentElement)
                return true;
            else //sometimes its not the "root" doc-element that is being signed, but the "assertion" element
            {
                var assertionNode = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion", _xmlNameSpaceManager) as XmlElement;
                if (assertionNode != idElement)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// LoadXML Document.
        /// </summary>
        /// <param name="xml"></param>
        public void LoadXml(string xml)
        {
            _xmlDoc = new XmlDocument();
            _xmlDoc.PreserveWhitespace = true;
            _xmlDoc.XmlResolver = null;
            _xmlDoc.LoadXml(xml);

            _xmlNameSpaceManager = GetNamespaceManager(); //lets construct a "manager" for XPath queries
        }

        /// <summary>
        /// Load XML From Base64 String.
        /// </summary>
        /// <param name="response"></param>
        public void LoadXmlFromBase64(string response)
        {
            UTF8Encoding enc = new UTF8Encoding();
            LoadXml(enc.GetString(Convert.FromBase64String(response)));
        }

        /// <summary>
        /// Handles the sign in.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="SecurityTokenException">No token validator was found for the given token.</exception>
        private async Task<HandleRequestResult> HandleSignIn()
        {
            if (Request.Method != HttpMethods.Post)
                return HandleRequestResult.Fail("Request method must be an HTTP-Post Method");

            var form = await Request.ReadFormAsync();

            var samlRequest = form[Saml2Constants.Parameters.SamlRequest];
            var response = form[Saml2Constants.Parameters.SamlResponse];
            var relayState = form[Saml2Constants.Parameters.RelayState].ToString()?.DeflateDecompress();

            // Check for logout requests to the login endpoint (Happens in AD FS when we loose a session).

            if (samlRequest.Count != 0)
            {
                try
                {
                    UTF8Encoding enc = new UTF8Encoding();
                    var raw = enc.GetString(Convert.FromBase64String(samlRequest)).ToString();

                    if (raw.Contains(Saml2Constants.ResponseTypes.LogoutRequest))
                    {
                        string redirectUrl = !string.IsNullOrEmpty(Options.UrlBase.ToString()) ? Options.UrlBase.ToString() : Options.CallbackPath.ToString();
                        Context.Response.Redirect(redirectUrl, true);
                        return HandleRequestResult.Handle();
                    }

                }
                catch { }
            }

            AuthenticationProperties authenticationProperties = Options.StateDataFormat.Unprotect(relayState);

            try
            {
                if (authenticationProperties == null)
                {
                    if (!Options.AllowUnsolicitedLogins)
                    {
                        return HandleRequestResult.Fail("Unsolicited logins are not allowed.");
                    }
                }

                if (authenticationProperties.Items.TryGetValue(CorrelationProperty, out string correlationId)
                        && !ValidateCorrelationId(authenticationProperties))
                {
                    return HandleRequestResult.Fail("Correlation failed.", authenticationProperties);
                }

                if (_configuration == null)
                {
                    _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
                    // Get configuration again to avoid timing issue where the configuration was null on the first call.
                    Options.Configuration = _configuration;
                }

                string base64EncodedSamlResponse = response;
                ResponseType idpSamlResponseToken = _saml2Service.GetSamlResponseToken(base64EncodedSamlResponse, Saml2Constants.ResponseTypes.AuthnResponse, Options);

                // Write To XML Doc `_xmlDoc` Object, This Step Is Critical For The ValidateToken Call Below.
                LoadXmlFromBase64(response);

                IRequestCookieCollection cookies = Request.Cookies;
                string originalSamlRequestId = cookies[cookies.Keys.FirstOrDefault(key => key.StartsWith(Options.AuthenticationScheme))];

                _saml2Service.CheckIfReplayAttack(idpSamlResponseToken.InResponseTo, originalSamlRequestId);
                _saml2Service.CheckStatus(idpSamlResponseToken);

                string token = _saml2Service.GetAssertion(idpSamlResponseToken, Options);

                AssertionType assertion = new AssertionType();
                XmlSerializer xmlSerializer = new XmlSerializer(typeof(AssertionType));
                using (MemoryStream memStm = new MemoryStream(Encoding.UTF8.GetBytes(token)))
                {
                    assertion = (AssertionType)xmlSerializer.Deserialize(memStm);
                }

                if (Options.WantAssertionsSigned)
                {
                    var doc = new XmlDocument
                    {
                        XmlResolver = null,
                        PreserveWhitespace = true
                    };
                    doc.LoadXml(token);

                    if (!_saml2Service.ValidateX509CertificateSignature(doc, Options))
                    {
                        throw new Exception("Assertion signature is not valid");
                    }
                }

                AuthnStatementType session = new AuthnStatementType();

                if (assertion.Items.Any(x => x.GetType() == typeof(AuthnStatementType)))
                {
                    session = (AuthnStatementType)assertion.Items.FirstOrDefault(x => x.GetType() == typeof(AuthnStatementType));
                }

                if (assertion.Subject.Items.Any(x => x.GetType() == typeof(NameIDType)))
                {
                    Options.NameIDType = (NameIDType)assertion.Subject.Items.FirstOrDefault(x => x.GetType() == typeof(NameIDType));
                }

                var tvp = Options.TokenValidationParameters.Clone();
                var validator = Options.Saml2SecurityTokenHandler;
                ClaimsPrincipal principal = null;
                SecurityToken parsedToken = null;

                var issuers = new[] { _configuration.Issuer };
                tvp.ValidateIssuerSigningKey = Options.WantAssertionsSigned;
                tvp.ValidateTokenReplay = !Options.IsPassive;
                tvp.ValidateIssuer = true;
                tvp.ValidateAudience = true;
                tvp.ValidIssuers = (tvp.ValidIssuers == null ? issuers : tvp.ValidIssuers.Concat(issuers));
                tvp.IssuerSigningKeys = (tvp.IssuerSigningKeys == null ? _configuration.SigningKeys : tvp.IssuerSigningKeys.Concat(_configuration.SigningKeys));

                if (!Options.WantAssertionsSigned) // in case they aren't signed
                {
                    tvp.RequireSignedTokens = false;
                }

                if (Options.EnablePIILogging)
                {
                    IdentityModelEventSource.ShowPII = true;
                }

                if (validator.CanReadToken(token))
                {
                    // Our Token Is Valid, Now Check Signaures.

                    var doc = new XmlDocument
                    {
                        XmlResolver = null,
                        PreserveWhitespace = true
                    };
                    doc.LoadXml(token);

                    // Pull Signatures.

                    XmlNodeList XMLSignatures = doc.GetElementsByTagName(Saml2Constants.Parameters.Signature, Saml2Constants.Namespaces.DsNamespace);

                    var signedXmlDoc = new SignedXml(doc);

                    signedXmlDoc.LoadXml((XmlElement)XMLSignatures[0]);

                    KeyInfoX509Data x509data = signedXmlDoc.Signature.KeyInfo.OfType<KeyInfoX509Data>().First();
                    X509Certificate2 cert = (X509Certificate2)x509data.Certificates[0];
                    string serialNumber = cert.SerialNumber;
                    X509Certificate2 _idpcert = Options.Configuration.X509Certificate2.Where(c => c.SerialNumber == serialNumber).FirstOrDefault();

                    var _xmlNameSpaceManager = GetNamespaceManager(); // Manager For XPath Queries.

                    // Important: To Check Signatures We Pull The Signature XML Node. 

                    // Critically This Check Differers From The ValidateToken Call Below, See Note.

                    XmlNodeList nodeList = _xmlDoc.SelectNodes(".//ds:Signature", _xmlNameSpaceManager);
                    SignedXml signedXml = new SignedXml(_xmlDoc);
                    signedXml.LoadXml((XmlElement)nodeList[0]);

                    var check_reference = ValidateSignatureReference(signedXml);
                    var check_signature = signedXml.CheckSignature(cert, true);

                    if (check_reference && check_signature)
                    {
                        // Tech Note: At This Point We've:

                        // 1. Verified The Token.
                        // 2. Verified The Signature Reference.
                        // 3. Verified The Signature For The Entire Document, And The Specific Assertion.

                        // The Final Step Is To Create Our Security Principal Via The ValidateToken() Call.

                        // The Big "Trick" Here Is This Call Is Known To Fail When The XML Source Is Not .NET.

                        // Specifically, The Signature Validation Process Requires The XML Byte Stream To Be Identical, 
                        // And Unfortunately Our Token Call Above, Among Other Things, Strips XML Namespaces And Changes Line Feeds. 

                        // To Address This We Pass This Call The "Original" XML From The LoadXmlFromBase64() Call Above.
                        try
                        {
                            XmlNodeList nodeListAssertion = _xmlDoc.SelectNodes(".//saml:Assertion", _xmlNameSpaceManager);

                            // This Call Maps Our SAML <saml2:AttributeStatement> Items To Our Identity As Claims.

                            principal = validator.ValidateToken(nodeListAssertion[0].OuterXml, tvp, out parsedToken);
                        }
                        catch (Exception e)
                        {
                            Debug.WriteLine(e.ToString());
                        }
                    }
                }

                if (principal == null)
                {
                    throw new SecurityTokenException("No token validator was found for the given token.");
                }

                if (Options.UseTokenLifetime && parsedToken != null)
                {
                    // Override any session persistence to match the token lifetime.
                    var issued = parsedToken.ValidFrom;
                    if (issued != DateTime.MinValue)
                    {
                        authenticationProperties.IssuedUtc = issued.ToUniversalTime();
                    }
                    var expires = parsedToken.ValidTo;
                    if (expires != DateTime.MinValue)
                    {
                        authenticationProperties.ExpiresUtc = expires.ToUniversalTime();
                    }
                    authenticationProperties.AllowRefresh = false;
                }

                ClaimsIdentity identity = new ClaimsIdentity(principal.Claims, Scheme.Name);

                session.SessionIndex = !String.IsNullOrEmpty(session.SessionIndex) ? session.SessionIndex : assertion.ID;

                //get the session index from assertion so you can use it to logout later
                identity.AddClaim(new Claim(Saml2ClaimTypes.SessionIndex, session.SessionIndex));

                // Create Entry For User.Identity.Name

                if (principal.Claims.Any(c => c.Type == ClaimTypes.NameIdentifier))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Name, principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value));
                }

                string redirectUrl = !string.IsNullOrEmpty(authenticationProperties.RedirectUri) ? authenticationProperties.RedirectUri : Options.CallbackPath.ToString();
                Context.Response.Redirect(redirectUrl, true);
                Context.User = new ClaimsPrincipal(identity);
                await Context.SignInAsync(Options.SignInScheme, Context.User, authenticationProperties);
                return HandleRequestResult.Success(new AuthenticationTicket(Context.User, authenticationProperties, Scheme.Name));
            }
            catch (Exception exception)
            {
                return HandleRequestResult.Fail(exception, authenticationProperties);
            }
        }

        /// <summary>
        /// Signout behavior.
        /// </summary>
        /// <param name="properties">The <see cref="T:Microsoft.AspNetCore.Authentication.AuthenticationProperties" /> that contains the extra meta-data arriving with the authentication.</param>
        /// <returns>
        /// A task.
        /// </returns>
        public async Task SignOutAsync(AuthenticationProperties properties)
        {
            properties.Items["redirectUri"] = Options.SignOutPath;

            var target = ResolveTarget(Options.ForwardSignOut);
            if (target != null)
            {
                await Context.SignOutAsync(target, properties);
                return;
            }
            if (Options.Configuration == null)
            {
                Options.Configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
            }

            string sendSignoutTo = new Uri(new Uri(CurrentUri), Options.SignOutPath).AbsoluteUri;

            // Prepare AuthnRequest ID, assertion Url and Relay State to prepare for Idp call 
            string logoutRequestId = "id" + Guid.NewGuid().ToString("N");
            GenerateCorrelationId(properties);
            string relayState = Options.StateDataFormat.Protect(properties);

            // Cleanup and remove existing cookies
            CookieOptions deleteCookieOptions = Options.RequestCookieId.Build(Context, Clock.UtcNow);
            Response.DeleteAllRequestIdCookies(Context.Request, deleteCookieOptions);

            // Create and append new response cookie
            Options.RequestCookieId.Name = Options.AuthenticationScheme + Options.SignOutPath.ToString().Replace("/", "") + relayState;
            Response.Cookies.Append(Options.RequestCookieId.Name, logoutRequestId, Options.RequestCookieId.Build(Context));
            string logoutRequest = "/";
            if (Options.hasCertificate)
            {
                //create logoutrequest call
                logoutRequest = _saml2Service.CreateLogoutRequest(Options, logoutRequestId, Context.User.FindFirst(Saml2ClaimTypes.SessionIndex).Value, Context.User.Identity.Name, relayState, sendSignoutTo);
            }
            // call idp
            Response.Redirect(logoutRequest, true);
        }

        /// <summary>
        /// Handles the remote sign out asynchronous.
        /// </summary>
        /// <returns></returns>
        protected virtual async Task<bool> HandleRemoteSignOutAsync()
        {
            if (Request.Method != HttpMethods.Post)
                return false;

            var form = await Request.ReadFormAsync();

            //check if it is an idp initiated logout request or a sn sp intiated logout request 
            //idp initated logout request. 
            //The idp sends this out when a user wants to logout from a session in anoher app.
            //it'll log them out of all other active sessions for other applications.
            if (_saml2Service.IsLogoutRequest(Context.Request))
            {
                //TODO
                return false;
            }

            //sp initated logout reqeuest. This is the response received from the idp as a result of the sp intiated logout request.
            var response = form[Saml2Constants.Parameters.SamlResponse];
            var relayState = form[Saml2Constants.Parameters.RelayState].ToString()?.DeflateDecompress();

            AuthenticationProperties authenticationProperties = Options.StateDataFormat.Unprotect(relayState);

            if(Options.Configuration == null)
            {
                _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
                Options.Configuration = _configuration;
            }

            string base64EncodedSamlResponse = response;
            ResponseType idpSamlResponseToken = _saml2Service.GetSamlResponseToken(base64EncodedSamlResponse, Saml2Constants.ResponseTypes.LogoutResponse, Options);

            IRequestCookieCollection cookies = Request.Cookies;
            string signoutSamlRequestId = cookies[cookies.Keys.FirstOrDefault(key => key.StartsWith(Options.AuthenticationScheme + Options.SignOutPath.ToString().Replace("/", "")))];

            _saml2Service.CheckIfReplayAttack(idpSamlResponseToken.InResponseTo, signoutSamlRequestId);
            _saml2Service.CheckStatus(idpSamlResponseToken);

            //check to see if successfully logged out from both app and idp
            if (Context.User.Identity.IsAuthenticated)
                return false;

            await Context.SignOutAsync(Options.SignOutScheme, authenticationProperties);

            var cookieOptions = Options.RequestCookieId.Build(Context, Clock.UtcNow);
            Context.Response.DeleteAllRequestIdCookies(Context.Request, cookieOptions);

            var redirectUrl = !string.IsNullOrEmpty(authenticationProperties.RedirectUri) ? authenticationProperties.RedirectUri : Options.DefaultRedirectUrl.ToString();

            Response.Redirect(redirectUrl, true);
            return true;
        }
    }
}