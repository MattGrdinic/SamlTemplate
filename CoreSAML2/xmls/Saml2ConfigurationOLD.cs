﻿////------------------------------------------------------------------------------
//// <auto-generated>
////     This code was generated by a tool.
////     Runtime Version:4.0.30319.42000
////
////     Changes to this file may cause incorrect behavior and will be lost if
////     the code is regenerated.
//// </auto-generated>
////------------------------------------------------------------------------------

//using System;
//using System.CodeDom.Compiler;
//using System.ComponentModel;
//using System.Diagnostics;
//using System.Xml.Serialization;

//// 
//// This source code was auto-generated by xsd, Version=4.6.1055.0.
//// 
//namespace SamlCore.AspNetCore.Authentication.Saml2
//{
//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
//    [XmlRootAttribute(ElementName = "AuthnRequest", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
//    public partial class Saml2ConfigurationOLD
//    {
//        private string extensionsField;

//        private string nameIDPolicyField;

//        private Issuer issuerField;

//        private Signature signatureField;

//        private Subject subjectField;

//        private Conditions conditionsField;

//        private AuthnRequestRequestedAuthnContext[] requestedAuthnContextField;

//        private AuthnRequestScoping[] scopingField;

//        private string idField;

//        private string versionField;

//        private string consentField;

//        private string issueInstantField;

//        private string destinationField;

//        private string forceAuthnField;

//        private string isPassiveField;

//        private string protocolBindingField;

//        private string assertionConsumerServiceURLField;

//        private string assertionConsumerServiceIndexField;

//        private string attributeConsumingServiceIndexField;

//        private string providerNameField;

//        /// <remarks/>
//        public string Extensions
//        {
//            get
//            {
//                return this.extensionsField;
//            }
//            set
//            {
//                this.extensionsField = value;
//            }
//        }

//        /// <remarks/>
//        public string NameIDPolicy
//        {
//            get
//            {
//                return this.nameIDPolicyField;
//            }
//            set
//            {
//                this.nameIDPolicyField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = true)]
//        public Issuer Issuer
//        {
//            get
//            {
//                return this.issuerField;
//            }
//            set
//            {
//                this.issuerField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
//        public Signature Signature
//        {
//            get
//            {
//                return this.signatureField;
//            }
//            set
//            {
//                this.signatureField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
//        public Subject Subject
//        {
//            get
//            {
//                return this.subjectField;
//            }
//            set
//            {
//                this.subjectField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
//        public Conditions Conditions
//        {
//            get
//            {
//                return this.conditionsField;
//            }
//            set
//            {
//                this.conditionsField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute("RequestedAuthnContext")]
//        public AuthnRequestRequestedAuthnContext[] RequestedAuthnContext
//        {
//            get
//            {
//                return this.requestedAuthnContextField;
//            }
//            set
//            {
//                this.requestedAuthnContextField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute("Scoping")]
//        public AuthnRequestScoping[] Scoping
//        {
//            get
//            {
//                return this.scopingField;
//            }
//            set
//            {
//                this.scopingField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string ID
//        {
//            get
//            {
//                return this.idField;
//            }
//            set
//            {
//                this.idField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string Version
//        {
//            get
//            {
//                return this.versionField;
//            }
//            set
//            {
//                this.versionField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string Consent
//        {
//            get
//            {
//                return this.consentField;
//            }
//            set
//            {
//                this.consentField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string IssueInstant
//        {
//            get
//            {
//                return this.issueInstantField;
//            }
//            set
//            {
//                this.issueInstantField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string Destination
//        {
//            get
//            {
//                return this.destinationField;
//            }
//            set
//            {
//                this.destinationField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string ForceAuthn
//        {
//            get
//            {
//                return this.forceAuthnField;
//            }
//            set
//            {
//                this.forceAuthnField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string IsPassive
//        {
//            get
//            {
//                return this.isPassiveField;
//            }
//            set
//            {
//                this.isPassiveField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string ProtocolBinding
//        {
//            get
//            {
//                return this.protocolBindingField;
//            }
//            set
//            {
//                this.protocolBindingField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string AssertionConsumerServiceURL
//        {
//            get
//            {
//                return this.assertionConsumerServiceURLField;
//            }
//            set
//            {
//                this.assertionConsumerServiceURLField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string AssertionConsumerServiceIndex
//        {
//            get
//            {
//                return this.assertionConsumerServiceIndexField;
//            }
//            set
//            {
//                this.assertionConsumerServiceIndexField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string AttributeConsumingServiceIndex
//        {
//            get
//            {
//                return this.attributeConsumingServiceIndexField;
//            }
//            set
//            {
//                this.attributeConsumingServiceIndexField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string ProviderName
//        {
//            get
//            {
//                return this.providerNameField;
//            }
//            set
//            {
//                this.providerNameField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
//    [XmlRootAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = true)]
//    public partial class Issuer
//    {

//        private string nameQualifierField;

//        private string sPNameQualifierField;

//        private string formatField;

//        private string sPProvidedIDField;

//        private string valueField;

//        /// <remarks/>
//        [System.Xml.Serialization.XmlAttributeAttribute()]
//        public string NameQualifier
//        {
//            get
//            {
//                return this.nameQualifierField;
//            }
//            set
//            {
//                this.nameQualifierField = value;
//            }
//        }

//        /// <remarks/>
//        [System.Xml.Serialization.XmlAttributeAttribute()]
//        public string SPNameQualifier
//        {
//            get
//            {
//                return this.sPNameQualifierField;
//            }
//            set
//            {
//                this.sPNameQualifierField = value;
//            }
//        }

//        /// <remarks/>
//        [System.Xml.Serialization.XmlAttributeAttribute()]
//        public string Format
//        {
//            get
//            {
//                return this.formatField;
//            }
//            set
//            {
//                this.formatField = value;
//            }
//        }

//        /// <remarks/>
//        [System.Xml.Serialization.XmlAttributeAttribute()]
//        public string SPProvidedID
//        {
//            get
//            {
//                return this.sPProvidedIDField;
//            }
//            set
//            {
//                this.sPProvidedIDField = value;
//            }
//        }

//        /// <remarks/>
//        [System.Xml.Serialization.XmlTextAttribute()]
//        public string Value
//        {
//            get
//            {
//                return this.valueField;
//            }
//            set
//            {
//                this.valueField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.w3.org/2000/09/xmldsig#")]
//    [XmlRootAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
//    public partial class Signature
//    {

//        private string signatureValueField;

//        private string objectField;

//        private SignatureSignedInfo[] signedInfoField;

//        private SignatureKeyInfoX509Data[][] keyInfoField;

//        /// <remarks/>
//        public string SignatureValue
//        {
//            get
//            {
//                return this.signatureValueField;
//            }
//            set
//            {
//                this.signatureValueField = value;
//            }
//        }

//        /// <remarks/>
//        public string Object
//        {
//            get
//            {
//                return this.objectField;
//            }
//            set
//            {
//                this.objectField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute("SignedInfo")]
//        public SignatureSignedInfo[] SignedInfo
//        {
//            get
//            {
//                return this.signedInfoField;
//            }
//            set
//            {
//                this.signedInfoField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlArrayItemAttribute("X509Data", typeof(SignatureKeyInfoX509Data), IsNullable = false)]
//        public SignatureKeyInfoX509Data[][] KeyInfo
//        {
//            get
//            {
//                return this.keyInfoField;
//            }
//            set
//            {
//                this.keyInfoField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.w3.org/2000/09/xmldsig#")]
//    public partial class SignatureSignedInfo
//    {

//        private SignatureSignedInfoCanonicalizationMethod[] canonicalizationMethodField;

//        private SignatureSignedInfoSignatureMethod[] signatureMethodField;

//        private SignatureSignedInfoReference[] referenceField;

//        /// <remarks/>
//        [XmlElementAttribute("CanonicalizationMethod")]
//        public SignatureSignedInfoCanonicalizationMethod[] CanonicalizationMethod
//        {
//            get
//            {
//                return this.canonicalizationMethodField;
//            }
//            set
//            {
//                this.canonicalizationMethodField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute("SignatureMethod")]
//        public SignatureSignedInfoSignatureMethod[] SignatureMethod
//        {
//            get
//            {
//                return this.signatureMethodField;
//            }
//            set
//            {
//                this.signatureMethodField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute("Reference")]
//        public SignatureSignedInfoReference[] Reference
//        {
//            get
//            {
//                return this.referenceField;
//            }
//            set
//            {
//                this.referenceField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.w3.org/2000/09/xmldsig#")]
//    public partial class SignatureSignedInfoCanonicalizationMethod
//    {

//        private string algorithmField;

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string Algorithm
//        {
//            get
//            {
//                return this.algorithmField;
//            }
//            set
//            {
//                this.algorithmField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.w3.org/2000/09/xmldsig#")]
//    public partial class SignatureSignedInfoSignatureMethod
//    {

//        private string algorithmField;

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string Algorithm
//        {
//            get
//            {
//                return this.algorithmField;
//            }
//            set
//            {
//                this.algorithmField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.w3.org/2000/09/xmldsig#")]
//    public partial class SignatureSignedInfoReference
//    {

//        private string digestValueField;

//        private SignatureSignedInfoReferenceTransformsTransform[][] transformsField;

//        private SignatureSignedInfoReferenceDigestMethod[] digestMethodField;

//        private string uRIField;

//        /// <remarks/>
//        public string DigestValue
//        {
//            get
//            {
//                return this.digestValueField;
//            }
//            set
//            {
//                this.digestValueField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlArrayItemAttribute("Transform", typeof(SignatureSignedInfoReferenceTransformsTransform), IsNullable = false)]
//        public SignatureSignedInfoReferenceTransformsTransform[][] Transforms
//        {
//            get
//            {
//                return this.transformsField;
//            }
//            set
//            {
//                this.transformsField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute("DigestMethod")]
//        public SignatureSignedInfoReferenceDigestMethod[] DigestMethod
//        {
//            get
//            {
//                return this.digestMethodField;
//            }
//            set
//            {
//                this.digestMethodField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string URI
//        {
//            get
//            {
//                return this.uRIField;
//            }
//            set
//            {
//                this.uRIField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.w3.org/2000/09/xmldsig#")]
//    public partial class SignatureSignedInfoReferenceTransformsTransform
//    {

//        private string algorithmField;

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string Algorithm
//        {
//            get
//            {
//                return this.algorithmField;
//            }
//            set
//            {
//                this.algorithmField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.w3.org/2000/09/xmldsig#")]
//    public partial class SignatureSignedInfoReferenceDigestMethod
//    {

//        private string algorithmField;

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string Algorithm
//        {
//            get
//            {
//                return this.algorithmField;
//            }
//            set
//            {
//                this.algorithmField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.w3.org/2000/09/xmldsig#")]
//    public partial class SignatureKeyInfoX509Data
//    {

//        private string x509CertificateField;

//        /// <remarks/>
//        public string X509Certificate
//        {
//            get
//            {
//                return this.x509CertificateField;
//            }
//            set
//            {
//                this.x509CertificateField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
//    [XmlRootAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
//    public partial class Subject
//    {

//        private string nameIDField;

//        private SubjectSubjectConfirmation[] subjectConfirmationField;

//        /// <remarks/>
//        public string NameID
//        {
//            get
//            {
//                return this.nameIDField;
//            }
//            set
//            {
//                this.nameIDField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute("SubjectConfirmation")]
//        public SubjectSubjectConfirmation[] SubjectConfirmation
//        {
//            get
//            {
//                return this.subjectConfirmationField;
//            }
//            set
//            {
//                this.subjectConfirmationField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
//    public partial class SubjectSubjectConfirmation
//    {

//        private string baseIDField;

//        private string subjectConfirmationDataField;

//        private string methodField;

//        /// <remarks/>
//        public string BaseID
//        {
//            get
//            {
//                return this.baseIDField;
//            }
//            set
//            {
//                this.baseIDField = value;
//            }
//        }

//        /// <remarks/>
//        public string SubjectConfirmationData
//        {
//            get
//            {
//                return this.subjectConfirmationDataField;
//            }
//            set
//            {
//                this.subjectConfirmationDataField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string Method
//        {
//            get
//            {
//                return this.methodField;
//            }
//            set
//            {
//                this.methodField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
//    [XmlRootAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
//    public partial class Conditions
//    {

//        private string conditionField;

//        private ConditionsAudienceRestriction audienceRestrictionField;

//        /// <remarks/>
//        public string Condition
//        {
//            get
//            {
//                return this.conditionField;
//            }
//            set
//            {
//                this.conditionField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute(Form = System.Xml.Schema.XmlSchemaForm.Unqualified)]
//        public ConditionsAudienceRestriction AudienceRestriction
//        {
//            get
//            {
//                return this.audienceRestrictionField;
//            }
//            set
//            {
//                this.audienceRestrictionField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
//    public partial class ConditionsAudienceRestriction
//    {

//        private string audienceField;

//        /// <remarks/>
//        [XmlElementAttribute(Form = System.Xml.Schema.XmlSchemaForm.Unqualified)]
//        public string Audience
//        {
//            get
//            {
//                return this.audienceField;
//            }
//            set
//            {
//                this.audienceField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
//    public partial class AuthnRequestRequestedAuthnContext
//    {

//        private string authnContextClassRefField;

//        /// <remarks/>
//        [XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
//        public string AuthnContextClassRef
//        {
//            get
//            {
//                return this.authnContextClassRefField;
//            }
//            set
//            {
//                this.authnContextClassRefField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
//    public partial class AuthnRequestScoping
//    {

//        private string requesterIDField;

//        private AuthnRequestScopingIDPList[] iDPListField;

//        /// <remarks/>
//        public string RequesterID
//        {
//            get
//            {
//                return this.requesterIDField;
//            }
//            set
//            {
//                this.requesterIDField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute("IDPList")]
//        public AuthnRequestScopingIDPList[] IDPList
//        {
//            get
//            {
//                return this.iDPListField;
//            }
//            set
//            {
//                this.iDPListField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
//    public partial class AuthnRequestScopingIDPList
//    {

//        private string getCompleteField;

//        private AuthnRequestScopingIDPListIDPEntry[] iDPEntryField;

//        /// <remarks/>
//        public string GetComplete
//        {
//            get
//            {
//                return this.getCompleteField;
//            }
//            set
//            {
//                this.getCompleteField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlElementAttribute("IDPEntry")]
//        public AuthnRequestScopingIDPListIDPEntry[] IDPEntry
//        {
//            get
//            {
//                return this.iDPEntryField;
//            }
//            set
//            {
//                this.iDPEntryField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
//    public partial class AuthnRequestScopingIDPListIDPEntry
//    {

//        private string providerIDField;

//        private string nameField;

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string ProviderID
//        {
//            get
//            {
//                return this.providerIDField;
//            }
//            set
//            {
//                this.providerIDField = value;
//            }
//        }

//        /// <remarks/>
//        [XmlAttributeAttribute()]
//        public string Name
//        {
//            get
//            {
//                return this.nameField;
//            }
//            set
//            {
//                this.nameField = value;
//            }
//        }
//    }

//    /// <remarks/>
//    [GeneratedCodeAttribute("xsd", "4.6.1055.0")]
//    [SerializableAttribute()]
//    [DebuggerStepThroughAttribute()]
//    [DesignerCategoryAttribute("code")]
//    [XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
//    [XmlRootAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
//    public partial class NewDataSet
//    {

//        private Saml2Configuration[] itemsField;

//        /// <remarks/>
//        [System.Xml.Serialization.XmlElementAttribute("AuthnRequest")]
//        public Saml2Configuration[] Items
//        {
//            get
//            {
//                return this.itemsField;
//            }
//            set
//            {
//                this.itemsField = value;
//            }
//        }
//    }
//}