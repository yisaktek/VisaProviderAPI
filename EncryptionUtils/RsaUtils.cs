/*
 * *© Copyright 2021 Visa. All Rights Reserved.**
 *
 * NOTICE: The software and accompanying information and documentation (together, the “Software”) remain the property of
 * and are proprietary to Visa and its suppliers and affiliates. The Software remains protected by intellectual property
 * rights and may be covered by U.S. and foreign patents or patent applications. The Software is licensed and not sold.*
 *
 * By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (developer.visa.com/privacy).
 * In addition, all permissible uses of the Software must be in support of Visa products, programs and services provided
 * through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE SOFTWARE AND ANY ASSOCIATED
 * INFORMATION OR DOCUMENTATION IS PROVIDED ON AN “AS IS,” “AS AVAILABLE,” “WITH ALL FAULTS” BASIS WITHOUT WARRANTY OR
 * CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of their respective owners, used for identification purposes only, and do not imply
 * product endorsement or affiliation with Visa. Any links to third party sites are for your information only and equally
 * do not constitute a Visa endorsement. Visa has no insight into and control over third party content and code and disclaims
 * all liability for any such components, including continued availability and functionality. Benefits depend on implementation
 * details and business factors and coding steps shown are exemplary only and do not reflect all necessary elements for the
 * described capabilities. Capabilities and features are subject to Visa’s terms and conditions and may require development,
 * implementation and resources by you based on your business and operational details. Please refer to the specific
 * API documentation for details on the requirements, eligibility and geographic availability.*
 *
 * This Software includes programs, concepts and details under continuing development by Visa. Any Visa features,
 * functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa’s discretion.
 * The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa’s control,
 * including but not limited to deployment of necessary infrastructure by issuers, acquirers, merchants and mobile device manufacturers.
 *
 *
 *  This sample code is licensed only for use in a non-production environment for sandbox testing. See the license for all terms of use.
 */

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace EncryptionUtils
{
    public static class RsaUtils
    {
        /**
         * Load public pey from file. File should be a certificate in PEM format
         */
        public static RSA LoadPublicKeyFromFile(string certificatePath)
        {
            //  var cert = new X509Certificate2(certificatePath);
            string certThumbPrint = "b2086912c1abf1eca013a1f2d33b86616b5d0dbd";
            X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            // Try to open the store.

            certStore.Open(OpenFlags.ReadOnly);
            // Find the certificate that matches the thumbprint.
            X509Certificate2Collection certCollection = certStore.Certificates.Find(
                X509FindType.FindByThumbprint, certThumbPrint, false);
            certStore.Close();

            // Check to see if our certificate was added to the collection. If no, 
            // throw an error, if yes, create a certificate using it.
            if (0 == certCollection.Count)
            {
                Console.WriteLine("Error: No certificate found containing thumbprint ");
            }
            var certificate = certCollection.First();
            return certificate!.GetRSAPublicKey();
        }

        /**
         * Load private key from file. File should be a unencrypted private key in PEM format
         */
        public static RSA LoadPrivateKeyFromFile(string privateKeyFile) {
            try
            {
                var pemValue = System.Text.Encoding.Default.GetString(File.ReadAllBytes(privateKeyFile));
                var pr = new PemReader(new StringReader(pemValue));
                var keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
                var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

                var rsa = RSA.Create();
                rsa.ImportParameters(rsaParams);

                return rsa;
            }
            catch (Exception e)
            {
                Console.WriteLine("Unable to load private key file. " + e.Message);
                throw;
            }
        }
    }

}
