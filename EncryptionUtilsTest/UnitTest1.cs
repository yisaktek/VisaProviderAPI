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
using System.Collections.Generic;
using EncryptionUtils;
using Jose;
using NUnit.Framework;
using static EncryptionUtils.EncryptionUtils;

namespace EncryptionUtilsTest
{
    public class Tests
    {
        private string payload = "<PAYLOAD>";
        
        [SetUp]
        public void Setup()
        {
        }

        /**
         * This is an example of using RSA Public Key and Private Key for asymmetric encryption and decryption
         */
        [Test]
        public void EncryptDecryptUsingRsaTest()
        {
            IDictionary<string, object> extraHeaders = new Dictionary<string, object>();
            extraHeaders.Add("iat", DateTime.Now.Millisecond);
            
            //1. Use Encryption Certificate (Public Key)
            var encryptionCertId = "<ENCRYPTION_CERTIFICATE_ID";
            var encPublicKey = RsaUtils.LoadPublicKeyFromFile("<ENCRYPTION_CERTIFICATE_PATH>");
            var jwe = CreateJweWithRsa(payload, encryptionCertId, encPublicKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM, extraHeaders);
            Console.WriteLine(jwe);
            
            //2. Use Private Key to sign the JWE and create the JWS
            var signingCertId = "<SIGNING_CERT_ID>";
            var signingPrivateKey = RsaUtils.LoadPrivateKeyFromFile("<SIGNING_PRIVATE_KEY>");
            var jws = CreateJwsWithRsa(jwe, signingCertId, signingPrivateKey, JwsAlgorithm.RS256);
            Console.WriteLine(jws);

            //3. Use Signing Certificate to verify the JWS
            var publicKey = RsaUtils.LoadPublicKeyFromFile("<CERTIFICATE_FILE_PATH>");
            var jweFromJws = VerifyJwsWithRsa(jws, publicKey);
            Console.WriteLine(jweFromJws);
            
            //4. Use Encryption Private Key to decrypt the JWE
            var encryptionPrivateKey = RsaUtils.LoadPrivateKeyFromFile("<PRIVATE_KEY_FILE_PATH>");
            var decryptedJwe = DecryptJweWithRsa(jweFromJws, encryptionPrivateKey);
            Console.WriteLine(decryptedJwe);
        }

        /**
         * This is an example of the code usage for Symmetric Encryption Decryption Using Shared Secret
         *   1. To create a jwe,
         *   2. Sign the jwe to get the jws
         *   3. Verify the JWS
         *   4. Decrypt the JWE
         */
        [Test]
        public void EncryptDecryptUsingSharedSecretTest()
        {
            var apiKey = Guid.NewGuid().ToString();
            var sharedSecret = Guid.NewGuid().ToString();
            var jwe = CreateJwe(payload, apiKey, sharedSecret);
            Console.WriteLine("JWE: "  + jwe);

            var signingKid = Guid.NewGuid().ToString();
            var signingSharedSecret = Guid.NewGuid().ToString();
            var jws = CreateJws(jwe, signingKid, signingSharedSecret);
            Console.WriteLine("JWS: " + jws);

            var jweAfterVerifyingJws = VerifyJws(jws, signingSharedSecret);
            Console.WriteLine("JWE after verifying JWS: " + jweAfterVerifyingJws);

            var decryptedJwe = DecryptJwe(jwe, sharedSecret);
            Console.WriteLine("Decrypted JWE: " + decryptedJwe);

            Assert.AreEqual(payload, decryptedJwe);
        }
    }
}