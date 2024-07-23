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

using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Jose;

namespace EncryptionUtils
{
    public struct EncryptionUtils
    {

        /**
         * Create JWE Using API & Shared Secret (Symmetric Encryption)
         * apiKey = a74fccb8-8198-4fc5-8bda-4ea124a91445
         */

        public static string CreateJwe(string payload, string apiKey, string sharedSecret, 
            JweAlgorithm  jweAlgorithm = JweAlgorithm.A256GCMKW,
            JweEncryption jweEncryption = JweEncryption.A256GCM,
            IDictionary<string, object> extraHeaders = null)
        {
            var secretKey = GetHash(SHA256.Create(), sharedSecret);
            
            IDictionary<string, object> jweHeaders = new Dictionary<string, object>();
            jweHeaders.Add("kid", apiKey);

            if (extraHeaders != null && extraHeaders.Count > 0) {
                foreach (var (key, value) in extraHeaders) {
                    jweHeaders.Add(key, value); 
                }
            }
            return JWT.Encode(payload, secretKey, jweAlgorithm, jweEncryption, null, jweHeaders);
        }

        /**
         * Sign a JWE using Shared Secret
         */
        public static string CreateJws(string jwe, string signingKid, string signingSharedSecret, 
            JwsAlgorithm jwsAlgorithm = JwsAlgorithm.HS256, 
            IDictionary<string, object> extraHeaders = null)
        {
            var secretKey = GetHash(SHA256.Create(), signingSharedSecret);
            IDictionary<string, object> jweHeaders = new Dictionary<string, object>{
                {"kid", signingKid},{"type", "JOSE"}, {"cty", "JWE"}
            };
            
            if (extraHeaders != null && extraHeaders.Count > 0) {
                foreach (var (key, value) in extraHeaders) {
                    jweHeaders.Add(key, value);
                }
            }
            return JWT.Encode(jwe, secretKey, jwsAlgorithm, extraHeaders: jweHeaders);
        }

        /**
         * Verify a JWS Using Shared Secret (Symmetric Encryption) and return the JWE
         */
        public static string VerifyJws(string jws, string signingSharedSecret)
        {
            var secretKey = GetHash(SHA256.Create(), signingSharedSecret);
            return JWT.Decode(jws, secretKey);
        }

        /**
         * Create JWE Using RSA PKI (public key
         */
        public static string CreateJweWithRsa(string payload, string encryptionCertId, RSA publicKey, 
            JweAlgorithm  jweAlgorithm,
            JweEncryption jweEncryption,
            IDictionary<string, object> extraHeaders = null) 
        {
            IDictionary<string, object> jweHeaders = new Dictionary<string, object>();
            jweHeaders.Add("type", "JOSE");
            jweHeaders.Add("kid", encryptionCertId);

            if (extraHeaders != null && extraHeaders.Count > 0) {
                foreach (var (key, value) in extraHeaders) {
                    jweHeaders.Add(key, value); 
                }
            }
            return JWT.Encode(payload, publicKey, jweAlgorithm, jweEncryption, null, jweHeaders);
        }
        
        /**
         * Decrypt JWE Using Shared Secret (Symmetric Decryption)
         */
        public static string DecryptJwe(string jweStr, string sharedSecret)
        {
            var secretKey = GetHash(SHA256.Create(), sharedSecret);
            return JWT.Decode(jweStr, secretKey);
        }

        /**
         * Decrypt JWE Using RSA PKI (private key)
         */
        public static string DecryptJweWithRsa(string jweStr, RSA privateKey)
        {
            return JWT.Decode(jweStr, privateKey);
        }

        /**
         * Create JWS - Sign JWE Using RSA PKI
         */
        public static string CreateJwsWithRsa(string jwe, string signingKid, RSA privateKey, JwsAlgorithm jwsAlgorithm, 
            IDictionary<string, object> extraHeaders = null) {
            IDictionary<string, object> jweHeaders = new Dictionary<string, object>{
                {"kid", signingKid},{"type", "JOSE"}, {"cty", "JWE"}
            };
            
            if (extraHeaders != null && extraHeaders.Count > 0) {
                foreach (var (key, value) in extraHeaders) {
                    jweHeaders.Add(key, value);
                }
            }
            return JWT.Encode(jwe, privateKey, jwsAlgorithm, jweHeaders);
        }

        /**
         * Verify the JWS Using RSA PKI (Public Key)
         */
        public static string VerifyJwsWithRsa(string jws, RSA publicKey) {
            return JWT.Decode(jws, publicKey);
        }

        /**
         * Create a hash using a hash algorithm
         */
        private static byte[] GetHash(HashAlgorithm hashAlgorithm, string input)
        {
            // Convert the input string to a byte array and compute the hash.
            return hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(input));
        }
    }
}