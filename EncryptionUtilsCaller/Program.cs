/*
 * (c) Copyright 2018 - 2020 Visa.All Rights Reserved.**
 *
 * NOTICE: The software and accompanying information and documentation(together, the "Software") remain the property of and are proprietary to Visa and its suppliers and affiliates.The Software remains protected by intellectual property rights and may be covered by U.S.and foreign patents or patent applications.The Software is licensed and not sold.*
 *
 *  By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (developer.visa.com/privacy).In addition, all permissible uses of the Software must be in support of Visa products, programs and services provided through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE SOFTWARE AND ANY ASSOCIATED INFORMATION OR DOCUMENTATION IS PROVIDED ON AN "AS IS," "AS AVAILABLE," "WITH ALL FAULTS" BASIS WITHOUT WARRANTY OR  CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of their respective owners, used for identification purposes only, and do not imply product endorsement or affiliation with Visa. Any links to third party sites are for your information only and equally  do not constitute a Visa endorsement. Visa has no insight into and control over third party content and code and disclaims all liability for any such components, including continued availability and functionality. Benefits depend on implementation details and business factors and coding steps shown are exemplary only and do not reflect all necessary elements for the described capabilities. Capabilities and features are subject to Visa's terms and conditions and may require development,implementation and resources by you based on your business and operational details. Please refer to the specific API documentation for details on the requirements, eligibility and geographic availability.*
 *
 * This Software includes programs, concepts and details under continuing development by Visa. Any Visa features, functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa"s discretion.The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa's control, including but not limited to deployment of necessary infrastructure by issuers, acquirers, merchants and mobile device manufacturers.*
 *
 */
using System.Net;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Diagnostics;
using Jose;
using Org.BouncyCastle.OpenSsl;

using Newtonsoft.Json;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;

using Org.BouncyCastle.Crypto.Parameters;

using Newtonsoft.Json.Linq;

namespace Vdp
{
    class Program
    {
        public static string visaUrl = "https://sandbox.api.visa.com/";
        public static string userId = "AW5XNTYSR310FFGPB9IV21J9Bh5A3o1rE58V0C29upmcF44_g";
        public static string password = "dmq40l3zIJuz";
        public static string cert = @"C:\DEV\client_cert.pfx";
        public static string certPassword = "carmentViza";

        //For MLE
        public static string keyId = "a74fccb8-8198-4fc5-8bda-4ea124a91445";
        public static string mleClientPrivateKey = @"C:\DEV\key_a74fccb8-8198-4fc5-8bda-4ea124a91445.pem";
        public static string mleServerPublicCertificate = @"C:\DEV\server_cert_a74fccb8-8198-4fc5-8bda-4ea124a91445.pem";

        static void Main(string[] args)
        {
            Program p = new Program();

            Console.WriteLine("Start Payout Validate\n");
            string decryptedPayloadValidate = p.ValidateTransactions(); 
            Console.WriteLine("Decrypted Payout Validate Response\n" + decryptedPayloadValidate);

            Console.WriteLine("\n\nStart Send Payout \n");
            string decryptedPayload = p.SendPayoutTransactions();
            Console.WriteLine("Decrypted Payout  Response\n" + decryptedPayload);


            //get Payout id payoutId
            var responseObj = JObject.Parse(decryptedPayload) as JToken;
            var initiatingPartyId = "1002";
            var payoutId = responseObj["transactionDetail"]["payoutId"].ToString();

            Console.WriteLine("\n\nStart Payout Query payoutId:\n" + payoutId);
            var queryResponse = p.Query(payoutId, initiatingPartyId);
            Console.WriteLine("payout Query Response:\n" + queryResponse);


            // var eleteResponse = p.Delete(payoutId, initiatingPartyId);
            Console.WriteLine("\n\nStart HellowWorld\n");
            string hi = p.HellowWorld();
            Console.WriteLine(" HellowWorld\n" + hi);
        }

        private void LogRequest(string url, string requestBody)
        {
            Console.WriteLine(url);
            Console.WriteLine(requestBody);
        }

        private void LogResponse(string info, HttpWebResponse response)
        {

            Debug.WriteLine(info);
            Console.WriteLine("Response Status: \n" + response.StatusCode);
            Console.WriteLine("Response Headers: \n" + response.Headers.ToString());

            Console.WriteLine("Response Body: \n" + GetResponseBody(response));
        }

        private string GetResponseBody(HttpWebResponse response)
        {
            string responseBody = "";
            using (var reader = new StreamReader(response.GetResponseStream(), ASCIIEncoding.Default))
            {
                responseBody = reader.ReadToEnd();
            }
            return responseBody;
        }

        //Correlation Id ( ex-correlation-id ) is an optional header while making an API call. You can skip passing the header while calling the API's.
        private string GetCorrelationId()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, 12).Select(s => s[random.Next(s.Length)]).ToArray()) + "_SC";

        }

        private string GetBasicAuthHeader(string userId, string password)
        {
            string authString = userId + ":" + password;
            var authStringBytes = Encoding.UTF8.GetBytes(authString);
            string authHeaderString = Convert.ToBase64String(authStringBytes);
            return "Basic " + authHeaderString;
        }

        public string DoMutualAuthCall(string path, string method, string testInfo, string requestBodyString, Dictionary<string, string> headers = null)
        {
            string requestURL = visaUrl + path;
            string certificatePath = cert;
            string certificatePassword = certPassword;
            string statusCode = "";
            string responseBody = "";
          //  LogRequest(requestURL, requestBodyString);
            // Create the POST request object 
            HttpWebRequest request = WebRequest.Create(requestURL) as HttpWebRequest;

            request.Method = method;
            if (method.Equals("POST") || method.Equals("PUT"))
            {
                request.ContentType = "application/json";
                request.Accept = "application/json";
                // Load the body for the post request
                var requestStringBytes = Encoding.UTF8.GetBytes(requestBodyString);
                request.GetRequestStream().Write(requestStringBytes, 0, requestStringBytes.Length);
            }

            if (headers != null)
            {
                foreach (KeyValuePair<string, string> header in headers)
                {
                    request.Headers[header.Key] = header.Value;
                }
            }

            // Add headers
            request.Headers["Authorization"] = GetBasicAuthHeader(userId, password);
            request.Headers["ex-correlation-id"] = GetCorrelationId();
            request.Headers["keyId"] = keyId;

            // Add certificate
            string certThumbPrint = "968cbce38877fafafa1500293da762beccf73cce";
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
            request.ClientCertificates.Add(certificate);
            try
            {
                // Make the call
                using (HttpWebResponse response = request.GetResponse() as HttpWebResponse)
                {
                    responseBody = GetResponseBody(response);
                   // LogResponse(testInfo, response);
                    statusCode = response.StatusCode.ToString();

                }
            }
            catch (WebException e)
            {
                Console.WriteLine(e.ToString());
                if (e.Response is HttpWebResponse)
                {
                    HttpWebResponse response = (HttpWebResponse)e.Response;
                    responseBody = GetResponseBody(response);
                  //  LogResponse(testInfo, response);
                    statusCode = response.StatusCode.ToString();
                }
            }
            return responseBody;
        }
        public string HellowWorld()
        {
            string requestURL = "vdp/helloworld";

            return DoMutualAuthCall(requestURL, "GET", "helloworld", null, null);
        }
        public string ValidateTransactions()
        {
            string localTransactionDateTime = DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss");
            string requestBody = File.ReadAllText("payload-ValidationSuccess.json");

            string requestURL = "visapayouts/v3/payouts/validate";
            
            return GetDecryptedPayload(DoMutualAuthCall(requestURL, "POST", "OCT With MLE", getEncryptedPayload(requestBody), null));
        }
        public string SendPayoutTransactions()
        {
            string localTransactionDateTime = DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss");
            string requestPayout = File.ReadAllText("payload.json");

            //init client
            var payload = JObject.Parse(requestPayout) as JToken;
            payload["transactionDetail"]["clientReferenceId"] = "111" + DateTime.UnixEpoch.Ticks.ToString();

            var requestBody = payload.ToString();

            string requestURL = "visapayouts/v3/payouts";

            return GetDecryptedPayload(DoMutualAuthCall(requestURL, "POST", "OCT With MLE", getEncryptedPayload(requestBody), null));
        }
        public string SendPayoutValidationResultTransactions()
        {
            string localTransactionDateTime = DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss");
            string requestBody = File.ReadAllText("payload.json");

            string requestURL = "visapayouts/v3/payouts";

            var token =
                "eyJjdHkiOiJhcHBsaWNhdGlvbi9qc29uIiwiZW5jIjoiQTEyOEdDTSIsImlhdCI6MTcyMTU0OTQyMTA5OSwiYWxnIjoiUlNBLU9BRVAtMjU2In0.glcmpzlVpyBHPo34FLPx8AY2ZTVTJknL9GxHljrfjZ5_7hf9_ElHNH-Ehr8XIK6lK-uJkLvz_FDPGUUnL8zNqRjgMRwn5eAM01omAD-z8H1p81VvSuSOYxVM-nZhojNucw_hqkYp-E6HSC2eMKsdMIFxz3n8CgGtcuioHW5FnWt9PGB_3y1fUR0DeS4y9_ZQfNz1_rls6rZ9cZxbzmvP_hoOs-T2t-PWwTthb7e1Mi7CpMLXtYOpMcb_LvBw-l2HWSGsf9Vbq9tlbKTrmzqiALomwOMuzLbRIu_wI39h8rpW-6TymCxkhS0crJxOLAnV2IWN6VPkiv2DfsLFG-dwVQ.yC9eUiUPlSqZJTwC.r3NMVKdduNoB1-AGumEmFyVRd5BfOVFO7WNwwt9tLP3caxvPtRZq_h4sThyv6MgBGE_0l5YU4VyPakBoIdLLo5YLCQ.jV00qkpa15d8Rjfjy_ijzg";
            var requestBody1 = "{\"encData\":\"" + token + "\"}";
            return GetDecryptedPayload(DoMutualAuthCall(requestURL, "POST", "OCT With MLE", requestBody1, null));
         
        }
        public string PushFundsTransactions()
        {
            string localTransactionDateTime = DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss");
            string requestBody = "{ \"acquirerCountryCode\": \"840\", \"acquiringBin\": \"408999\", \"amount\": \"124.05\", \"businessApplicationId\": \"AA\", \"cardAcceptor\": {   \"address\": {   \"country\": \"USA\",   \"county\": \"San Mateo\",   \"state\": \"CA\",   \"zipCode\": \"94404\"   },   \"idCode\": \"CA-IDCode-77765\",   \"name\": \"Visa Inc. USA-Foster City\",   \"terminalId\": \"TID-9999\" }, \"localTransactionDateTime\": \"" + localTransactionDateTime + "\", \"merchantCategoryCode\": \"6012\", \"pointOfServiceData\": {   \"motoECIIndicator\": \"0\",   \"panEntryMode\": \"90\",   \"posConditionCode\": \"00\" }, \"recipientName\": \"rohan\", \"recipientPrimaryAccountNumber\": \"4957030420210462\", \"retrievalReferenceNumber\": \"412770451018\", \"senderAccountNumber\": \"4957030420210454\", \"senderAddress\": \"901 Metro Center Blvd\", \"senderCity\": \"Foster City\", \"senderCountryCode\": \"124\", \"senderName\": \"Mohammed Qasim\", \"senderReference\": \"\", \"senderStateCode\": \"CA\", \"sourceOfFundsCode\": \"05\", \"systemsTraceAuditNumber\": \"451018\", \"transactionCurrencyCode\": \"USD\", \"transactionIdentifier\": \"381228649430015\" }";

            string requestURL = "visadirect/fundstransfer/v3/pushfundstransactions";

            return GetDecryptedPayload(DoMutualAuthCall(requestURL, "POST", "OCT With MLE", getEncryptedPayload(requestBody), null));
        }

        public string Query(string payoutId, string initiatingPartyId)
        {
            var queryString = "?id=" + payoutId + "&idType=PAYOUT_ID&initiatingPartyId=" + initiatingPartyId;
            var requestUrl = "visapayouts/v3/payouts" + queryString;

            return GetDecryptedPayload(DoMutualAuthCall(requestUrl, "GET", "payouts Query With MLE", null, null));
        }
        public string Delete(string payoutId, string initiatingPartyId)
        {
            var queryString = "?id=" + payoutId + "&idType=PAYOUT_ID&initiatingPartyId=" + initiatingPartyId;
            var requestUrl = "visapayouts/v3/payouts" + queryString;

            return GetDecryptedPayload(DoMutualAuthCall(requestUrl, "DELETE", "payouts DELETE With MLE", null, null));
        }
        private static string GetTimestamp()
        {
            long timeStamp = ((long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds) / 1000;
            return timeStamp.ToString();
        }
        private String getEncryptedPayload(String requestBody)
        {
            RSA clientCertificate = new X509Certificate2(mleServerPublicCertificate).GetRSAPublicKey();
            DateTime now = DateTime.UtcNow;
            long unixTimeMilliseconds = new DateTimeOffset(now).ToUnixTimeMilliseconds();
            IDictionary<string, object> extraHeaders = new Dictionary<string, object>{
                {"kid", keyId},{"iat",unixTimeMilliseconds}
            };
            string token = JWT.Encode(requestBody, clientCertificate, JweAlgorithm.RSA_OAEP_256, JweEncryption.A128GCM, null, extraHeaders);
            return "{\"encData\":\"" + token + "\"}";
        }

        private static String GetDecryptedPayload(String encryptedPayload)
        {
            var jsonPayload = JsonConvert.DeserializeObject<EncryptedPayload>(encryptedPayload);
            return JWT.Decode(jsonPayload.encData, ImportPrivateKey(mleClientPrivateKey));
        }

        private static RSA ImportPrivateKey(string privateKeyFile)
        {
            var pemValue = System.Text.Encoding.Default.GetString(File.ReadAllBytes(privateKeyFile));
            var pr = new PemReader(new StringReader(pemValue));
            var keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

            var rsa = RSA.Create();
            rsa.ImportParameters(rsaParams);

            return rsa;
        }

    }

    public class EncryptedPayload
    {
        public string encData { get; set; }
    }

}