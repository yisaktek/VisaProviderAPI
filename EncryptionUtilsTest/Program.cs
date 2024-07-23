// See https://aka.ms/new-console-template for more information
using EncryptionUtils;
using Jose;

var a =new EncryptionTest();
a.EncryptDecryptUsingRsaTestclient_cert_a74fccb8();
a.EncryptDecryptUsingRsaTestserver_cert_414bc707();
a.EncryptDecryptUsingRsaTestserver_cert_a9eac();
a.EncryptDecryptUsingRsaTest();
Console.WriteLine("Hello, World!");

public class EncryptionTest
{
    public string payload2 = File.ReadAllText("payload.json");
    //public string payload2 =
    //    "{\r\n  \"recipientDetail\": {\r\n    \"lastName\": \"smith\",\r\n    \"firstName\": \"Jessica\",\r\n    \"bank\": {\r\n      \"bankCode\": \"800554\",\r\n      \"bankCodeType\": \"SORT_CODE\",\r\n      \"accountNumberType\": \"DEFAULT\",\r\n      \"accountName\": \"Money Market\",\r\n      \"countryCode\": \"GBR\",\r\n      \"bankName\": \"Barclays\",\r\n      \"accountNumber\": \"6970093\",\r\n      \"currencyCode\": \"GBP\"\r\n    },\r\n    \"address\": {\r\n      \"country\": \"GBR\",\r\n      \"city\": \"London\",\r\n      \"postalCode\": \"675456\",\r\n      \"addressLine1\": \"123 Main St\",\r\n      \"state\": \"CF\"\r\n    },\r\n    \"type\": \"I\"\r\n  },\r\n  \"senderDetail\": {\r\n    \"address\": {\r\n      \"country\": \"USA\",\r\n      \"city\": \"Washington\",\r\n      \"addressLine1\": \"addressline1\"\r\n    },\r\n    \"name\": \"Ben\",\r\n    \"type\": \"C\",\r\n    \"senderAccountNumber\": \"senderAccountNumber\"\r\n  },\r\n  \"payoutMethod\": \"B\",\r\n  \"transactionDetail\": {\r\n    \"initiatingPartyId\": 1002,\r\n    \"businessApplicationId\": \"FD\",\r\n    \"statementNarrative\": \"advancepayment\",\r\n    \"transactionAmount\": 1.5,\r\n    \"transactionCurrencyCode\": \"GBP\",\r\n    \"settlementCurrencyCode\": \"GBP\",\r\n    \"clientReferenceId\": \"888852397088\",\r\n    \"senderSourceOfFunds\": \"01\"\r\n  }\r\n}\r\n";

    public string ENCRYPTION_CERTIFICATE_PATH =
        @"C:\DEV\client_cert.pfx";
    public string ENCRYPTION_CERTIFICATE_PATH2_Server =
        @"C:\DEV\server_cert_a74fccb8-8198-4fc5-8bda-4ea124a91445.pem";

    public string ENCRYPTION_CERTIFICATE_PATH2_CLIENT =
        @"C:\DEV\client_cert_a74fccb8-8198-4fc5-8bda-4ea124a91445.pem";

    public string SIGNING_PRIVATE_KEY_PATH = @"C:\DEV\key_a74fccb8-8198-4fc5-8bda-4ea124a91445.pem";

    private string SIGNING_CERT_ID = "a74fccb8-8198-4fc5-8bda-4ea124a91445";
    public string ENCRYPTION_CERTIFICATE_ID = "a74fccb8-8198-4fc5-8bda-4ea124a91445";

    public void EncryptDecryptUsingRsaTest()
    {
       
        IDictionary<string, object> extraHeaders = new Dictionary<string, object>();
        extraHeaders.Add("iat", DateTime.Now.Millisecond);

        //1. Use Encryption Certificate (Public Key)
        var encryptionCertId = ENCRYPTION_CERTIFICATE_ID;
        var encPublicKey = RsaUtils.LoadPublicKeyFromFile(ENCRYPTION_CERTIFICATE_PATH2_Server);
     //   var jwe = EncryptionUtils.EncryptionUtils.CreateJweWithRsa(payload2, encryptionCertId, encPublicKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM, extraHeaders);
        var jwe = EncryptionUtils.EncryptionUtils.CreateJweWithRsa(payload2, encryptionCertId, encPublicKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A128GCM, extraHeaders);
        Console.WriteLine(jwe);



        //2. Use Private Key to sign the JWE and create the JWS
        var signingCertId = SIGNING_CERT_ID;
        var signingPrivateKey = RsaUtils.LoadPrivateKeyFromFile(SIGNING_PRIVATE_KEY_PATH);
        var jws = EncryptionUtils.EncryptionUtils.CreateJwsWithRsa(jwe, signingCertId, signingPrivateKey, JwsAlgorithm.RS256);
        Console.WriteLine(jws);


        //3. Use Signing Certificate to verify the JWS
        var publicKey = RsaUtils.LoadPublicKeyFromFile(ENCRYPTION_CERTIFICATE_PATH);
        var jweFromJws = EncryptionUtils.EncryptionUtils.VerifyJwsWithRsa(jws, publicKey);
        Console.WriteLine(jweFromJws);


        //4. Use Encryption Private Key to decrypt the JWE
        var encryptionPrivateKey = RsaUtils.LoadPrivateKeyFromFile(SIGNING_PRIVATE_KEY_PATH);
        var decryptedJwe = EncryptionUtils.EncryptionUtils.DecryptJweWithRsa(jweFromJws, encryptionPrivateKey);
        Console.WriteLine(decryptedJwe);
    }

    public void EncryptDecryptUsingRsaTestserver_cert_a9eac()
    {

        IDictionary<string, object> extraHeaders = new Dictionary<string, object>();
        extraHeaders.Add("iat", DateTime.Now.Millisecond);

        //1. Use Encryption Certificate (Public Key)
        var encryptionCertId = "a9eac5a6-a00b-45a4-8789-35aa22bf6dca";
        var encPublicKey = RsaUtils.LoadPublicKeyFromFile(@"C:\DEV\server_cert_a9eac5a6-a00b-45a4-8789-35aa22bf6dca.pem");
        //   var jwe = EncryptionUtils.EncryptionUtils.CreateJweWithRsa(payload2, encryptionCertId, encPublicKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM, extraHeaders);
        var jwe = EncryptionUtils.EncryptionUtils.CreateJweWithRsa(payload2, encryptionCertId, encPublicKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A128GCM, extraHeaders);
        Console.WriteLine(jwe);



        //2. Use Private Key to sign the JWE and create the JWS
        var signingCertId = SIGNING_CERT_ID;
        var signingPrivateKey = RsaUtils.LoadPrivateKeyFromFile(SIGNING_PRIVATE_KEY_PATH);
        var jws = EncryptionUtils.EncryptionUtils.CreateJwsWithRsa(jwe, signingCertId, signingPrivateKey, JwsAlgorithm.RS256);
        Console.WriteLine(jws);


        //3. Use Signing Certificate to verify the JWS
        var publicKey = RsaUtils.LoadPublicKeyFromFile(ENCRYPTION_CERTIFICATE_PATH);
        var jweFromJws = EncryptionUtils.EncryptionUtils.VerifyJwsWithRsa(jws, publicKey);
        Console.WriteLine(jweFromJws);


        //4. Use Encryption Private Key to decrypt the JWE
        var encryptionPrivateKey = RsaUtils.LoadPrivateKeyFromFile(SIGNING_PRIVATE_KEY_PATH);
        var decryptedJwe = EncryptionUtils.EncryptionUtils.DecryptJweWithRsa(jweFromJws, encryptionPrivateKey);
        Console.WriteLine(decryptedJwe);
    }



    public void EncryptDecryptUsingRsaTestserver_cert_414bc707()
    {

        IDictionary<string, object> extraHeaders = new Dictionary<string, object>();
        extraHeaders.Add("iat", DateTime.Now.Millisecond);

        //1. Use Encryption Certificate (Public Key)
        var encryptionCertId = "414bc707-efed-42f9-bba2-786ce544b7a6";
        var encPublicKey = RsaUtils.LoadPublicKeyFromFile(@"C:\DEV\server_cert_414bc707-efed-42f9-bba2-786ce544b7a6.pem");
        //   var jwe = EncryptionUtils.EncryptionUtils.CreateJweWithRsa(payload2, encryptionCertId, encPublicKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM, extraHeaders);
        var jwe = EncryptionUtils.EncryptionUtils.CreateJweWithRsa(payload2, encryptionCertId, encPublicKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A128GCM, extraHeaders);
        Console.WriteLine(jwe);



        //2. Use Private Key to sign the JWE and create the JWS
        var signingCertId = SIGNING_CERT_ID;
        var signingPrivateKey = RsaUtils.LoadPrivateKeyFromFile(SIGNING_PRIVATE_KEY_PATH);
        var jws = EncryptionUtils.EncryptionUtils.CreateJwsWithRsa(jwe, signingCertId, signingPrivateKey, JwsAlgorithm.RS256);
        Console.WriteLine(jws);


        //3. Use Signing Certificate to verify the JWS
        var publicKey = RsaUtils.LoadPublicKeyFromFile(ENCRYPTION_CERTIFICATE_PATH);
        var jweFromJws = EncryptionUtils.EncryptionUtils.VerifyJwsWithRsa(jws, publicKey);
        Console.WriteLine(jweFromJws);


        //4. Use Encryption Private Key to decrypt the JWE
        var encryptionPrivateKey = RsaUtils.LoadPrivateKeyFromFile(SIGNING_PRIVATE_KEY_PATH);
        var decryptedJwe = EncryptionUtils.EncryptionUtils.DecryptJweWithRsa(jweFromJws, encryptionPrivateKey);
        Console.WriteLine(decryptedJwe);
    }

    public void EncryptDecryptUsingRsaTestclient_cert_a74fccb8()
    {

        IDictionary<string, object> extraHeaders = new Dictionary<string, object>();
        extraHeaders.Add("iat", DateTime.Now.Millisecond);

        //1. Use Encryption Certificate (Public Key)
        var encryptionCertId = "a74fccb8-8198-4fc5-8bda-4ea124a91445";
        var encPublicKey = RsaUtils.LoadPublicKeyFromFile(@"C:\DEV\client_cert_a74fccb8-8198-4fc5-8bda-4ea124a91445.pem");
        //   var jwe = EncryptionUtils.EncryptionUtils.CreateJweWithRsa(payload2, encryptionCertId, encPublicKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM, extraHeaders);
        var jwe = EncryptionUtils.EncryptionUtils.CreateJweWithRsa(payload2, encryptionCertId, encPublicKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A128GCM, extraHeaders);
        Console.WriteLine(jwe);



        //2. Use Private Key to sign the JWE and create the JWS
        var signingCertId = SIGNING_CERT_ID;
        var signingPrivateKey = RsaUtils.LoadPrivateKeyFromFile(SIGNING_PRIVATE_KEY_PATH);
        var jws = EncryptionUtils.EncryptionUtils.CreateJwsWithRsa(jwe, signingCertId, signingPrivateKey, JwsAlgorithm.RS256);
        Console.WriteLine(jws);


        //3. Use Signing Certificate to verify the JWS
        var publicKey = RsaUtils.LoadPublicKeyFromFile(ENCRYPTION_CERTIFICATE_PATH);
        var jweFromJws = EncryptionUtils.EncryptionUtils.VerifyJwsWithRsa(jws, publicKey);
        Console.WriteLine(jweFromJws);


        //4. Use Encryption Private Key to decrypt the JWE
        var encryptionPrivateKey = RsaUtils.LoadPrivateKeyFromFile(SIGNING_PRIVATE_KEY_PATH);
        var decryptedJwe = EncryptionUtils.EncryptionUtils.DecryptJweWithRsa(jweFromJws, encryptionPrivateKey);
        Console.WriteLine(decryptedJwe);
    }

}

