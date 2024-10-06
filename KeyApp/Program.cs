/*
using System;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        using (RSA rsa = RSA.Create(2048)) // Generate a 2048-bit RSA key pair
        {
            // Export the public key
            var publicKey = rsa.ToXmlString(false); // false means export only the public key
            Console.WriteLine("Public Key:");
            Console.WriteLine(publicKey);

            // Export the private key
            var privateKey = rsa.ToXmlString(true); // true means export the private key
            Console.WriteLine("Private Key:");
            Console.WriteLine(privateKey);
        }
    }
}
*/
/*
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static void Main()
    {
        using (RSA rsa = RSA.Create(2048))
        {
            // Create a certificate request
            var request = new CertificateRequest(
                "CN=trackabet.online, O=Software Boutique, C=ZA",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            // Generate the CSR
            byte[] csrBytes = request.CreateSigningRequest();
            string csr = Convert.ToBase64String(csrBytes);

            // Save CSR to a file
            System.IO.File.WriteAllText(@"C:\certs\request.csr", csr);


            Console.WriteLine("CSR has been generated and saved as request.csr.");
        }
    }
}
*/
/*
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static void Main()
    {
        // Load your certificate and private key
        var certificate = new X509Certificate2(@"C:\certs\certificate.crt");
        var privateKey = new X509Certificate2(@"C:\certs\private.key", "$Tinkerbell1");

        // Create a new .pfx file
        var pfx = new X509Certificate2(certificate.Export(X509ContentType.Pfx, "$Tinkerbell1"), "$Tinkerbell1");
        System.IO.File.WriteAllBytes(@"C:\certs\certificate.pfx", pfx.Export(X509ContentType.Pfx, "$Tinkerbell1"));
    }
}

*/
/*
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static void Main()
    {
        string certPath = "path/to/your/certificate.pem"; // Path to your PEM certificate
        string keyPath = "path/to/your/private_key.pem"; // Path to your private key
        string outputPath = "path/to/output/certificate.pfx"; // Output PFX file path
        string pfxPassword = "$Tinkerbell1"; // Password for the PFX file

        // Load the certificate
        var cert = new X509Certificate2(certPath);

        // Load the private key (for demonstration, we assume it is in PEM format)
        string privateKeyPem = File.ReadAllText(keyPath);
        var privateKey = new X509Certificate2(Convert.FromBase64String(privateKeyPem));

        // Combine certificate and private key into a .pfx file
        var pfx = new X509Certificate2(cert.Export(X509ContentType.Pfx, pfxPassword), pfxPassword);

        // Save the .pfx file
        File.WriteAllBytes(outputPath, pfx.Export(X509ContentType.Pfx, pfxPassword));

        Console.WriteLine("PFX file created successfully at: " + outputPath);
    }
}
*/
/*
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;

class Program
{
    static void Main()
    {
        using (RSA rsa = RSA.Create(2048))
        {
            // Generate a CSR
            var request = new CertificateRequest(
               "CN=trackabet.online, O=Software Boutique, C=ZA",
               rsa,
               HashAlgorithmName.SHA256,
               RSASignaturePadding.Pkcs1);            
            var csrBytes = request.CreateSigningRequest();
            File.WriteAllText(@"C:\certs2\request.csr", Convert.ToBase64String(csrBytes));
            Console.WriteLine("CSR has been generated.");

            // Export the private key to a PEM file
            File.WriteAllText(@"C:\certs2\private_key.pem", Convert.ToBase64String(rsa.ExportRSAPrivateKey()));
            Console.WriteLine("Private key has been saved.");
        }
    }
}
*/
/*
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static void Main()
    {
        string certPath = @"C:\certs2\trackabet.online.pem"; // Path to your PEM certificate
        string keyPath =  @"C:\certs2\private_key.pem"; // Path to your private key
        string outputPath = @"C:\certs2\certificate.pfx"; // Output PFX file path
        string pfxPassword = "$Tinkerbell1"; // Password for the PFX file

        // Load the certificate
        var cert = new X509Certificate2(certPath);

        // Load the private key (for demonstration, we assume it is in PEM format)
        string privateKeyPem = File.ReadAllText(keyPath);
        var privateKey = new X509Certificate2(Convert.FromBase64String(privateKeyPem));

        // Combine certificate and private key into a .pfx file
        var pfx = new X509Certificate2(cert.Export(X509ContentType.Pfx, pfxPassword), pfxPassword);

        // Save the .pfx file
        File.WriteAllBytes(outputPath, pfx.Export(X509ContentType.Pfx, pfxPassword));

        Console.WriteLine("PFX file created successfully at: " + outputPath);
    }
}
*/
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        string certPath = @"C:\certs2\trackabet.online.pem"; // Path to your PEM certificate
        string keyPath = @"C:\certs2\private_key.pem"; // Path to your private key
        string outputPath = @"C:\certs2\certificate.pfx"; // Output PFX file path
        string pfxPassword = "$Tinkerbell1"; // Password for the PFX file

        // Load the certificate
        var cert = new X509Certificate2(certPath);

        // Read the private key from the PEM file
        AsymmetricKeyParameter privateKey;
        using (var reader = File.OpenText(keyPath))
        {
            var pemReader = new PemReader(reader);
            privateKey = (AsymmetricKeyParameter)pemReader.ReadObject();

            if (privateKey == null)
            {
                Console.WriteLine("Failed to read the private key from the PEM file.");
                return;
            }
        }

        // Convert the private key to RSA
        RSA rsaPrivateKey = DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)privateKey);

        // Create a new Pkcs12 store
        var pkcs12Store = new Pkcs12Store();

        // Create BouncyCastle X509Certificate from X509Certificate2
        var bouncyCastleCert = DotNetUtilities.FromX509Certificate(cert);

        // Add the certificate and private key to the store
        pkcs12Store.SetCertificateEntry("cert", new X509CertificateEntry(bouncyCastleCert));
        pkcs12Store.SetKeyEntry("key", new AsymmetricKeyEntry(privateKey), new[] { new X509CertificateEntry(bouncyCastleCert) });

        // Save the PFX file
        using (var fs = File.Create(outputPath))
        {
            pkcs12Store.Save(fs, pfxPassword.ToCharArray(), new SecureRandom());
        }

        Console.WriteLine("PFX file created successfully at: " + outputPath);
    }
}



/*
using System;
using System.IO;
using System.Security.Cryptography;

using System.Security.Cryptography.X509Certificates;
using System.IO;
class Program
{
    static void Main()
    {
        using (RSA rsa = RSA.Create(2048))
        {
            // Generate a CSR
            var request = new CertificateRequest(
              "CN=trackabet.online, O=Software Boutique, C=ZA",
              rsa,
              HashAlgorithmName.SHA256,
              RSASignaturePadding.Pkcs1);
            var csrBytes = request.CreateSigningRequest();
            File.WriteAllText("request.csr", Convert.ToBase64String(csrBytes));
            Console.WriteLine("CSR has been generated.");

            // Export the private key to PKCS#8 format
            var pkcs8PrivateKey = rsa.ExportPkcs8PrivateKey();
            var privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                                 Convert.ToBase64String(pkcs8PrivateKey, Base64FormattingOptions.InsertLineBreaks) +
                                 "\n-----END PRIVATE KEY-----\n";
            File.WriteAllText(@"C:\certs2\private_key.pem", privateKeyPem);
            Console.WriteLine("Private key has been saved in PEM format.");
        }
    }
}
*/