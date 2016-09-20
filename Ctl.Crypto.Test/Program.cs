using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ctl.Crypto;

namespace Ctl.Crypto.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            TestEncrypt();
            TestDecrypt();
        }

        /// <summary>
        /// Encrypts test.txt into test.txt.gpg for alice and carol's public key, and creates a signature using bob's private key.
        /// </summary>
        static void TestEncrypt()
        {
            PgpSecretKeyRingBundle privateKeys = PGP.LoadSecretKeys("bob-private.asc");
            PgpPublicKeyRingBundle publicKeysAlice = PGP.LoadPublicKeys("alice-public.asc");
            PgpPublicKeyRingBundle publicKeysCarol = PGP.LoadPublicKeys("carol-public.asc");

            PgpSecretKey secretKey = privateKeys
                .GetKeyRings()
                .OfType<PgpSecretKeyRing>()
                .Select(r => r.GetSecretKey())
                .First();

            PgpPublicKey publicKeyAlice = publicKeysAlice
                .GetKeyRings()
                .OfType<PgpPublicKeyRing>()
                .Select(r => r.GetPublicKey())
                .First();

            PgpPublicKey publicKeyCarol = publicKeysCarol
                .GetKeyRings()
                .OfType<PgpPublicKeyRing>()
                .Select(r => r.GetPublicKey())
                .First();

            var publicKeys = new[] { publicKeyAlice, publicKeyCarol };

            using (Stream input = File.OpenRead("test.txt"))
            using (Stream output = File.Create("test.txt.gpg"))
            {
                PGP.Encrypt(input, output, publicKeys, secretKey, "asdf");
            }
        }

        /// <summary>
        /// Decrypts test.txt.gpg into test-out.txt using alice's private key, and verifies the file's signature using bob's public key.
        /// </summary>
        static void TestDecrypt()
        {
            PgpSecretKeyRingBundle privateKeys = PGP.LoadSecretKeys("alice-private.asc");
            PgpPublicKeyRingBundle publicKeys = PGP.LoadPublicKeys("bob-public.asc");

            using (Stream input = File.OpenRead("test.txt.gpg"))
            using (Stream output = File.OpenWrite("test-out.txt"))
            {
                
                PGP.Decrypt(input, output, publicKeys, privateKeys, "zxcv");
            }
        }

        
    }
}
