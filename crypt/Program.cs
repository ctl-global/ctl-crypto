using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace crypt
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
            PgpSecretKeyRingBundle privateKeys = LoadSecretKeys("bob-private.asc");
            PgpPublicKeyRingBundle publicKeysAlice = LoadPublicKeys("alice-public.asc");
            PgpPublicKeyRingBundle publicKeysCarol = LoadPublicKeys("carol-public.asc");

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
                Encrypt(input, output, publicKeys, secretKey, "asdf");
            }
        }

        /// <summary>
        /// Decrypts test.txt.gpg into test-out.txt using alice's private key, and verifies the file's signature using bob's public key.
        /// </summary>
        static void TestDecrypt()
        {
            PgpSecretKeyRingBundle privateKeys = LoadSecretKeys("alice-private.asc");
            PgpPublicKeyRingBundle publicKeys = LoadPublicKeys("bob-public.asc");

            using (Stream input = File.OpenRead("test.txt.gpg"))
            using (Stream output = File.OpenWrite("test-out.txt"))
            {
                Decrypt(input, output, publicKeys, privateKeys, "zxcv");
            }
        }

        static PgpSecretKeyRingBundle LoadSecretKeys(string filePath)
        {
            using (Stream input = File.OpenRead(filePath))
            {
                return new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(input));
            }
        }

        static PgpPublicKeyRingBundle LoadPublicKeys(string filePath)
        {
            using (Stream input = File.OpenRead(filePath))
            {
                return new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(input));
            }
        }

        /// <summary>
        /// Encrypts a stream.
        /// </summary>
        /// <param name="inputStream">The input stream to encrypt.</param>
        /// <param name="outputStream">The output stream.</param>
        /// <param name="publicKeys">A collection of public keys to encrypt to.</param>
        /// <param name="secretKey">A secret key to sign with. If null, no digital signature is created.</param>
        /// <param name="secretKeyPassword">A password used to decrypt the secret key.</param>
        static void Encrypt(Stream inputStream, Stream outputStream, IEnumerable<PgpPublicKey> publicKeys, PgpSecretKey secretKey, string secretKeyPassword)
        {
            // signature.

            PgpSignatureGenerator sigGen = null;
            if (secretKey != null)
            {
                string userId = secretKey.PublicKey.GetUserIds().OfType<string>().First();
                PgpSignatureSubpacketGenerator subpackGen = new PgpSignatureSubpacketGenerator();
                subpackGen.SetSignerUserId(false, userId);

                PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(secretKeyPassword.ToCharArray());
                sigGen = new PgpSignatureGenerator(secretKey.PublicKey.Algorithm, Org.BouncyCastle.Bcpg.HashAlgorithmTag.Sha256);
                sigGen.InitSign(PgpSignature.BinaryDocument, privateKey);
                sigGen.SetHashedSubpackets(subpackGen.Generate());
            }

            // encrypt.

            PgpEncryptedDataGenerator enc = new PgpEncryptedDataGenerator(Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag.Aes128, true);

            foreach (var k in publicKeys)
            {
                enc.AddMethod(k);
            }

            outputStream = enc.Open(outputStream, new byte[BufferSize]);
            
            // compression.

            PgpCompressedDataGenerator compress = new PgpCompressedDataGenerator(Org.BouncyCastle.Bcpg.CompressionAlgorithmTag.Zip);
            outputStream = compress.Open(outputStream);

            // write out the one-pass signature list.
            sigGen?.GenerateOnePassVersion(false).Encode(outputStream);

            // write out the literal data, and generate signature.

            PgpLiteralDataGenerator literal = new PgpLiteralDataGenerator();
            using (Stream literalStream = literal.Open(outputStream, PgpLiteralData.Binary, "fileName", DateTime.Now, new byte[BufferSize]))
            {
                if (sigGen != null)
                {
                    byte[] buffer = new byte[BufferSize];
                    int len;

                    while ((len = inputStream.Read(buffer, 0, buffer.Length)) != 0)
                    {
                        sigGen.Update(buffer, 0, len);
                        literalStream.Write(buffer, 0, len);
                    }
                }
                else
                {
                    inputStream.CopyTo(literalStream);
                }
            }

            // write out the signature.
            sigGen?.Generate().Encode(outputStream);

            // close out.
            compress.Close();
            enc.Close();
        }

        /// <summary>
        /// Decrypts a stream.
        /// </summary>
        /// <param name="inputStream">The input stream to decrypt.</param>
        /// <param name="outputStream">The output stream.</param>
        /// <param name="publicKeys">A bundle of public keys, used to verify digital signatures. If specified, an exception will be thrown if a signature does not exist.</param>
        /// <param name="secretKeys">A bundle of secret keys, used to decrypt the stream.</param>
        /// <param name="secretKeyPassword">A password to decrypt the secret key.</param>
        static void Decrypt(Stream inputStream, Stream outputStream, PgpPublicKeyRingBundle publicKeys, PgpSecretKeyRingBundle secretKeys, string secretKeyPassword)
        {
            // this is all just tree traversal, going through a PGP object.
            // -root
            //   -encrypted data
            //     -compressed data (optional -- might just skip to below)
            //       -one-pass signature list (optional -- for digital signatures)
            //       -literal data (required -- this is the actual encrypted data)
            //       -signature list (optional -- for digital signatures)

            PgpObject o;

            // find the encrypted data list.
            
            PgpObjectFactory fact = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            PgpEncryptedDataList enc = null;

            do
            {
                o = fact.NextPgpObject();
                if (o == null) throw new Exception("Unable to find encrypted data list.");

                enc = o as PgpEncryptedDataList;
            }
            while (enc == null);

            // find data and the key that works for it.

            var secretData = (from eo in enc.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>()
                              let key = secretKeys.GetSecretKey(eo.KeyId)
                              where key != null
                              select new
                              {
                                  EncryptedData = eo,
                                  SecretKey = key
                              }).SingleOrDefault();

            if (secretData == null)
            {
                throw new Exception("Unable to find secret key pertaining to encrypted data.");
            }

            PgpPrivateKey privateKey = secretData.SecretKey.ExtractPrivateKey(secretKeyPassword.ToCharArray());
            PgpPublicKeyEncryptedData encryptedData = secretData.EncryptedData;

            // get the decrypted data.
            
            fact = new PgpObjectFactory(encryptedData.GetDataStream(privateKey));
            o = fact.NextPgpObject();

            // if compressed, decompress.

            PgpCompressedData cd = o as PgpCompressedData;
            if (cd != null)
            {
                fact = new PgpObjectFactory(cd.GetDataStream());
                o = fact.NextPgpObject();
            }

            // check if there are signatures.

            PgpOnePassSignatureList onePassSigList = o as PgpOnePassSignatureList;

            if (onePassSigList != null)
            {
                o = fact.NextPgpObject();
            }

            // now send the data to the output stream.

            PgpLiteralData ld = o as PgpLiteralData;
            if (ld == null)
            {
                throw new Exception("Unable to find data within encrypted object.");
            }

            if (onePassSigList != null && publicKeys != null)
            {
                // read the decrypted stream and compute the digital signature.

                if (onePassSigList.IsEmpty)
                {
                    throw new Exception("Expected one-pass signature, but none found.");
                }

                PgpOnePassSignature onePassSig = onePassSigList[0];

                PgpPublicKey publicKey = publicKeys.GetPublicKey(onePassSig.KeyId);

                if (publicKey == null)
                {
                    throw new Exception("Unable to find public key matching signature.");
                }

                onePassSig.InitVerify(publicKey);

                byte[] data = new byte[BufferSize];
                int len;

                Stream clearStream = ld.GetInputStream();

                while ((len = clearStream.Read(data, 0, data.Length)) != 0)
                {
                    onePassSig.Update(data, 0, len);
                    outputStream.Write(data, 0, len);
                }

                // verify integrity, if possible.

                if (encryptedData.IsIntegrityProtected() && !encryptedData.Verify())
                {
                    throw new Exception("Encrypted data failed integrity check.");
                }

                // verify digital signature.

                o = fact.NextPgpObject();
                PgpSignatureList sigList = o as PgpSignatureList;

                if (sigList == null || sigList.IsEmpty)
                {
                    throw new Exception("Expected signature, but none found.");
                }

                if (!onePassSig.Verify(sigList[0]))
                {
                    throw new Exception("Signature failed verification.");
                }
            }
            else
            {
                if (publicKeys != null)
                {
                    throw new Exception("Message does not contain a signature to verify.");
                }

                ld.GetInputStream().CopyTo(outputStream);

                // verify integrity, if possible.

                if (encryptedData.IsIntegrityProtected() && !encryptedData.Verify())
                {
                    throw new Exception("Encrypted data failed integrity check.");
                }
            }
        }

        const int BufferSize = 81920; // this is the maximum non-large object size for .NET.
    }
}
