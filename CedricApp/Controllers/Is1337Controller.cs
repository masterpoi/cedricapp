#region Header

// Is1337Controller.cs - Created 2013-03-18 13:27 by Tom Allard
// All code Copyright (c) 2013 and property of EurAm plc
// Reproduction of this material is strictly forbidden unless prior written permission is obtained from EurAm plc

#endregion

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.Mvc;
using CedricApp.Models;


namespace CedricApp.Controllers
{
    public class Is1337Controller : Controller
    {
        
        //
        // GET: /LeetController238/

        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Unlock( string msg )
        {
            const string key = "KB1uR/RObxi4DjK6Vr/+8K1yQKpGFkEtF1VUNV1ndcE=|l3PjrQMJNHVKtCMJPcYugg==";

            const string hash = "1gGA63tS8wJSRb/K6tDty97dN8g/GS4m1hQFPy9SD5A=";
            const string data = "iLhyYEO7VB3sid1NQJgkGBKxX+WiDbSSTziH67a0XTg=";    

            if (!key.Contains("|")) return RedirectToAction("Index");

            var keyParts = key.Split('|');
            var text = DecryptStringFromBytes(Convert.FromBase64String(data), Convert.FromBase64String(keyParts[0]), Convert.FromBase64String(keyParts[1]));
            //const string original = "Gelukkige Verjaardag!";
            byte[] encrypted = EncryptStringToBytes(msg, Convert.FromBase64String(keyParts[0]), Convert.FromBase64String(keyParts[1]));
            text = Convert.ToBase64String(encrypted);
            return View( new UnlockViewModel { Message = text });

            if (hash.Equals(Convert.ToBase64String((new SHA256Managed()).ComputeHash(Encoding.ASCII.GetBytes(text)))))
            {
                return View(new UnlockViewModel { Message = text });
            }

            return RedirectToAction("Index");
        }

        private static string DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] iv)
        {
            string plaintext;

            using (var rijAlg = Rijndael.Create())
            {
                rijAlg.Key = key;
                rijAlg.IV = iv;

                var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
             
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
        
        
                static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");
            byte[] encrypted;
            // Create an Rijndael object 
            // with the specified key and IV. 
            using (Rijndael rijAlg = Rijndael.Create())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption. 
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream. 
            return encrypted;

        }
        
    }
}
