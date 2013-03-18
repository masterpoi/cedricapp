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

        public ActionResult Unlock()
        {
            const string key = "<INSERT KEY>";

            const string hash = "1gGA63tS8wJSRb/K6tDty97dN8g/GS4m1hQFPy9SD5A=";
            const string data = "iLhyYEO7VB3sid1NQJgkGBKxX+WiDbSSTziH67a0XTg=";

            if (!key.Contains("|")) return RedirectToAction("Index");

            var keyParts = key.Split('|');
            var text = DecryptStringFromBytes(Convert.FromBase64String(data), Convert.FromBase64String(keyParts[0]), Convert.FromBase64String(keyParts[1]));

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
    }
}