/*
 * Copyright 2006-2010 WorldWide Conferencing, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package softwave.util

import java.security.SecureRandom
import net.liftweb.util._
import net.liftweb.common._
import _root_.java.io.{InputStream, ByteArrayOutputStream, ByteArrayInputStream}
import _root_.javax.crypto._
import _root_.javax.crypto.spec._
import _root_.scala.xml.{Node, XML}

object SecurityUtils extends SecurityHelpers with StringHelpers with IoHelpers with SecurityUtils

/**
 * The SecurityUtils trait extends <code>net.liftweb.util.SecurityHelpers</code> trait to provide functions to:<ul>
 * <li> generate Blowfish and TripleDES keys
 * <li> encrypt/decrypt using Blowfish and TripleDES keys
 * </ul>
 * It's based on Lift's original code, that've been removed from <code>SecurityHelpers</code> due to vulnerability
 * caused by using predictable IVs.
 * <br><br>
 * This trait fixes that by using random IVs generated by <code>java.security.SecureRandom</code>.<br> 
 * All encryption functions return tuple <code>(encrypted, iv)</code> so that generated IV is returned.<br>
 * All decryption functions require IV to be passed as a parameter.
 * <br><br>
 * It's safe to send IVs to receiver as a plaintext, because an attacker cannot determine what the encrypted IV looks like 
 * without knowing the key, so he actually have no way to know what has been XORed with the first block of plaintext.
 *
 */
trait SecurityUtils 
{
	self: SecurityHelpers with StringHelpers with IoHelpers =>

  /** create a Blowfish key as an array of bytes */
  def makeBlowfishKey: Array[Byte] = KeyGenerator.getInstance("Blowfish").generateKey.getEncoded

  /** create a Blowfish key from an array of bytes*/
  def blowfishKeyFromBytes(key: Array[Byte]): SecretKey = new SecretKeySpec(key, "Blowfish")

  /** decrypt a Byte array with a Blowfish key (as a Byte array)*/
  def blowfishDecrypt(enc: Array[Byte], key: Array[Byte], iv: Array[Byte]): Array[Byte] = blowfishDecrypt(enc, blowfishKeyFromBytes(key), iv)

  /** decrypt a Byte array with a Blowfish key (as a SecretKey object)*/
  def blowfishDecrypt(enc: Array[Byte], key: SecretKey, iv: Array[Byte]): Array[Byte] = readWholeStream(decryptStream(new ByteArrayInputStream(enc), key, iv))

  /** decrypt a Byte array with a Blowfish key (as a SecretKey object)*/
  def blowfishDecrypt(enc: String, key: Array[Byte], iv: String): String = blowfishDecrypt(enc, blowfishKeyFromBytes(key), iv)

  /** decrypt a Byte array with a Blowfish key (as a SecretKey object)*/
  def blowfishDecrypt(enc: String, key: SecretKey, iv: String): String = new String(blowfishDecrypt(base64Decode(enc), key, base64Decode(iv)), "UTF-8")

  /** encrypt a Byte array with a Blowfish key (as a Byte array)*/
  def blowfishEncrypt(plain: Array[Byte], key: Array[Byte]): (Array[Byte],Array[Byte]) = blowfishEncrypt(plain, blowfishKeyFromBytes(key))

  /** encrypt a Byte array with a Blowfish key (as a SecretKey object)*/
  def blowfishEncrypt(plain: Array[Byte], key: SecretKey): (Array[Byte],Array[Byte]) = 
  {
	  val (encStream,iv) = encryptStream(new ByteArrayInputStream(plain), key)
	  (readWholeStream(encStream),iv)
  }

  /** encrypt a String with a Blowfish key (as a Byte array)*/
  def blowfishEncrypt(plain: String, key: Array[Byte]): (String, String) = blowfishEncrypt(plain, blowfishKeyFromBytes(key))

  /** encrypt a String with a Blowfish key (as a SecretKey object)*/
  def blowfishEncrypt(plain: String, key: SecretKey): (String, String) = 
  {
	  val (enc,iv) = blowfishEncrypt(plain.getBytes("UTF-8"), key)
	  (base64Encode(enc),base64Encode(iv))
  }

    /** create a 3DES key as an array of bytes */
  def makeTripleDESKey: Array[Byte] = KeyGenerator.getInstance("DESede").generateKey.getEncoded

  /** create a 3DES key from an array of bytes*/
  def tripleDESKeyFromBytes(key: Array[Byte]): SecretKey = new SecretKeySpec(key, "DESede")

  /** decrypt a Byte array with a 3DES key (as a Byte array)*/
  def tripleDESDecrypt(enc: Array[Byte], key: Array[Byte], iv: Array[Byte]): Array[Byte] = tripleDESDecrypt(enc, tripleDESKeyFromBytes(key), iv)

  /** decrypt a Byte array with a 3DES key (as a SecretKey object)*/
  def tripleDESDecrypt(enc: Array[Byte], key: SecretKey, iv: Array[Byte]): Array[Byte] = readWholeStream(tripleDESDecryptStream(new ByteArrayInputStream(enc), key, iv))

  /** decrypt a Byte array with a 3DES key (as a SecretKey object)*/
  def tripleDESDecrypt(enc: String, key: Array[Byte], iv: String): String = tripleDESDecrypt(enc, tripleDESKeyFromBytes(key), iv)

  /** decrypt a Byte array with a 3DES key (as a SecretKey object)*/
  def tripleDESDecrypt(enc: String, key: SecretKey, iv: String): String = new String(tripleDESDecrypt(base64Decode(enc), key, base64Decode(iv)), "UTF-8")

  /** encrypt a Byte array with a 3DES key (as a Byte array)*/
  def tripleDESEncrypt(plain: Array[Byte], key: Array[Byte]): (Array[Byte],Array[Byte]) = tripleDESEncrypt(plain, tripleDESKeyFromBytes(key))

  /** encrypt a Byte array with a 3DES key (as a SecretKey object)*/
  def tripleDESEncrypt(plain: Array[Byte], key: SecretKey): (Array[Byte],Array[Byte]) = 
  {
	  val (encStream,iv) = tripleDESEncryptStream(new ByteArrayInputStream(plain), key)
	  (readWholeStream(encStream), iv)
  }

  /** encrypt a String with a 3DES key (as a Byte array)*/
  def tripleDESEncrypt(plain: String, key: Array[Byte]): (String, String) = tripleDESEncrypt(plain, tripleDESKeyFromBytes(key))

  /** encrypt a String with a 3DES key (as a SecretKey object)*/
  def tripleDESEncrypt(plain: String, key: SecretKey): (String, String) = 
  {
	  val (enc, iv) = tripleDESEncrypt(plain.getBytes("UTF-8"), key)
	  (base64Encode(enc),base64Encode(iv))
  }

  /** decrypt an InputStream with a Blowfish key (as a Byte array)*/
  def decryptStream(in: InputStream, key: Array[Byte], iv: Array[Byte]): InputStream = decryptStream(in, blowfishKeyFromBytes(key), iv)

  /** decrypt an InputStream with a Blowfish key (as a SecretKey object)*/
  def decryptStream(in: InputStream, key: SecretKey, iv: Array[Byte]): InputStream = {
    val cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv))
    new CipherInputStream(in, cipher)
  }

   /** decrypt an InputStream with a 3DES key (as a Byte array)*/
  def tripleDESDDecryptStream(in: InputStream, key: Array[Byte], iv: Array[Byte]): InputStream = tripleDESDecryptStream(in, tripleDESKeyFromBytes(key), iv)

  /** decrypt an InputStream with a 3DES key (as a SecretKey object)*/
  def tripleDESDecryptStream(in: InputStream, key: SecretKey, iv: Array[Byte]): InputStream = {
    val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv))

    new CipherInputStream(in, cipher)
  }

  def encryptXML(in: Node, key: Array[Byte]): (String,String) =
  encryptXML(in, blowfishKeyFromBytes(key))

  def encryptXML(in: Node, key: SecretKey): (String,String) =
  blowfishEncrypt(in.toString, key)

  def decryptXML(in: String, key: Array[Byte], iv: String): Box[Node] =
  decryptXML(in, blowfishKeyFromBytes(key), iv)

  def decryptXML(in: String, key: SecretKey, iv: String): Box[Node] =
    for {str <-  Helpers.tryo(blowfishDecrypt(in, key, iv))
         xml <- Helpers.tryo(XML.loadString(str))
    } yield xml

  /** encrypt an InputStream with a Blowfish key (as a Byte array)*/
  def encryptStream(in: InputStream, key: Array[Byte]): (InputStream,Array[Byte])= encryptStream(in, blowfishKeyFromBytes(key))

  /** encrypt an InputStream with a Blowfish key (as a SecretKey object)*/
  def encryptStream(in: InputStream, key: SecretKey): (InputStream,Array[Byte]) = {
    val cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding")
    val iv = randomIV
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv))
    (new CipherInputStream(in, cipher), iv)
  }

   /** encrypt an InputStream with a 3DES key (as a Byte array)*/
  def tripleDESEncryptStream(in: InputStream, key: Array[Byte]): (InputStream,Array[Byte])= tripleDESEncryptStream(in, tripleDESKeyFromBytes(key))

  /** encrypt an InputStream with a 3DES key (as a SecretKey object)*/
  def tripleDESEncryptStream(in: InputStream, key: SecretKey): (InputStream,Array[Byte]) = {
    val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding")
    val iv = randomIV
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv))

    (new CipherInputStream(in, cipher), iv)
  }
  
  private val secureRandom = new SecureRandom()
  private def randomIV: Array[Byte] = 
  {
	  var bytes = new Array[Byte](8)
	  secureRandom.nextBytes(bytes)
	  bytes
  }
}