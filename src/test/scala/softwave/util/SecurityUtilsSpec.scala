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

import _root_.org.specs._
import _root_.org.specs.runner._
import _root_.java.io.ByteArrayInputStream
import net.liftweb.util._
import net.liftweb.common._

object SecurityUtilsSpec extends Specification with SecurityUtils with SecurityHelpers with IoHelpers with StringHelpers {
    "provide makeBlowfishKey, blowfishEncrypt, blowfishDecrypt functions to encrypt/decrypt Strings with Blowfish keys" in {
      val key = makeBlowfishKey
      val (encrypted,iv) = blowfishEncrypt("hello world", key)
      val (encrypted2,iv2) = blowfishEncrypt("hello world", key)
      
      encrypted must_!= "hello world"
      encrypted2 must_!= "hello world"
      //same plaintext must not result to same encrypted
      encrypted must_!= encrypted2
      //IVs must not be the same
      iv must_!= iv2
      //decryption must not be possible with wrong IV
      blowfishDecrypt(base64Decode(encrypted), key, new Array[Byte](8)) must_!= "hello world"
      blowfishDecrypt(base64Decode(encrypted2), key, new Array[Byte](8)) must_!= "hello world"
      blowfishDecrypt(encrypted, key, iv2) must_!= "hello world"
      blowfishDecrypt(encrypted2, key, iv) must_!= "hello world"
      //decryption must be successful is proper IV is used
      blowfishDecrypt(encrypted, key, iv) must_== "hello world"
      blowfishDecrypt(encrypted2, key, iv2) must_== "hello world"
    }  
    "provide makeTripleDESKey, tripleDESEncrypt, tripleDESDecrypt functions to encrypt/decrypt Strings with TripleDES keys" in {
      val key = makeTripleDESKey
      val (encrypted,iv) = tripleDESEncrypt("hello world", key)
      val (encrypted2,iv2) = tripleDESEncrypt("hello world", key)
      
      encrypted must_!= "hello world"
      encrypted2 must_!= "hello world"
      //same plaintext must not result to same encrypted
      encrypted must_!= encrypted2
      //IVs must not be the same
      iv must_!= iv2
      //decryption must not be possible with wrong IV
      tripleDESDecrypt(base64Decode(encrypted), key, new Array[Byte](8)) must_!= "hello world"
      tripleDESDecrypt(base64Decode(encrypted2), key, new Array[Byte](8)) must_!= "hello world"
      tripleDESDecrypt(encrypted, key, iv2) must_!= "hello world"
      tripleDESDecrypt(encrypted2, key, iv) must_!= "hello world"
      //decryption must be successful is proper IV is used
      tripleDESDecrypt(encrypted, key, iv) must_== "hello world"
      tripleDESDecrypt(encrypted2, key, iv2) must_== "hello world"
    }  
}

class SecurityUtilsSpecTest extends JUnit4(SecurityUtilsSpec)
