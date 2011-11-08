What is it?
==========

**CryptandDrop** is a program that encrypts files and send them to Dropbox. 
Then they can be decrypted to current directory when are needed. AES is 
used as the cryptographic backend, with SHA256 and HMAC providing, 
respectively, key hashing and signature veryfing.

**CryptandDrop** was born out of the lack of privacy on Drobpox (they 
provide encryption of files but they can also decrypt at will, not 
making for a very private way to store important documents) and the 
lack of a quick and simply solution to encrypt and decrypt files without 
having to use separate programs (like a Truecrypt container). Therefore 
I chose to wrote one myself and here it is.

Basically if you are looking for a way to store important files on 
Dropbox without worrying that anybody else but you can see their 
contents, **CryptandDrop** is for you.

Requirements
--

* Python 2.7 http://python.org/
* Pycrypto https://github.com/dlitz/pycrypto
* Python-Oauth http://code.google.com/p/oauth/
* Simplejson https://github.com/simplejson/simplejson

Project status
--

Alpha. Very.

License
--

LGPL. See LICENSE
