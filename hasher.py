#!/usr/bin/env python
"""
Author:     phillips321 contact at phillips321.co.uk
License:    CC BY-SA 3.0
Use:        Python hash generator
Released:   www.phillips321.co.uk
Dependencies:
       python python-passlib(1.6) python-bcrypt
ToDo:
       add flags to command line -p password -s salt -u user
ChangeLog:
       v0.1 - first release
"""
version = "0.1"
import sys
import hashlib #used for MD5 SHA1, SHA256 and SHA512
import passlib.hash #apt-get install python-passlib python-bcrypt
def toscreen(algorithm, salt, hash):
	if salt == "nosalt":
		print '    %s hash is: %s' % (algorithm, hash)
	else:
		print '    %s hash with salt of %s is: %s' % (algorithm, salt, hash)

if len(sys.argv) > 1 :
	string = sys.argv[1]
	if len(sys.argv) > 2:	# SALT Given
		salt = sys.argv[2]
		print "Salt provided so we will use it in our calculations"
	else:			# NOSALT given
		salt = "nosalt"
		print "No salt provided"
		
	#Now for the output

	print "  Basic Hashing algorithms"
	toscreen("MD5", "nosalt", hashlib.md5(string).hexdigest())
	toscreen("SHA1", "nosalt", hashlib.sha1(string).hexdigest())
	toscreen("SHA256", "nosalt", hashlib.sha256(string).hexdigest())
	toscreen("SHA512", "nosalt", hashlib.sha512(string).hexdigest())
	
	print "Unix & Modular Crypt Hashes"
	print "  Archaic Unix Schemes"
	toscreen("DES Crypt", salt, passlib.hash.des_crypt.encrypt(string, salt=salt[:2].zfill(2)))
	toscreen("BSDi Crypt", salt, passlib.hash.bsdi_crypt.encrypt(string, salt=salt[:4].zfill(4)))
	toscreen("BigCrypt", salt, passlib.hash.bigcrypt.encrypt(string, salt=salt[:2].zfill(2)))
	toscreen("Crypt16", salt, passlib.hash.crypt16.encrypt(string, salt=salt[:2].zfill(2)))
	print "  Standard Unix Schemes"
	toscreen("MD5 Crypt", salt, passlib.hash.md5_crypt.encrypt(string, salt=salt[:2]))
	toscreen("BCrypt", salt, passlib.hash.bcrypt.encrypt(string, salt=salt[:22].zfill(22)))
	toscreen("Sun MD5 Crypt", salt, passlib.hash.sun_md5_crypt.encrypt(string, salt=salt))
	toscreen("SHA-1 Crypt", salt, passlib.hash.sha1_crypt.encrypt(string, salt=salt))
	toscreen("SHA-256 Crypt", salt, passlib.hash.sha256_crypt.encrypt(string, salt=salt[:16].zfill(16)))
	toscreen("SHA-512 Crypt", salt, passlib.hash.sha512_crypt.encrypt(string, salt=salt[:16].zfill(16)))
	print "  Other Modular Crypt Schemes"
	toscreen("Apr MD5 Crypt", salt, passlib.hash.apr_md5_crypt.encrypt(string, salt=salt[:8].zfill(8)))
	toscreen("PHPass", salt, passlib.hash.phpass.encrypt(string, salt=salt[:8].zfill(8)))
	toscreen("Generic PBKDF2 SHA1", salt, passlib.hash.pbkdf2_sha1.encrypt(string, salt=salt))
	toscreen("Generic PBKDF2 SHA256", salt, passlib.hash.pbkdf2_sha256.encrypt(string, salt=salt))
	toscreen("Generic PBKDF2 SHA512", salt, passlib.hash.pbkdf2_sha512.encrypt(string, salt=salt))
	toscreen("Cryptaculars PBKDF2 hash", salt, passlib.hash.cta_pbkdf2_sha1.encrypt(string, salt=salt))
	toscreen("Dwayne Litzenbergers PBKDF2 hash", salt, passlib.hash.dlitz_pbkdf2_sha1.encrypt(string, salt=salt))
	
	print "LDAP / RFC2307 Hashes"
	print "  Standard LDAP Schemes"
	toscreen("MD5 Digest", "nosalt", passlib.hash.ldap_md5.encrypt(string))
	toscreen("MD5 Digest(salted)", salt, passlib.hash.ldap_salted_md5.encrypt(string, salt=salt[:16].zfill(4)))
	toscreen("SHA1 Digest", "nosalt", passlib.hash.ldap_sha1.encrypt(string))
	toscreen("SHA1 Digest(salted)", salt, passlib.hash.ldap_salted_sha1.encrypt(string, salt=salt[:16].zfill(4)))
	toscreen("LDAP DES Wrapper", "nosalt", passlib.hash.ldap_des_crypt.encrypt(string))
	toscreen("LDAP BSDi Wrapper", "nosalt", passlib.hash.ldap_bsdi_crypt.encrypt(string))
	toscreen("LDAP MD5 Wrapper", "nosalt", passlib.hash.ldap_md5_crypt.encrypt(string))
	toscreen("LDAP bcrypt Wrapper", "nosalt", passlib.hash.ldap_bcrypt.encrypt(string))
	toscreen("LDAP sha1 Wrapper", "nosalt", passlib.hash.ldap_sha1_crypt.encrypt(string))
	toscreen("LDAP sha256 Wrapper", "nosalt", passlib.hash.ldap_sha256_crypt.encrypt(string))
	toscreen("LDAP sha512 Wrapper", "nosalt", passlib.hash.ldap_sha512_crypt.encrypt(string))
	print "  Non-Standard LDAP Schemes"
	toscreen("Hex-Encoded MD5 Digest", "nosalt", passlib.hash.ldap_hex_md5.encrypt(string))
	toscreen("Hex-Encoded SHA1 Digest", "nosalt", passlib.hash.ldap_hex_sha1.encrypt(string))
	toscreen("Atlassians PBKDF2 Hash", "nosalt", passlib.hash.atlassian_pbkdf2_sha1.encrypt(string))
	toscreen("Fairly Secure Hashed Password", "nosalt", passlib.hash.fshp.encrypt(string))
	
	print "Database Hashes"
	toscreen("MS SQL 2000", "nosalt", passlib.hash.mssql2000.encrypt(string))
	toscreen("MS SQL 2005", "nosalt", passlib.hash.mssql2005.encrypt(string))
	toscreen("MySQL 3.2.3", "nosalt", passlib.hash.mysql323.encrypt(string))
	toscreen("MySQL 4.1", "nosalt", passlib.hash.mysql41.encrypt(string))
	toscreen("PostgreSQL MD5", salt, passlib.hash.postgres_md5.encrypt(string, user=salt))
	toscreen("Oracle 10g", salt, passlib.hash.oracle10.encrypt(string, user=salt))
	toscreen("Oracle 11g", "nosalt", passlib.hash.oracle11.encrypt(string))
	
	print "MS Windows Hashes"
	toscreen("LanManager", "nosalt", passlib.hash.lmhash.encrypt(string))
	toscreen("NT-HASH", "nosalt", passlib.hash.nthash.encrypt(string))
	toscreen("Domain Cached Creds", salt, passlib.hash.msdcc.encrypt(string, salt))
	toscreen("Domain Cached Creds v2", salt, passlib.hash.msdcc2.encrypt(string, salt))

	print "Other Hashes"
	toscreen("Cisco PIX", salt, passlib.hash.cisco_pix.encrypt(string, user=salt))
	toscreen("Cisco Type7", "nosalt", passlib.hash.cisco_type7.encrypt(string))
	toscreen("Django 1.0 DES Crypt", salt, passlib.hash.django_des_crypt.encrypt(string, salt=salt.zfill(2)))
	toscreen("Django 1.0 Salted MD5", salt, passlib.hash.django_salted_md5.encrypt(string, salt=salt))
	toscreen("Django 1.0 Salted SHA1", salt, passlib.hash.django_salted_sha1.encrypt(string, salt=salt))
	toscreen("Django 1.4 Bcrypt", salt, passlib.hash.django_bcrypt.encrypt(string, salt=salt[:22].zfill(22)))
	toscreen("Django 1.4 PBKDF2 SHA1", salt, passlib.hash.django_pbkdf2_sha1.encrypt(string, salt=salt))
	toscreen("Django 1.4 PBKDF2 SHA256", salt, passlib.hash.django_pbkdf2_sha256.encrypt(string, salt=salt))

	
else:
	print "hasher.py version %s" % version
	print "You need to provide the string on the command line"
	print "hasher.py password [salt/username]"
	print "If salt is incorrect length it will be preceeded with zero's"

