

Example

java sd-dss-util-cli.jar SignCli
	"input/file.pdf"
	--format=CAdES
	--level=BES
	--packaging=ENVELOPING
	--pkcs12="path/to/the/pkcs12/key.p12" "pkcs12filepassword"
	--output="output/file.pdf"
	--url="http://localhost:8080/service"
	--icn=".*some.key.provider.*"

//////////////////////////////////////////////////////////////////////////////////////////////
Crea Private Key on keystore 

keytool -genkey -keyalg RSA -alias selfsigned -keystore "keystore2.jks" -storepass password -validity 9360 -keysize 2048

keytool -genkey -keyalg "RSA" -alias "testFirma" -keypass "changeit" -keystore "testKeystore.jks" -storepass "changeit" -storeType "JKS" -validity 3650



////////////////////////////////////////////////////////////////////////////////////////////////

keytool -genkeypair -keyalg "RSA" -alias "testFirma" -keypass "changeit" -keystore "testKeystore2.jks" -storepass "changeit" -storeType "JKS" -validity 3650 -keysize 2048



keytool -genkeypair -alias rgateway -keyalg RSA -keysize 2048 -keystore newkeystore.jks -validity 365 -storetype JCEKS

keytool -genkeypair -dname "CN=gateway.mycompany.com, O=My Company, C=US" -alias rgateway -keyalg RSA -keysize 2048 -keystore newkeystore.jks -validity 365  -storetype JCEKS

#######################################################################################

## Import Certificate Phisical File 

keytool -importcert -file tsa.crt -keystore "testKeystore2.jks" -alias "TSA_DER"
keytool -importcert -file tsa.crt -keystore "cacerts" -alias "TSA_DER"

######################################################################################


Export/import commands We'll use the keytool -export command to extract the public key into a file, and then use the keytool -import command to insert it into a new keystore. Here's the command to extract the client's public key:

	keytool -export -alias clientprivate -keystore client.private -file temp.key -storepass clientpw

And here's the command to insert the client's private key into its own keystore:

	keytool -import -noprompt -alias clientpublic -keystore client.public -file temp.key -storepass public

We'll also extract and store the server's public key. Here's the command to extract the key:

	keytool -export -alias serverprivate -keystore server.private -file temp.key -storepass serverpw

And here's the command to place it in its own keystore:

	keytool -import -noprompt -alias serverpublic -keystore server.public -file temp.ke

##########################################################
Keytool -list -keystore NONE -storetype PKCS11 -providerclass sun.security.pkcs11.SunPKCS11 -providerArg ./enToken.cfg

jarsigner -tsa http://timestamp.entrust.net/TSS/RFC3161sha2TS -verbose -keystore \
NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg \
./enToken.cfg <your JAR filename> <your private key ALIAS> 


jarsigner -verify -verbose <JAR filename>


########################################################################
# GENERATE EXTENSIONS KEYSOTRE EKU
#########################################################################

keytool -genkey -alias oftp2.sinotrans.com -validity 3650 -keyalg RSA -keysize 2048 -ext "KeyUsage:incritical=keyEncipherment" -keystorerainybei.jks -dname "CN=rainybei,OU=rainybei,O=rainybei,L=BEIJING,ST=BEIJING,C=CN" -ext "EKU=clientAuth"


keytool -genkeypair -v -alias exampleca2 -dname "CN=exampleCA, OU=Example Org, O=Example Company, L=San Francisco, ST=California, C=US" -keystore exa2.jks -keypass changeit -storepass changeit -keyalg RSA -keysize 4096 -ext KeyUsage:critical="keyCertSign" -ext "KeyUsage:incritical=keyEncipherment" -ext BasicConstraints:critical="ca:true" -validity 9999


#####################################################################
# IMPORT PFX TO JKS o IMPORT KEYSTORE TO ANOTHER
####################################################################
keytool -importkeystore -srckeystore mykeystore.pxf -destkeystore clientcert.jks -srcstoretype pkcs12 -deststoretype JKS

https://www.playframework.com/documentation/2.5.x/CertificateGeneration




keytool -importkeystore -srckeystore TSAServerCertificate.pfx -destkeystore testKeystore4.jks -srcstoretype pkcs12 -deststoretype JKS

#####################################################################
# MAVEN SETTINGS NEXUS
####################################################################
ADD repo on settings.xml

<server>
	<id>tenti-maven</id>
	<username>admin</username>
	<password>admin123</password>
</server>


UPLOAD JAR TO NEXUS


mvn deploy:deploy-file -DgroupId=accv -DartifactId=arangi -Dversion=1.5.0 -Dpackaging=jar -Dfile="C:\Users\tenti\Downloads\arangi_base-1.5.0.jar" -DgeneratePom=true -DrepositoryId=tenti-maven -Durl="http://localhost:8081/repository/tenti-maven/"
mvn deploy:deploy-file -DgroupId=at.gv.egiz -DartifactId=mocca -Dversion=1.3.16 -Dpackaging=zip -Dfile="C:\Users\tenti\Downloads\mocca-mocca-1.3.16.zip" -DgeneratePom=true -DrepositoryId=tenti-maven -Durl="http://localhost:8081/repository/tenti-maven/"


mvn deploy:deploy-file -DgroupId=accv -DartifactId=arangi -Dversion=1.5.0 -Dpackaging=jar -Dfile="C:\Users\tenti\Downloads\arangi_base-1.5.0.jar" -DgeneratePom=true -DrepositoryId=maven-public -Durl="http://localhost:8081/repository/maven-public/"
mvn deploy:deploy-file -DgroupId=at.gv.egiz -DartifactId=mocca -Dversion=1.3.16 -Dpackaging=zip -Dfile="C:\Users\tenti\Downloads\mocca-mocca-1.3.16.zip" -DgeneratePom=true -DrepositoryId=maven-public -Durl="http://localhost:8081/repository/maven-public/"


https://springframework.svn.sourceforge.net/svnroot/springframework/repos/repo-ext/javax/xml/crypto/xmldsig/1.0/xmldsig-1.0.jar

mvn install:install-file -Dfile=xmldsig-1.0.jar -DgroupId=javax.xml.crypto -DartifactId=xmldsig -Dversion=1.0 -Dpackaging=jar -DgeneratePom=true -DcreateChecksum=tru
mvn install:install-file -Dfile=xmldsig-1.0.jar -DgroupId=javax.xml.crypto -DartifactId=xmldsig -Dversion=1.0 -Dpackaging=jar -DgeneratePom=true -DcreateChecksum=tru