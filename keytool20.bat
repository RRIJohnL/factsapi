"c:\Program Files\git\usr\bin\openssl" pkcs12 -export -name rriapi -out rriapi.p12 -inkey rri-safety.key2 -in rri-safety.crt -passin "pass:rriapi" -passout "pass:rriapi"
pause
rem "c:\Program Files\java\jdk-20\bin\keytool" -import -alias rriapi -keystore rriapi.ks -file rri-safety.pem -storepass rriapi
pause
rem "c:\Program Files\java\jdk-20\bin\keytool" -list -keystore rriapi.ks -storepass rriapi
pause
