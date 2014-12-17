#!/bin/sh -e

if [ -e "sig.keystore" ] ; then
  echo "sig.keystore already exists"
  exit
fi

keytool -genkey -keyalg RSA -keysize 4096 -keystore sig.keystore -alias coverity -storepass password -keypass password -dname "CN=Coverity, OU=SRL, O=Coverity, L=San Francisco, S=California, C=US"
keytool -list -rfc -keystore sig.keystore -storepass password -alias coverity > src/main/resources/coverity.crt

