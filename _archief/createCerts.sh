# Pre Requisites

# 127.0.0.1 registry.ubopscenter.def

# Tooling (on mac)
# had to use temurin version of JAVA...setting JAVA_HOME with (proper support for keytool( needed for certs))
# export JAVA_HOME=$(/usr/libexec/java_home)

# brew install mkcert
# brew install nss 
# mkcert -install 

#mkdir -p certs
#CAROOT="$(mkcert -CAROOT)"
#cp $CAROOT/rootCA.pem ./certs/rootCA.crt
mkcert -cert-file certs/keycloak.crt -key-file certs/keycloak.key keycloak.zinl.nl
