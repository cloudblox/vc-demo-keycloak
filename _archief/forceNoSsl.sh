#realm_name=$1

realm_name=master

# Eerst 1x inloggen
docker exec -it zinnl-keycloak /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm $realm_name \
  --user admin \
  --password FdE1YRL3569X

docker exec -it zinnl-keycloak /opt/keycloak/bin/kcadm.sh update realms/$realm_name -s sslRequired=NONE
docker exec -it zinnl-keycloak /opt/keycloak/bin/kcadm.sh get realms/$realm_name | grep -i sslRequired
