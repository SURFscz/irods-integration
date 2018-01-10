FROM osixia/openldap:1.1.10
MAINTAINER Harry Kodden (harry.kodden@surfsara.nl)

ARG LDAP_BASE_DN
ENV LDAP_BASE_DN $LDAP_BASE_DN

#ADD bootstrap /container/service/slapd/assets/config/bootstrap
#ADD certs /container/service/slapd/assets/certs
ADD environment /container/environment/01-custom

RUN echo '\
dn: olcDatabase={1}hdb,cn=config\n\
changetype: modify\n\
delete: olcAccess\n\
-\n\
add: olcAccess\n\
olcAccess: {1}to attrs=userPassword,shadowLastChange by self write by anonymous auth by dn="cn=admin,'${LDAP_BASE_DN}'" write by * none\n\
-\n\
add: olcAccess\n\
olcAccess: {2}to dn.base="" by * read\n\
-\n\
add: olcAccess\n\
olcAccess: {3}to * by self write by dn="cn=admin,'${LDAP_BASE_DN}'" write\n\
-\n\
add: olcAccess\n\
olcAccess: {4}to dn.subtree="'${LDAP_BASE_DN}'" attrs=description by self write by dn.children="ou=people,'${LDAP_BASE_DN}'" search by anonymous auth\n\
-\n\
' > /container/service/slapd/assets/config/bootstrap/ldif/01_access.ldif
 
ADD eduPerson.ldif /container/service/slapd/assets/config/bootstrap/ldif/02_eduPerson.ldif

RUN echo '\
dn: ou=people,'${LDAP_BASE_DN}'\n\
changetype: add\n\
objectclass: top\n\
objectclass: organizationalUnit\n\
ou: people\n\
' > /container/service/slapd/assets/config/bootstrap/ldif/03_people.ldif 

