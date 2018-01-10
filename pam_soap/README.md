Release information:
  pkg:  pam_soap version 0.1
  date: Tue Aug 17 00:40:09 GMT 2017
--------------------------------------------------------------------------
Initial deposit

Credit:
part of code used from pam_2fa project of CERN

Harry Kodden

# Install

Requirement for building the pam module is that the basic development tools are installed on your system. This can be achieved by installing the following:

~~~
apt-get install build-essential
apt-get install autoconf
apt-get install shtool
~~~

Furthermore, we need PAM and CURL development and library components:

~~~
apt-get install libpam-dev
apt-get install libcurl4-gnutls-dev
~~~

After cloning the repository, do the following:

~~~
cd pam_soap
ln -s /usr/bin/shtool .
autoconf
./configure
make
sudo make install
~~~

# Sample Usage

Let:
- The pam_soap.so module is installed in /usr/local/lib/security
- The pam_soap.so is used to iRODS authentication
- The SOAP Service is available at https://<domain>/api

The file /etc/pam.d/irods would then look like:

~~~
#%PAM-1.0
auth      sufficient     pam_unix.so
auth      sufficient     pam_soap.so uri=https://<domain>/api
~~~

You can verify the PAM module is working as expected using the standard iRODS command line utility ***irodsPamAuthCheck***

Example 1: Verify a system user can logon to iRODS...

~~~
irodsPamAuthCheck rods
<enter your system password now>
~~~

Example 2: Verify a COManage provisioned user can logon to iRODS...

~~~
irodsPamAuthCheck harry.kodden@yoda.uu
<enter your Service Token / One Time Password now>
~~~
