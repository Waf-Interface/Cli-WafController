For running and intergating the modsec for this cpp wrapper api you need to build the mod security lib from source to get .so lib's for your own os server(or dll for widnows server for apachi...).
here is a quick tutorial:
Step 1: Install Dependencies
First, ensure you have the necessary dependencies for building ModSecurity from source.

Run the following commands to install the required libraries and tools:

```
sudo apt update
sudo apt install build-essential git autoconf libtool libxml2-dev libcurl4-openssl-dev libapr1-dev libpcre3-dev apache2-dev
```
Step 2: Download ModSecurity Source Code
Next, download the ModSecurity version 3 source code from GitHub.
```
cd /usr/local/src
git clone --branch v3/master https://github.com/SpiderLabs/ModSecurity.git
cd ModSecurity
```

Step 3: Build and Install ModSecurity
Now, build and install ModSecurity. This process will configure the library and prepare it for use with Apache.

Initialize the build system:
```
git submodule init
git submodule update
```

Build ModSecurity:

```
./build.sh
```

Install ModSecurity:

```
./configure
make
sudo make install
```
Step 4: Install ModSecurity Apache Module
After ModSecurity is installed, you'll need to build the ModSecurity Apache module (mod_security3.so).

Navigate to the apache2 folder inside ModSecurity source:

```
cd /usr/local/src/ModSecurity/apache2
```
Run the make command to build the Apache module:

```
make
```
Install the module:
```
sudo make install
```
This should install mod_security3.so to the appropriate directory.

Step 5: Enable ModSecurity in Apache

Load the ModSecurity module by editing the Apache configuration file (usually /etc/apache2/apache2.conf or /etc/httpd/httpd.conf) and adding the following line:

```
LoadModule security3_module /usr/local/lib/apache2/modules/mod_security3.so
```
Adjust the path if necessary (depending on where mod_security3.so was installed).

Configure ModSecurity by adding or editing the following in /etc/modsecurity/modsecurity.conf:

```
SecRuleEngine On
```

Restart Apache to apply the changes:

```
sudo systemctl restart apache2
```
Step 6: Verify Installation
Check that the ModSecurity module is loaded:
```
apachectl -M | grep security3
```

This should output security3_module if it was successfully loaded.
Test ModSecurity by adding a simple rule in the /etc/modsecurity/modsecurity.conf file (if not already there) to deny a POST request:

```
SecRule REQUEST_METHOD "POST" "id:1000001,deny,status:403,msg:'POST method not allowed'"
```

Restart Apache again:
```
sudo systemctl restart apache2
```
Test with a POST request.You can use curl to test if ModSecurity is working:


```
curl -X POST http://localhost/test
```
You should receive a 403 Forbidden response if ModSecurity is working correctly.

Step 7: Final Check
If you continue to encounter issues, check the Apache error logs (/var/log/apache2/error.log) and ModSecurity audit logs (/var/log/modsec_audit.log) for any errors related to the ModSecurity configuration.

