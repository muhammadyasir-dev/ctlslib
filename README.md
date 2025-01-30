## ctlslib
ctlslib uses posiz lib-ssl-dev under the hood which uses rsa cryptograpy for signing and unsigning payloads or heartbeats with a asymmetric algorithm and it is production grade and can interoperte with self-signed ssl certificates and it is not tested for tech vendor's SSL certificates.

###Note
make sure to lod secure_data_handler worke in your directory and call methods on top of it


###Setup

~~~bash
cd ctlslib
~~~
~~~bash
sudo make or build using gcc manually and mke sure you have lib-ssl-dev, curl4, and build-esentials along with cmake installed properly
~~~

