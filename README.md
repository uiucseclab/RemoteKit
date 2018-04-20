# CS 460 rootkit project

## What is this?

This is a full-chain exploit for Linux, using some well-known (and now
patched) exploits to install a rootkit remotely on a vulnerable system.

## Goals

Only technical vulnerabilities, no social engineering (phishing, etc). The
intended goal is to explore how easy it is to attack unpatched machines,
using only publicly documented exploits. The attack should be automated from
start to finish - no human interaction required.

Patch your machines, people!

## Setup (victim host)

You will need a kernel that is vulnerable to the dirtycow exploit.
The newest version that is still vulnerable is 4.8.2. If you are running
Ubuntu 16.04, you can install it using:

```
curl -O http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.8.2/linux-image-4.8.2-040802-generic_4.8.2-040802.201610161339_amd64.deb
curl -O http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.8.2/linux-headers-4.8.2-040802-generic_4.8.2-040802.201610161339_amd64.deb
curl -O http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.8.2/linux-headers-4.8.2-040802_4.8.2-040802.201610161339_all.deb
sudo dpkg -i *.deb
```

You may need to modify your GRUB config to select this kernel version
at boot. Use `uname -r` to check your running kernel version.

## Install Apache Tomcat and Struts

Download [Tomcat](http://apache.mirrors.tds.net/tomcat/tomcat-8/v8.5.30/bin/apache-tomcat-8.5.30.tar.gz) and untar it anywhere convenient. Download [Struts 2.5.10](https://archive.apache.org/dist/struts/2.5.10/struts-2.5.10-all.zip) and uncompress it.
Install Struts 2 by copying the REST example to webapps directory (`$CATALINA_HOME$` being the root directory of Tomcat, `$STRUTS$` being the Struts 2 directory):

```
cp $STRUTS$/apps/struts2-rest-showcase.war $CATALINA_HOME$/webapps/ROOT.war
sudo $CATALINA_HOME$/bin/startup.sh
```