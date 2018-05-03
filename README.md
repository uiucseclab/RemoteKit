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

## Rootkit details

To give any process root permissions, we use `commit_creds(prepare_kernel_cred(NULL))`,
which is intended to be used for kernel userspace daemons. It's a pretty
well-known backdoor method which sets the calling process's UID to 0.

To hide the module from the kernel module list, we simply remove it from
the linked list of all kernel modules. Luckily, the list is a doubly
linked list, so we don't need the head node's address.

To hide files on the filesystem, we replaced the callback that the kernel
uses to read files in the `getdents` syscall, which is what `ls` uses to
read the files within a directory. To inject our hook into the kernel, we
modify the file ops table for any files opened, then create a trampoline
to wrap the original callback, and skipping any files with a name matching
the list of hidden files.

To send the Rootkit source code, we first tar the code and sent separate packets, 
which does not exceed 2KB to the target machine that runs Tomcat with Struts 2.
Using a vulnerability found in Multipart parser in Apache Struts 2, we write 
the code into /dev/shm, and compile the rootkit.

To install the rootkit without root privilege, we use DirtyCOW exploit, where 
a race condition in Linux kernel enables write operation to those protected files 
with setuid bit. In this case, we created a payload to backup the /usr/bin/passwd 
and overwrite it with the compilation and the installation of the rootkit, along 
with the code to finally recover /usr/bin/passwd.

## Video demo

[Here](http://dsun18.web.engr.illinois.edu/cs460rootkit.mp4) is the video demo of the Rootkit.
