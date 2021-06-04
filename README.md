# REMARKS ON ROGER SKYLINE 1 (NETWORK ADMINISTRATION)

The objective of the École42 project ‘Roger Skyline 1’ is to create a Virtual Machine and configure it to function as a web server. The requirements for the project were the following:  
* Disk size of 8GB  
* At least one 4.2GB partition  
* Version and packages must be up to date
* Create a non-root user with sudo privileges
* Change the DHCP service to a static IP and a Netmask of \30
* Change the default SSH port to one of your choice. SSH access must be done with public keys, SSH root access should not be allowed directly
* Set up a firewall
* Set up a DOS protection on your open ports
* Stop services not needed for this project
* Create a script that updates and upgrades packages and logs them in a file. This script must run once a week at 4AM and every time the machine reboots
* Create a script to monitor changes of the /etc/crontab file and sends an email to root if it has been modified. This script should run every day at midnight
* Set up a web server that is available on your VM’s IP
* Set up a self-signed SSL
* Create a web page
* Propose a functional solution for deployment automation of your web page
  
## How-to guide
  
### Creating a virtual machine
Download a new debian disk image from https://www.debian.org/CD/netinst/ (i used the amd64 from the ‘netinst CD image (generally 150-300 MB, varies by architecture)’ side).  
  
First, you will want to create a new Virtual Machine. Open your (or install) VirtualBox and press ‘New’ to create a new VM. Name it however you want and set type to ‘Linux’ and version to ‘Debian (64-bit)’. The default memory size, which is set to 1024MB is ok, press continue. Many of the following presets are ok, cruise through with continue. 
At File location and size, check that the size is set to 8GB.
Then, from the ‘Storage’ area of the VirtualBox, click [optical Drive] and choose the disk image you downloaded earlier.
  
Start your VM. Installation will be fairly simple, default settings for ex. concerning partitions are fine (in the first partition slide, choose ‘Guided - use entire disk’). Changes to partition sizes can be made later. In the software selection part, I only chose SSH server and standard system utilities, the webserver can be downloaded later.  In ‘Install the GRUB boot loader’, check yes and in the next slide, select the option ‘/dev/sda’
  
### Inside the VM
#### Adding a user and making it a ‘sudoer’
To use sudo, it must be installed first as root with   `apt-get install sudo`  
To create a new user		`adduser username`  
To add user to sudoers	`usermod -aG sudo username`  
To see users in sudoers group	`grep 'sudo' /etc/group`
  
#### Changing partition sizes
To see partitions		`sudo fdisk -l`  
To modify partitions		`sudo cfdisk`  
After, choose the partition you want to resize and write changes to disk.  
The thing to note here, is that with fdisk and cfdisk the sizes are actually expressed as GiB, not GB. So if while creating the VM, a partition of size 4.2GB was added, it will show up as 3.9G (GiB). (1 GB is  1 * 0.931323 GiB)  
  
#### Configuring the network interfaces
To see what network interfaces you have in your use    `ip link show`  
To enable a static ip, modify the file **/etc/network/interfaces**  so that the enp0s3
that’s previously stated `iface enp0s3 inet dhcp` to `iface enp0s3 inet static`  
To configure the ip address, there’s two possibilities: either add the following info under the line just modified in the interfaces file or define your network interfaces separately in the directory **/etc/network/interfaces.d**.  

*I like using Vim to edit files, also vim has to be separately installed with `sudo apt-get install vim` and when using it, if you want to save changes you make to files, always use sudo to open a file (sudo vim filename).*  
  
Change the network in your VirtualBox settings to bridged adaptor.
To find out the default gateway on your host computer, run `netstat -r -n | grep default | head -n 1 | awk '{print $2}'`	use this as your gateway. (In my case it is 10.11.254.254)  
  
#### Subnetting for Roger Skyline
Subnetting is the process of designating some high order bits from the host part as part of a network prefix and adjusting the subnet mask accordingly. This divides the network into smaller subnets.
 All hosts on the same network have the same network prefix, which occupies the most significant bits of the address. 
  
To find the Mac’s ip address your working on, use the normal terminal and check `ifconfig -a`  
In the subject, the new netmask is defined to \30, which means it is **255.255.255.252** as opposed to for ex \32 where all the bytes are used (255.255.255.255 and can only serve one host).  
  
#### Choosing an ip address
The static IP must be a part of my current cluster 1’s subnet (meaning 10.11.) I am free to choose the IP address, but I should check before that it’s not currently being used.  
So, with the host Mac, ping 10.11.16.16 or whatever ip you choose. If it’s free, there will be a timeout.  
 So I’ve chosen **10.11.16.16**. With my netmask, the range of my subnet is 10.11.16.16 - 10.11.16.19. The largest IP address will become the broadcast address.  
I will edit the file **/etc/network/interfaces** by adding  
```
iface eth0 inet static  
	address 10.11.16.16  
	netmask 255.255.255.252  
	gateway 10.11.254.254  
	dns-nameservers 8.8.8.8 8.8.4.4
```
	    (--->the dns servers are free google public servers)  
  
In general, after making changes to network rules, restart network with
`sudo service networking restart`  
Often, after doing this, if `ip a` shows that enp0s3 is “DOWN”, you should
`sudo ifup enp0s3` 	to get it to run again.  
  
  
#### Setting up public key authentication with OpenSSH
SSH keys are typically configured in an authorized_keys file in the directory .ssh. New keys can be generated using the ssh-keygen program and the ssh-copy-id tool to put them in the right file.  
  
#### Changing the default SSH port
To prevent automated bot attacks, it’s wise to change the SSH port from the default (port 22) to something else. To connect through SSH a user needs the public ip address and the port number alongside a username and password.  
ICAAN classifies ports in three categories:  
system/well-known ports 0-1023  
User or registered ports 1024-49151  
dynamic/private ports 49152-65535  
  
So I have chosen a port number from the last category (**51111**). To change the port, edit the file **/etc/ssh/sshd_config** and find the line `# Port 22`. Remove the hash and write your new port number.   
Uncomment also `#PasswordAuthentication` and have it momentarily on ‘yes’ so you can initially place keys from your host Mac into your user’s **.ssh** folder (this is only temporary, because it is a security hazard).   

    
#### Configuring SSH-keys (RSA keys) in practice
Do the following on your host Mac:  
`ssh-keygen`		The prompt asks if you want to save the key (the private one) in the default file /home/your_user_name/.ssh/id_rsa	press enter. Now that you list everything in the .ssh directory (which was empty if you didn’t do anything to it yet) there is a file id_rsa and id_rsa.pub (which has the public key).  
`ssh-copy-id your_user_name@<ip_address> -p [your port number]`  
This will copy the keys to **.ssh/authorized_keys**  
Use this copy method if you want to add keys to another server. Just change the user_name and ip address info. It will append the new key to its own line in the other user’s authorized_keys file.  
  
#### Allow SSH connections only with public keys
First it’s smart to share the keys w users you want to share with, because after this next step that will become a lot harder.
  
Run `sudo service sshd restart` (if you have changed something in the sshd_config file) on your VM and after connect from host mac to your VM with
`ssh username@<ip address> -p [your new port number]`  
It will ask for the user’s password, this we will change.  
You are now connected to the VM and if you want to exit, type ‘exit’.  
Better at this point to edit the sshd_config file again and switch Password authentication to ‘no’. After this if you connect again from the host Mac, it should only connect through ssh keys and only ask for the password of the key (not your VM user’s password).  
  
Now if you try ssh connection with a server that doesn’t have your public key, it will give a denial.
As stated in the subject for Roger-Skyline, root access MUST NOT be allowed with ssh connection. So open **/etc/ssh/sshd_config** again and uncomment `PermitRootLogin`, delete the ‘prohibit-password’ and write ‘no’ in its place.
  
#### Firewall
An easy firewall to use in debian is *ufw* (uncomplicated firewall). 
`sudo apt-get install ufw`  
`sudo ufw enable`		(it may be disabled the same way with disable)  
`sudo ufw default deny incoming`  
`sudo ufw default allow outgoing`		(and `sudo ufw status verbose` to see if changes were made)  
  
Next, I allowed traffic on my ssh, http, https ports  
`sudo ufw allow 51111`  
`sudo ufw allow 80`		(http)  
`sudo ufw allow 443`		(https)  
  
Further configuring the firewall:
Open **/etc/ufw/before.rules**
I found the following from a couple of sites; rules to limit connections per IP (20 connections/10 seconds/ip) and the packets to (20 packets / 1 second / packet)
(FROM http://bookofzeus.com/harden-ubuntu/hardening/protect-ddos-attacks/)  
  

I added this under the '*filter' at the beginning:
```
:ufw-http - [0:0]
:ufw-http-logdrop - [0:0]
```
I wrote the following rules before COMMIT line  
```
### Start HTTP ###

# Enter rule
-A ufw-before-input -p tcp --dport 80 -j ufw-http
-A ufw-before-input -p tcp --dport 443 -j ufw-http

# Limit connections per Class C
-A ufw-http -p tcp --syn -m connlimit --connlimit-above 50 --connlimit-mask 24 -j ufw-http-logdrop

# Limit connections per IP
-A ufw-http -m state --state NEW -m recent --name conn_per_ip --set
-A ufw-http -m state --state NEW -m recent --name conn_per_ip --update --seconds 10 --hitcount 20 -j ufw-http-logdrop

# Limit packets per IP
-A ufw-http -m recent --name pack_per_ip --set
-A ufw-http -m recent --name pack_per_ip --update --seconds 1 --hitcount 20 -j ufw-http-logdrop

# Finally accept
-A ufw-http -j ACCEPT

# Log
-A ufw-http-logdrop -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW HTTP DROP] "
-A ufw-http-logdrop -j DROP

### End HTTP ###
```
  
#### Download PortSentry to detect port scans
Information concerning PortSentry I found at (https://www.computersecuritystudent.com/UNIX/UBUNTU/1204/lesson14/index.html)  
  
`sudo apt-get install portsentry`  
PortSentry does not block by default, it must be configured at **/etc/portsentry/portsentry.conf**
  
##### Testing port scanning  
One way to test port scanning, is to install nmap for ex. on your host computer.  
To check port scanning, run `nmap -A 10.11.16.16` (or whatever is the ip address)  
I’ve disabled my ufw protection on my roger_skyline VM and after running nmap on the “attacker”, I ran `sudo cat /var/log/syslog`	where I should see lines with “attackalert” and the ip address that is trying to scan ports. On the same time on the attacker VM, we can see a list of open TCP ports. After enabling the “ufw” firewall and performing this sequence again, on the main VM it now only says “[UFW BLOCK]” and the source ip. On the attacker VM, nmap only finds ports 80 and 443, which it tells are closed.  
  
##### Configuring PortSentry
Open **/etc/portsentry/portsentry.conf** 	and find the lines that start with “BLOCK_UDP=” and “BLOCK_TCP=”
(in my case, it was on line 135 and 136)  
Edit both, so that for ex. BLOCK_UDP=”0” becomes “1”  
Also, check that all lines starting with “KILL_ROUTE” are commented out, except one that ends “DROP”.
Open /etc/default/portsentry and change settings to TCP=”atcp” and UDP=”audp” (advanced tcp and udp) This will close the unused ports.
Also, open /etc/hosts.deny and uncomment the last row “ALL: PARANOID”  
  
Stop PortSentry and restart it
`sudo service portsentry stop`  
`sudo service portsentry start`  
Now, try nmap again (check that ufw is disabled, so portsentry is more important).  
`nmap -A 10.11.16.16`		will start Nmap and seem to freeze. If we check the **/var/log/syslog** 
on the roger skyline VM, it will show attackeralert and that Host: 10.11.**.** is already blocked  
`telnet 10.11.16.16`	will show first that it’s trying to connect. After a while, it will say that “telnet:Unable to connect to remote host: Connection timed out”  
`ping -c 5 10.11.16.16`		it will say “5 packets transmitted, 0 received, 100% packet loss, time 79ms”
After, we can check from our Roger VM that the attacker has indeed been blocked.  
`sudo cat /etc/hosts.deny`	will show that “ALL: 10.11.71.71 : DENY” the ip has been blocked and so has the ssh connectivity  
`grep -n Blocked /var/lib/portsentry/portsentry.blocked.tcp`	shows the ip’s that are blocked for tcp scans  
`grep -n Blocked /var/lib/portsentry/portsentry.blocked.udp`	shows the ip’s that are blocked for udp scans  
To unblock an address, remove the line concerning the ip from **/etc/hosts.deny**, restart portsentry and reboot the whole VM with `sudo reboot`
  
#### Fail2ban
For more protection against ddos attacks, download fail2ban `sudo apt-get install fail2ban`  
To further configure fail2ban, copy the original jail.conf file into .local and modify it, don’t modify jail.conf directly.  
`sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local`  
The only thing I edited, was inserted my ssh port number into lines defining the ssh port and added to the end of file rules relating to http-get-dos:
```
[http-get-dos]
Enabled = true
Port = http,https
Filter = http-get-dos
Logpath = /var/log/apache2/access.log
Maxentry = 300
Findtime = 300
Bantime = 600
Action = iptables[name=HTTP, port=http, protocol=tcp]
```
`sudo service fail2ban restart`  
If you want to for ex ban someones ssh access manually, run
`sudo fail2ban-client set ssh banip 10.11.32.32`  
Then, if you check `sudo iptables -L`, the banned ip address will be listed in regards to ssh access.  
  
#### Add http-get-dos configurations to fail2ban
First, test without configuration. Download slowloris on your Mac, go to the folder to which you saved it (for me, it was home/Library/Python/3.9/lib/python/site-packages) and try attacking your VM with
`python3 slowloris.py 10.11.16.16`
This will start sending headers to your ip address, socket count will start at 19.
To protect your ip from these ddos attacks, create new file
`sudo vim /etc/fail2ban/filter.d/http-get-dos.conf`
And add
```
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*
ignoreregex =
```
After saving, restart fail2ban  
Perform another attack from your Mac and see how this time socket count has dropped to 0.
Check your fail2ban jail situation: `sudo fail2ban-client status` should show that you have 2 jails listed (sshd and http-get-dos). To further examine the http-get-dos jail, run `sudo fail2ban-client status http-get-dos`  
You should see the ip address of your Mac in the banned ip list.  
To unban an address, run `sudo fail2ban-client unban --all`  
  
### Stopping unnecessary services
There’s many ways to list active services, but for my liking the most straightforward is to run
`sudo systemctl list-unit-files --state=enabled`
Or `sudo service --status-all`  
Basically, all services that were listed with the second command are important!  
* Apache2 -- webserver
* Apparmor -- Mandatory Access Control framework
* Cron -- takes care of scheduled tasks
* Dbus -- network time synchronization
* Exim4 -- mail services
* Fail2ban -- one of the firewall services (ddos attacks)
* Kmod -- control kernel modules (insert, remove, load)
* Networking -- network connection, static ip
* Portsentry -- protects against port scans
* Procps -- process commands (kill, top, ps)
* Rsyslog -- takes care of logging
* Ssh -- secure shell (access from outside world etc w keys)
* Udev -- device file system (launch config files etc)
* Ufw -- firewall, used to open/close ports and to designate them
  
## SCRIPTS
To automate certain system updates, I created a new directory called “scripts” in my home directory and wrote bash scripts in it.  
  
#### Script to update and upgrade packages
```
#!/bin/bash
date >> /var/log/update_script.log
sudo apt-get update >> /var/log/update_script.log
sudo apt-get upgrade -y >> /var/log/update_script.log
```
This updates the package sources and upgrades the packages. It also logs the output of both commands into the designated file.
To automate this script to run at 4AM every week on Wednesday, I opened crontab with
`crontab -e` 
and wrote under the commented section 
```
0 4 * * 3 sudo bash ~/scripts/update_and_log_packages.sh
@reboot sudo bash ~/scripts/update_and_log_packages.sh
```
This will schedule the script to run at 4AM on Wednesdays and also on system reboot.  
  
If cron has a problem running the script, mail will be sent to the user whose script is in question. If the problem is ‘tty access’, you can modify the file **/etc/sudoers** and add a line 
`user_name ALL=(ALL) NOPASSWD:ALL`  
This way, cron doesn’t need a password to run sudo commands or to modify certain files.
  
#### Script to monitor changes in /etc/crontab and to send email to root
Save the current state of your crontab with cat /etc/crontab > cron_orig.txt
Create a new bash file called cron_changes.sh and add in it:
```
#!/bin/bash
if [[ $(diff /etc/crontab cron_orig.txt) ]]; then
	mail -s “Changes in crontab” root@localhost <<< ‘$(diff /etc/crontab cron_orig.txt)’
	cat /etc/crontab > cron_orig.txt
fi
```
This will compare the current state of the crontab file with the original one with diff. If there is a difference, an email will be sent to root. The email can be checked as a root or with sudo from **/var/mail/** 	The file your email will be found at, will be that with the name of your original user that your made when you created the VM. This is a security feature of debian; mail addressed to root will be found with the original user.
  
To schedule the script to run at midnight, run `crontab -e and` add
`0 0 * * * sudo bash /home/roger_user/scripts/cron_changes.sh`  

## Website part

Download apache if you haven’t already with
`sudo apt-get install apache2`
  
### SSL 
(mostly from https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-debian-10)  

`sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt`

This will create a 2048 bit rsa key, will be valid for a year. 'Nodes' means that it will not require a passphrase.  

Next you will be asked to fill in information for your certificate. The most important fields are
``
Common Name (e.g. server FQDN or YOUR name) []:server_IP_address
Email Address []:admin@your_domain.com
``
Here, you should write down your server ip address and email for ex. in the form of root@domain.hostname (however you have yours)
  
#### Configuring apache to use SSL
Open a new file which will include a configuration snippet
`sudo vim /etc/apache2/conf-available/ssl-params.conf`  
And paste this in it:
```
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLHonorCipherOrder On
# Disable preloading HSTS for now.  You can use the commented out header line that includes
# the "preload" directive if you understand the implications.
# Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
# Requires Apache >= 2.4
SSLCompression off
SSLUseStapling on
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
# Requires Apache >= 2.4.11
SSLSessionTickets Off
```
Next, we must modify the default Apache SSL Virtual Host File  
Copy the original into
`sudo cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf.bak`
  
Open the original and change the lines relating to your ServerAdmin email, the name of the ssl certificate anc the name of the private key to what you chose earlier. You must also add a line after the ServerAdmin, stating your ServerName as your ip address.  

Open the file 
**sudo vim /etc/apache2/sites-available/000-default.conf** 
and add a line somewhere between the VirtualHost *:80 opening and closing brackets to redirect all traffic to https
```
<VirtualHost *:80>
        . . .

        Redirect permanent "/" "https://10.11.16.16/"

        . . .
</VirtualHost>
```
  
#### Enabling changes in Apache
Type the following commands to make sure ssl and headers are enabled  
`sudo a2enmod ssl`  
`sudo a2enmod headers`  
`sudo a2ensite default-ssl`  
`sudo a2enconf ssl-params`  
  
Next, check that the configurations don’t have syntax errors:  
`sudo apache2ctl configtest`  
If this outputs “Syntax OK”, we can restart apache  
`sudo systemctl restart apache2`  

### Displaying your website
Already now, that the apache is up and running, going to your ip address with a browser will display the default Apache index.html file with some information. To display your own website, go to
`cd /var/www/html`	remove the default index.html (or name it something else) and save all your website files and subfolders in this **/var/www/html** folder. (Your own index.html must be at the root)  
Restart Apache and check the browser for your new website!  

### Script to automate website deployment
Say I work on my website files outside of the VM in Visual studio code for example. To deploy the changes, I could always download my git repository in my virtual machine, but I find this too much work, because I would have to download the git commands etc in my VM.
So, I have decided to use ssh connection to copy my website files to a folder website_updates which can be found in the home folder of my VM user. From there the files will be copied into the **/var/www/html** folder if changes are found. Do not try to copy the files directly with ssh to this folder, because root access has been denied and the /var/ folder does not belong to your user.
So from my Mac, from the folder with my website files:  
`scp -r -P 51111 * roger_user@10.11.16.16:~/website_updates`  

My script to check for changes and deploy the website is as follows:  
```
#!/bin/bash
if [[ $(diff -rq /home/roger_user/website_updates  /var/www/html) != “”]]; then
	sudo cp -r /home/roger_user/website_updates/* /var/www/html/
fi
```
I have scheduled this check to happen automatically at midnight (from the crontab)  
`0 0 * * * sudo bash /home/roger_user/scripts/deploy_update_website.sh`
  
If the website has many images and loading them on the webpage is very slow, your partitioning might need more swap space. This also can be added with `sudo cfdisk`  
