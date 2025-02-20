# Hardening Linux

- Hash (md5) over files from **/bin**, **/usr/bin**, **/sbin**, **/usr/sbin**
- Hash (md5) over **.so** files from **.so** files in **/usr/lib**, **/lib**, or **/lib64**
- Watch out for changes from **/etc/network/interfaces**, maybe they added a new interface
- Extract the users and groups for each one
- Extract the list of users with interactive shell
- Extract the list of services
- Extract permissions for **/etc/passwd**, **/etc/shadow**
- Extract links to **/etc/shadow**
- List loaded kernel modules: **/etc/modules-load.d/**
- Get "Global Initialization Scripts": Review changes in global initialization scripts, such as **/etc/profile**, **/etc/bash.bashrc**, or **/etc/environment**
- List of **/etc/inittabs** (This contains a table of processes to start automatically on bootup)
- **/etc/init.d/** -> Contains scripts for starting and stopping applications at Boot time
- **/etc/rc.local** -> It is executed after all the normal system services are started
- **/home/*/.bash_history** (Check for juicy stuff)
- List of newly created files in past 5 days ? (Or idk)
- List of **/etc/crontab**, **/etc/cron.**

