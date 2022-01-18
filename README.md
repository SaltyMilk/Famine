# Famine
Educational virus.

:warning: PLEASE DON'T BE STUPID: DO NOT RUN THIS ON YOUR SYSTEM. :warning:

Notes : 

A simple make will create a virus spreading only in /tmp/test and /tmp/test2

However make bonus will recursively infect EVERY binary file on the system. Use with caution.

Todo: 

* replace placeholder shellcode by infectious one ✔️
* recursive infection from root
* make virus create a network backdoor on system ✔️
* forbid execution when prog called "antivirus" is running ✔️

# Run in docker
```
./run.sh
docker exec -it famine /bin/bash 
cd /famine; make
```
# Run locally
```
cd srcs; make
```
