# Famine
Educational virus.

:warning: PLEASE DON'T BE STUPID: DO NOT RUN THIS ON YOUR SYSTEM. :warning:

Todo: 

* replace placeholder shellcode by infectious one
* recursive infection from root
* make virus create a setuid backdoor on system
* forbid execution when prog called "antivirus" is running
* make virus launch at boot

# Run in docker
```
./run.sh
docker exec -it famine /bin/bash 
cd /famine/srcs; make
```
# Run locally
```
cd srcs; make
```
