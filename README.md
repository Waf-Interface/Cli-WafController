# Cli-WafController
A cli for controlling mod security in progress.
This project is part of waf-interface.


Updating from Executable to Lib(dll or so) for using it so we removed the main.cpp.


For compiling into dll or .so for linux please run this commends after installing modsec:

```
test@test:~/Desktop/desktop$ g++ -fPIC -c waf-ghm.cpp -I/usr/local/include/modsecurity
test@test:~/Desktop/desktop$ g++ -shared -o waf-ghm.so waf-ghm.o -lmodsecurity -L/usr/local/lib
```

then you can verify for your client with this commend:

```
nm -C waf-ghm.so | grep initialize
000000000000f6b8 T WafGhm::initialize()
```
