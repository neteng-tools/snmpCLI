# snmpCLI
CLI snmp scanner tool that supports cisco AES256. You can scan one device or an entire network!
```
C:\windows\system32>.\snmpCLI.exe -h
-a string
        Provide Authentication Password
```
```
  -at string
        Enter SNMPv3 Auth Type.
                -at SHA
                -at SHA256
                -at SHA512 (default "SHA")
```
```
  -c string
        Set snmp community string or v3 User Name.
                -c v3User (default "public")
```
```
  -m string
        Set snmp method.
                -m Get
                -m Walk. (default "Get")
```
```
  -o string
        Enter OIDs to grab separated by a comma. You can also use this for a Walk (Ex. 1.3.6) (default "1.3.6.1.2.1.1.1.0")
```
```
  -p string
        Provide Privacy Password
```
```
  -pt string
        Enter SNMPv3 Priv Type.
                -pt AES
                -pt AES192
                -pt AES256 (default "AES")
```
```
  -t string
        Define target devices. (-t 10.0.0.1 or -t 10.0.0.1-100 or -t 10.0.0.1,10.0.0.2)
```
```
  -v string
        Set snmp version.
                -v 1
                -v 2c
                -v 3 (default "3")
```
```
  -vv
        Enable verbose output

        Ex: .\snmpCLI.exe -t 10.0.0.0-150 -c v3User -m Get -v 3 -p PrivPass -pt AES256 -a AuthPass -at SHA512 -o 1.3.6.1.2.1.1.1.0
```
The above example makes a call to every IP in the 10. range specified with the given credentials with a GET request to 1.3.6.1.2.1.1.1.0 which will look for snmpDeviceName. If you're using the base auth/priv types you don't need to specify them. 
