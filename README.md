# JWTF?!  
  
Modes:  
  
0: Runs all  
1: Allows patching and resigns target JWT with provided public key   
2: Allows patching and rebuilds JWT with None algorithm  
  
Usage (Mode = 1):  
```
python3 jwtf.py 1 --key="test.pub" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5"
```
  
Usage (Mode = 2):  
```
python3 jwtf.py 2 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5"
```
