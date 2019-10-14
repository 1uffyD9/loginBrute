# loginBrute
Python3 script to Bruteforce on login page where having csrf token validation. Any suggestions, feedback, Pull requests and comments are welcome!

## Installation
```
# git clone https://github.com/1uffyD9/loginBrute.git
# cd loginBrute
# pip3 install -r requirements.txt
# chmod +x loginBrute.py
# ln -sf `pwd`/loginBrute.py /usr/local/bin/loginBrute
```

## Syntax
```
# loginBrute -t token -m post -d 'username=$U&password=$P&submitLogin=submit::incorrect.' -l http://localhost/index.php -p /usr/share/wordlists/rockyou.txt -U admin
```

### Screenshot

![image](https://user-images.githubusercontent.com/49385501/66258890-0a12f200-e7c8-11e9-9d51-28a2531a29d5.png)

