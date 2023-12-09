"""plugins/auth.py

Functions related to handling and checking authentication.
"""

import pyotp
import re
from selenium import webdriver
from time import sleep

from .base import Plugin


class Auth(Plugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for plugin in ['Api', 'Db', 'Users']:
            setattr(self,
                    plugin.lower(),
                    self.registry.get(plugin)(self.state))

    def get_api_token(self):
        """Log in to get a new API token."""
        if self.users.get_profile():
            return self.db.api_token
        csrf = self.get_login_csrf()
        grant_token = None
        duo_url = None
        if csrf:
            duo_url = self.get_duo_url(csrf)
        if duo_url:
            grant_token = self.get_login_grant_token(duo_url)
        if grant_token:
            url = 'https://platform.synack.com/'
            headers = {
                'X-Requested-With': 'XMLHttpRequest'
            }
            query = {
                "grant_token": grant_token
            }
            res = self.api.request('GET',
                                   url + 'token',
                                   headers=headers,
                                   query=query)
            if res.status_code == 200:
                j = res.json()
                self.db.api_token = j.get('access_token')
                self.set_login_script()
                return j.get('access_token')

    def get_login_csrf(self):
        """Get the CSRF Token from the login page"""
        res = self.api.request('GET', 'https://login.synack.com')
        m = re.search('<meta name="csrf-token" content="([^"]*)"',
                      res.text)
        return m.group(1)

    def get_duo_url(self, csrf):
        """Get Duo url"""
        headers = {
            'X-CSRF-Token': csrf
        }
        data = {
            'email': self.db.email,
            'password': self.db.password
        }
        res = self.api.login('POST',
                             'authenticate',
                             headers=headers,
                             data=data)
        if res.status_code == 200:
            return res.json().get("duo_auth_url")

    def get_login_grant_token(self, duo_url):
        """Gets grant token after Duo MFA workaround"""
        options = webdriver.FirefoxOptions()
        options.add_argument("-headless")
        options.add_argument(duo_url)
        with webdriver.Firefox(options = options) as driver:
            while True:
                check_url = driver.current_url
                if 'grant_token' in check_url:
                    grant_token = check_url.split("grant_token=",1)[1]
                    break
        return grant_token

    def get_notifications_token(self):
        """Request a new Notifications Token"""
        res = self.api.request('GET', 'users/notifications_token')
        if res.status_code == 200:
            j = res.json()
            self.db.notifications_token = j['token']
            return j['token']

    def set_login_script(self):
        script = "let forceLogin = () => {" +\
            "const loc = window.location;" +\
            "if(loc.href.startsWith('https://login.synack.com/')) {" +\
            "loc.replace('https://platform.synack.com');" +\
            "}};" +\
            "(function() {" +\
            "sessionStorage.setItem('shared-session-com.synack.accessToken'" +\
            ",'" +\
            self.db.api_token +\
            "');" +\
            "setTimeout(forceLogin,60000);" +\
            "let btn = document.createElement('button');" +\
            "btn.addEventListener('click',forceLogin);" +\
            "btn.style = 'margin-top: 20px;';" +\
            "btn.innerText = 'SynackAPI Log In';" +\
            "btn.classList.add('btn');" +\
            "btn.classList.add('btn-blue');" +\
            "document.getElementsByClassName('onboarding-form')[0]" +\
            ".appendChild(btn)}" +\
            ")();"
        with open(self.state.config_dir / 'login.js', 'w') as fp:
            fp.write(script)

        return script
