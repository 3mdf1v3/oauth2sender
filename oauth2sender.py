import argparse
import base64
import json
import urllib.parse
import urllib.request
import lxml.html
import smtplib
import asyncio
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from aiosmtpd.controller import Controller

GOOGLE_ACCOUNTS_BASE_URL = 'https://accounts.google.com'
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'
 
argsparser = argparse.ArgumentParser()
argsparser.add_argument('--clientid', action='store', type=str, required=True)
argsparser.add_argument('--clientsecret', action='store', type=str, required=True)
argsparser.add_argument('--refreshtoken', action='store', type=str, required=True)
args = argsparser.parse_args()

GOOGLE_CLIENT_ID = args.clientid 
GOOGLE_CLIENT_SECRET = args.clientsecret
GOOGLE_REFRESH_TOKEN = args.refreshtoken

class sendGmail:
    def command_to_url(command):
        return '%s/%s' % (GOOGLE_ACCOUNTS_BASE_URL, command)

    def url_escape(text):
        return urllib.parse.quote(text, safe='~-._')

    def url_unescape(text):
        return urllib.parse.unquote(text)

    def url_format_params(params):
        param_fragments = []
        for param in sorted(params.items(), key=lambda x: x[0]):
            param_fragments.append('%s=%s' % (param[0], sendGmail.url_escape(param[1])))
        return '&'.join(param_fragments)

    def generate_permission_url(client_id, scope='https://mail.google.com/'):
        params = {}
        params['client_id'] = client_id
        params['redirect_uri'] = REDIRECT_URI
        params['scope'] = scope
        params['response_type'] = 'code'
        return '%s?%s' % (sendGmail.command_to_url('o/oauth2/auth'), sendGmail.url_format_params(params))

    def call_authorize_tokens(client_id, client_secret, authorization_code):
        params = {}
        params['client_id'] = client_id
        params['client_secret'] = client_secret
        params['code'] = authorization_code
        params['redirect_uri'] = REDIRECT_URI
        params['grant_type'] = 'authorization_code'
        request_url = sendGmail.command_to_url('o/oauth2/token')
        response = urllib.request.urlopen(request_url, urllib.parse.urlencode(params).encode('UTF-8')).read().decode('UTF-8')
        return json.loads(response)

    def call_refresh_token(client_id, client_secret, refresh_token):
        params = {}
        params['client_id'] = client_id
        params['client_secret'] = client_secret
        params['refresh_token'] = refresh_token
        params['grant_type'] = 'refresh_token'
        request_url = sendGmail.command_to_url('o/oauth2/token')
        response = urllib.request.urlopen(request_url, urllib.parse.urlencode(params).encode('UTF-8')).read().decode('UTF-8')
        return json.loads(response)

    def generate_oauth2_string(username, access_token, as_base64=False):
        auth_string = 'user=%s\1auth=Bearer %s\1\1' % (username, access_token)
        if as_base64:
            auth_string = base64.b64encode(auth_string.encode('ascii')).decode('ascii')
        return auth_string

    def get_authorization(google_client_id, google_client_secret):
        scope = "https://mail.google.com/"
        print('Navigate to the following URL to auth:', generate_permission_url(google_client_id, scope))
        authorization_code = input('Enter verification code: ')
        response = sendGmail.call_authorize_tokens(google_client_id, google_client_secret, authorization_code)
        return response['refresh_token'], response['access_token'], response['expires_in']

    def refresh_authorization(google_client_id, google_client_secret, refresh_token):
        response = sendGmail.call_refresh_token(google_client_id, google_client_secret, refresh_token)
        return response['access_token'], response['expires_in']

    def send_mail(fromaddr, toaddr, subject, message):
        access_token, expires_in = sendGmail.refresh_authorization(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN)
        auth_string = sendGmail.generate_oauth2_string(fromaddr, access_token, as_base64=True)

        server = smtplib.SMTP('smtp.gmail.com:587')
        server.ehlo(GOOGLE_CLIENT_ID)
        server.starttls()
        server.docmd('AUTH', 'XOAUTH2 ' + auth_string)
        server.sendmail(fromaddr, toaddr, message)
        server.quit()

class smtpHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return '250 OK'
        
    async def handle_DATA(self, server, session, envelope):
        if GOOGLE_REFRESH_TOKEN is None:
            print('No refresh token found, obtaining one')
            refresh_token, access_token, expires_in = sendGmail.get_authorization(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
            print('Set the following as your GOOGLE_REFRESH_TOKEN:', refresh_token)
            exit()

        sendGmail.send_mail(envelope.mail_from, envelope.rcpt_tos, '', envelope.content)
        return '250 Message accepted for delivery'

    async def startService(loop):
        controller = Controller(smtpHandler(), hostname='127.0.0.1', port=25)
        controller.start()

if __name__ == '__main__':    
    loop = asyncio.get_event_loop()
    loop.create_task(smtpHandler.startService(loop=loop))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
