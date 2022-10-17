import requests, json, urllib, base64
from bs4 import BeautifulSoup

BS = BeautifulSoup
from Crypto import Random
from Crypto.Cipher import AES
from hashlib import md5
from urllib import parse
import base64


class Kakao:
    def __init__(self, apiKey, your_site_address):
        if not isinstance(apiKey, str) or len(apiKey) != 32:
            raise TypeError("API 키 ( " + str(apiKey) + " ) 가 올바르지 않습니다.")
        self.apiKey = apiKey
        self.shortKey = None
        self.cookies = {}
        self.loginReferer = None
        self.cryptoKey = None
        self.parsedTemplate = None
        self.checksum = None
        self.rooms = None
        self.static = {
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36',
            'ct': 'application/x-www-form-urlencoded',
            'ka': 'sdk/1.36.6 os/javascript lang/en-US device/Win32 origin/' + urllib.parse.quote_plus(
                your_site_address)
        }

    def AES_encrypt(self, message, passphrase):

        BLOCK_SIZE = 16

        def pad(data):
            length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
            return data + (chr(length) * length).encode()

        def bytes_to_key(data, salt, output=48):
            assert len(salt) == 8, len(salt)
            data += salt
            key = md5(data).digest()
            final_key = key
            while len(final_key) < output:
                key = md5(key + data).digest()
                final_key += key
            return final_key[:output]

        message = bytes(message, 'utf-8')
        passphrase = bytes(passphrase, 'utf-8')

        salt = Random.new().read(8)
        key_iv = bytes_to_key(passphrase, salt, 32 + 16)
        key = key_iv[:32]
        iv = key_iv[32:]
        aes = AES.new(key, AES.MODE_CBC, iv)

        return base64.b64encode(
            b"Salted__" + salt + aes.encrypt(pad(message))).decode("utf-8")

    def login(self, ID, PW):
        if not isinstance(ID, str):
            raise TypeError("아이디의 타입 " + type(ID) + " 가 올바르지 않습니다.")
        elif not isinstance(PW, str):
            raise TypeError("비밀번호의 타입 " + type(PW) + "가 올바르지 않습니다.")

        def loginManager():
            connect = requests.post(
                'https://sharer.kakao.com/talk/friends/picker/link',
                headers={'User-Agent': self.static['ua']},
                data={
                    'app_key': self.apiKey,
                    'validation_action': 'default',
                    'validation_params': '{}',
                    'ka': self.static['ka'],
                    'lcba': ''
                }
            )

            status = connect.status_code
            if status == 401:
                raise ValueError('API 키가 유효하지 않습니다.')
            if status != 200:
                raise Exception('예상치 못한 오류로 로그인에 실패했습니다.')

            self.cookies['_kadu'] = connect.cookies.get('_kadu')
            self.cookies['_kadub'] = connect.cookies.get('_kadub')
            self.cookies[
                '_maldive_oauth_webapp_session_key'] = connect.cookies.get(
                '_maldive_oauth_webapp_session_key')
            self.loginReferer = connect.url
            ctx = BS(connect.content, 'html.parser')
            self.cryptoKey = ctx.find('input', {'name': 'p'}).get('value')

        def tiara():
            tiara = requests.get(
                'https://stat.tiara.kakao.com/track?d=%7B%22sdk%22%3A%7B%22type%22%3A%22WEB%22%2C%22version%22%3A%221.1.15%22%7D%7D'
            ).cookies.get('TIARA')
            self.cookies['TIARA'] = tiara

        def authenticate():
            connect = requests.post(
                'https://accounts.kakao.com/weblogin/authenticate.json',
                headers={
                    'User-Agent': self.static['ua'],
                    'Referer': self.loginReferer
                },
                cookies=self.cookies,
                data={
                    'os': 'web',
                    'webview_v': '2',
                    'email': self.AES_encrypt(ID, self.cryptoKey),
                    'password': self.AES_encrypt(PW, self.cryptoKey),
                    'continue': parse.unquote(
                        self.loginReferer.split('continue=')[1]),
                    'third': 'false',
                    'k': 'true',
                }
            )
            result = json.loads(connect.text)
            if result['status'] == -450:
                raise ValueError("아이디나 비밀번호가 잘못 되었습니다.")
            elif result['status'] != 0:
                raise Exception(
                    str(result['status']) + ' > 예상치 못한 오류로 로그인에 실패했습니다.')

            self.cookies['_kawlt'] = connect.cookies.get('_kawlt')
            self.cookies['_kawltea'] = connect.cookies.get('_kawltea')
            self.cookies['_karmt'] = connect.cookies.get('_karmt')
            self.cookies['_karmtea'] = connect.cookies.get('_karmtea')

        loginManager()
        tiara()
        authenticate()

    def send(self, roomTitle, data, sendtype='default'):
        def proceed():

            connect = requests.post(
                'https://sharer.kakao.com/picker/link',
                headers={
                    'User-Agent': self.static['ua'],
                    'Referer': self.loginReferer
                },
                cookies={
                    'TIARA': self.cookies['TIARA'],
                    '_kawlt': self.cookies['_kawlt'],
                    '_kawltea': self.cookies['_kawltea'],
                    '_karmt': self.cookies['_karmt'],
                    '_karmtea': self.cookies['_karmtea']
                },
                data={
                    'app_key': self.apiKey,
                    'validation_action': sendtype,
                    'validation_params': json.dumps(data),
                    'ka': self.static['ka'],
                    'lcba': ''
                }
            )

            if connect.status_code == 400:
                raise TypeError('템플릿의 변수가 올바르지 않습니다.')

            encodedData = \
                connect.content.decode("utf8").strip().split("serverData = \"")[1].split("\";")[0]
            encodedData = f"{encodedData}{'=' * (len(encodedData) % 4)}"
            decodedData = json.loads(
                base64.b64decode(encodedData).decode("utf8"))

            self.shortKey = decodedData["data"]["shortKey"]
            self.csrfToken = decodedData["data"]["csrfToken"]
            self.checksum = decodedData["data"]["checksum"]
            self.rooms = decodedData["data"]["chats"]
            self.cookies["_csrf"] = connect.cookies.get('_csrf')

        proceed()

        def sendTemplate():
            receiver = None
            for room in self.rooms:
                if room['title'] == roomTitle:
                    receiver = base64.b64encode(
                        json.dumps(room, ensure_ascii=False).encode(
                            "utf8")).decode("utf8")
                    break
            if not receiver: raise ReferenceError(
                'invalid room name ' + roomTitle)

            connect = requests.post(
                'https://sharer.kakao.com/picker/send',
                headers={
                    'User-Agent': self.static['ua'],
                    'Referer': 'https://sharer.kakao.com/talk/friends/picker/link',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                cookies={
                    'TIARA': self.cookies['TIARA'],
                    '_kadu': self.cookies['_kadu'],
                    '_kadub': self.cookies['_kadub'],
                    '_kawlt': self.cookies['_kawlt'],
                    '_kawltea': self.cookies['_kawltea'],
                    '_karmt': self.cookies['_karmt'],
                    '_karmtea': self.cookies['_karmtea'],
                    '_csrf': self.cookies['_csrf']
                },
                data={
                    "app_key": self.apiKey,
                    "short_key": self.shortKey,
                    "_csrf": self.csrfToken,
                    "checksum": self.checksum,
                    "receiver": receiver
                }
            )

        sendTemplate()
