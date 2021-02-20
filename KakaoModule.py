import requests, json, urllib, base64
from bs4 import BeautifulSoup
BS = BeautifulSoup
from Crypto import Random
from Crypto.Cipher import AES
from hashlib import md5
 
class Kakao:
    def __init__ (self, apiKey, your_site_address):
        if not isinstance (apiKey, str) or len (apiKey) != 32:
            raise TypeError("API 키 ( " + str(apiKey) + " ) 가 올바르지 않습니다.")
        self.apiKey = apiKey
        self.cookies = {}
        self.loginReferer = None
        self.cryptoKey = None
        self.parsedTemplate = None
        self.csrf = None
        self.static = {
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36',
            'ct': 'application/x-www-form-urlencoded',
            'ka': 'sdk/1.36.6 os/javascript lang/en-US device/Win32 origin/'+urllib.parse.quote_plus(your_site_address)
        }
    
    def AES_encrypt(self, message, passphrase):

            BLOCK_SIZE = 16
            def pad(data):
                    length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
                    return data + (chr(length)*length).encode()

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
            key_iv = bytes_to_key(passphrase, salt, 32+16)
            key = key_iv[:32]
            iv = key_iv[32:]
            aes = AES.new(key, AES.MODE_CBC, iv)
            
            return base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(message))).decode("utf-8") 

    def login (self, ID, PW):
        if not isinstance (ID, str):
            raise TypeError("아이디의 타입 " + type(ID) + " 가 올바르지 않습니다.")
        elif not isinstance (PW, str):
            raise TypeError("비밀번호의 타입 " + type(PW) + "가 올바르지 않습니다.")

        def loginManager():
            connect = requests.post(
                'https://sharer.kakao.com/talk/friends/picker/link',
                headers = {'User-Agent' : self.static['ua']},
                data = {
                    'app_key' : self.apiKey,
                    'validation_action' : 'default',
                    'validation_params' : '{}',
                    'ka' : self.static['ka'],
                    'lcba' : ''
                }
            )

            status = connect.status_code
            if status == 401:
                raise ValueError('API 키가 유효하지 않습니다.')
            if status != 200:
                raise Exception('예상치 못한 오류로 로그인에 실패했습니다.')

            self.cookies['_kadu'] = connect.cookies.get('_kadu')
            self.cookies['_kadub'] = connect.cookies.get('_kadub')
            self.cookies['_maldive_oauth_webapp_session'] = connect.cookies.get('_maldive_oauth_webapp_session')
            self.loginReferer = connect.url
            ctx = BS(connect.content, 'html.parser')
            self.cryptoKey = ctx.find('input', {'name' : 'p'}).get('value')

        def tiara():
            tiara = requests.post(
                'https://track.tiara.kakao.com/queen/footsteps'
            ).cookies.get('TIARA')
            self.cookies['TIARA'] = tiara

        def authenticate():
            connect = requests.post(
                'https://accounts.kakao.com/weblogin/authenticate.json',
                headers = {
                    'User-Agent' : self.static['ua'],
                    'Referer' : self.loginReferer
                },
                cookies = self.cookies,
                data = {
                    'os' : 'web',
                    'webview_v' : '2',
                    'email' : self.AES_encrypt(ID, self.cryptoKey),
                    'password' : self.AES_encrypt(PW, self.cryptoKey),
                    'continue': self.loginReferer.split('continue=')[1],
                    'third': 'false',
                    'k': 'true',
                }
            )
            result = json.loads(connect.text)
            if result['status'] == -450:
                raise ValueError("아이디나 비밀번호가 잘못 되었습니다.")
            elif result['status'] != 0:
                print(result)
                raise Exception(str(result['status']) + ' > 예상치 못한 오류로 로그인에 실패했습니다.')

            self.cookies['_kawlt'] = connect.cookies.get('_kawlt')
            self.cookies['_kawltea'] = connect.cookies.get('_kawltea')
            self.cookies['_karmt'] = connect.cookies.get('_karmt')
            self.cookies['_karmtea'] = connect.cookies.get('_karmtea')

        loginManager()
        tiara()
        authenticate()
    

    def send (self, roomTitle, data, sendtype='default'):
        def proceed ():
            
            connect = requests.post(
                'https://sharer.kakao.com/talk/friends/picker/link',
                headers = {
                    'User-Agent' : self.static['ua'],
                    'Referer' : self.loginReferer
                },
                cookies = {
                    'TIARA' : self.cookies['TIARA'],
                    '_kawlt' : self.cookies['_kawlt'],
                    '_kawltea' : self.cookies['_kawltea'],
                    '_karmt' : self.cookies['_karmt'],
                    '_karmtea' : self.cookies['_karmtea']
                },
                data = {
                    'app_key' : self.apiKey,
                    'validation_action' : sendtype,
                    'validation_params' : json.dumps(data),
                    'ka' : self.static['ka'],
                    'lcba' : ''
                }
            )

            if connect.status_code == 400:
                raise TypeError('템플릿의 변수가 올바르지 않습니다.')
            self.cookies['KSHARER'] = connect.cookies.get('KSHARER')
            self.cookies['using'] = 'true'
            
            ctx = BS(connect.content, 'html.parser')

            self.parsedTemplate = json.loads(ctx.find('input', {'id' : 'validatedTalkLink'}).get('value'))
            self.csrf = ctx.find_all('div')[-1].get('ng-init').split('\'')[1]

        proceed ()

        def getRooms():
            connect = requests.get(
                'https://sharer.kakao.com/api/talk/chats',
                headers = {
                    'User-Agent' : self.static['ua'],
                    'Referer' : 'https://sharer.kakao.com/talk/friends/picker/link',
                    'Csrf-Token' : self.csrf,
                    'App-Key' : self.apiKey
                },
                cookies = self.cookies
            )
            document = connect.text.replace(u'\u200b','')
            self.rooms = json.loads(document)
            
        getRooms ()

        def sendTemplate():
            id, securityKey = None, None
            for room in self.rooms['chats']:
                if(room['title'] == roomTitle):
                    id = room['id']
                    securityKey = self.rooms['securityKey']
                    break
            if not id: raise ReferenceError('invalid room name ' + roomTitle)
            connect = requests.post(
                'https://sharer.kakao.com/api/talk/message/link',
                headers = {
                    'User-Agent' : self.static['ua'],
                    'Referer' : 'https://sharer.kakao.com/talk/friends/picker/link',
                    'Csrf-Token' : self.csrf,
                    'App-Key' : self.apiKey,
                    'Content-Type' : 'application/json;charset=UTF-8'
                },
                cookies = {
                    'KSHARER': self.cookies['KSHARER'],
                    'TIARA': self.cookies['TIARA'],
                    'using': self.cookies['using'],
                    '_kadu': self.cookies['_kadu'],
                    '_kadub': self.cookies['_kadub'],
                    '_kawlt': self.cookies['_kawlt'],
                    '_kawltea': self.cookies['_kawltea'],
                    '_karmt': self.cookies['_karmt'],
                    '_karmtea': self.cookies['_karmtea']
                },
                data = json.dumps({
                    'receiverChatRoomMemberCount': [1],
                    'receiverIds': [id],
                    'receiverType': 'chat',
                    'securityKey': securityKey,
                    'validatedTalkLink': self.parsedTemplate
                }).encode('utf-8')
            )
        sendTemplate()
