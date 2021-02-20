# KakaoLink-Python

`pip install kaling`

https://pypi.org/project/kaling/

Send KakaoLink with pure Python

Fork of https://github.com/pl-Steve28-lq/KakaoLink-For-Python with performance and safety improvements

외부 사이트에서 encryption을 하면 제 비번으로 뭘하는지를 몰라서ㅜㅠ 보안과 속도를 위해 AES encryption을 외부 사이트가 아닌 내부에서 파이썬으로 하는 형식으로 고쳤습니다
이제 거의 즉시 메시지가 전송됩니다!

그리고 버튼에 걸수 있는 링크는 카카오데브에서 설정한 경로 내에 있어야 합니다

### example

    from kaling import Kakao

    KakaoLink = Kakao('javascript key','website written on you kaling')
    KakaoLink.login('login email', 'login password')

    KakaoLink.send("room name",{
                "link_ver": "4.0",
                "template_object": {
                    "object_type": "feed",
                    "button_title": "",
            
                    "content": {
                        "title": "이건 제목",
                        "image_url": "imageurl",
                        "link": {
                            "web_url": "",
                            "mobile_web_url": ""
                        },
                        "description": "이건 설명"
                    },
            
                    "buttons": [{
                        "title": "링크",
                        "link": {
                            "web_url": "url",
                            "mobile_web_url": "url"
                        }
                    }]
            
                }
            })
