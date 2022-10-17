# KakaoLink-Python

Send KakaoLink with pure Python

2022년 10월 17일 기준 정상작동합니다!

### example

    # from kaling import Kakao
    from KakaoModule import Kakao

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
