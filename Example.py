from KakaoModule import Kakao

KakaoLink = Kakao('javascript key','website written on you kaling')
KakaoLink.login('login email', 'login password')

KakaoLink.send("room name", {
    "link_ver": "4.0",
    "template_object": {
        "object_type": "feed",
        "button_title": "",

        "content": {
            "title": "이건 제목",
            "image_url": "이건 주소",
            "link": {
                "web_url": "",
                "mobile_web_url": ""
            },
            "description": "이건 설명"
        },

        "buttons": [{
            "title": "이건 버튼",
            "link": {
                "web_url": "이건 주소",
                "mobile_web_url": "이건 주소"
            }
        }]

    }
})