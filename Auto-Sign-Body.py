#/usr/bin/python3
#coding=utf-8

from mitmproxy import ctx, http
from mitmproxy.tools.main import mitmdump
import hashlib, json, re, sys

'''
使用方式：
（1）
默认的监听端口8888：
python Auto-Sign-Body.py
自定义监听端口：
python Auto-Sign-Body.py -p 9999
（2）
不同的应用系统需要更改脚本中的 flow.request.host 值和 SecretKey 值
'''

def md5(str):
    m5 = hashlib.md5()
    m5.update(str.encode('utf-8'))
    return m5.hexdigest()

def createsign(a, b):
    signtext = "{http_body_data}{SecretKey}".format(http_body_data=a, SecretKey=b)
    Sign = md5(signtext)
    return Sign, signtext

class Modify:
    def request(self, flow):
        if flow.request.method == "POST" and flow.request.host == "www.XXX.com" and re.search('^{.*}$', flow.request.get_text(), re.I):
            try:
                http_body = flow.request.get_text()			  # 获取请求包中body的dict类型数据
                http_body = json.loads(http_body)             # str => dict
                http_body1 = json.dumps(http_body, ensure_ascii=False)
                http_body_data = json.dumps(http_body["data"], ensure_ascii=False).replace(' ', '')    # dict => str
                SecretKey = 'xxxxxxxxxxxxxxxx'         #key值
                ori_sign = http_body["sign"]
                self.new_sign, self.signtext = createsign(http_body_data, SecretKey)
                if http_body != '{}':
                    new_http_body = json.dumps(http_body).replace(ori_sign, self.new_sign)
                    flow.request.set_text(new_http_body)
                    ctx.log.info('\n接口地址：{}\n更新签名：{} => {}\n签名内容：{}\nbody内容：{}\n'.format(flow.request.path, ori_sign, self.new_sign, self.signtext, http_body1))
                else:
                    ctx.log.info('无参数无需改签')
            except KeyError as e:
                ctx.log.info('数据包无签名')
        else:
            ctx.log.info('\n接口地址：{}\nbody内容：{}\n'.format(flow.request.path, flow.request.get_text()))

    def response(self, flow):
        response_body = flow.response.content.decode('utf-8', errors='ignore')
        if "验签失败" in response_body:
            ctx.log.error('\n签名异常：\n接口地址 => {}\n异常信息 => {}\n'.format(flow.request.path, response_body))

addons = [
    Modify()		# 加载类
 ]

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.argv += ['-s', sys.argv[0]]
    if not '-p' in  sys.argv:
        sys.argv += ['-p', '8888']
    sys.exit(mitmdump())

