#/usr/bin/python3
#coding=utf-8

from mitmproxy import ctx, http
from mitmproxy.tools.main import mitmdump
import hashlib, json, re, sys

'''
使用方式：
（1）
默认的监听端口8888：
python Auto-Sign-Header.py
自定义监听端口：
python Auto-Sign-Header.py -p 9999
（2）
不同的应用系统需要更改脚本中的 flow.request.host 值和 SecretKey 值
'''

def md5(str):
    m5 = hashlib.md5()
    m5.update(str.encode('utf-8'))
    return m5.hexdigest()

def createsign(a, b):
    signtext = "reqData={http_body}&reqN0={reqno}&reqTime={reqtime}{SecretKey}".format(http_body=a, reqno=b, reqtime=c, SecretKey=d)
    Sign = md5(signtext)
    return Sign, signtext

class Modify:
    def request(self, flow):
        if flow.request.method == "POST" and flow.request.host == "www.XXX.com" and re.search('^{.*}$', flow.request.get_text(), re.I):
            try:
                http_body = flow.request.get_text()			  # 获取请求包中body的dict类型数据
                reqno = flow.request.headers["reqno"]
                reqtime = flow.request.headers["reqtime"]
                SecretKey = 'xxxxxxxxxxxxxxxx'                # key值
                ori_sign = flow.request.headers["sign"]
                self.new_sign, self.signtext = createsign(http_body, SecretKey)
                if http_body != '{}':
                    flow.request.headers["sign"] = self.new_sign
                    ctx.log.info('\n接口地址：{}\n更新签名：{} => {}\n签名内容：{}\nbody内容：{}\n'.format(flow.request.path, ori_sign, self.new_sign, self.signtext, http_body))
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


