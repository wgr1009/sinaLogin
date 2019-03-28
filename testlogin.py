import requests
import base64
import random
import time
import json
import math
import rsa
import binascii
import re
import logging
import urllib3

# '''
# 登录流程：1、获取图片验证码
# 		  2、获取其他别的参数
# 		  3、登录
# 		  4、重定向
# 		  5、重定向
# 		  6、重定向
# 		  7、登录成功
# '''


class WeiBo_GetAllParams():

	def __init__(self):
		self.session = requests.session()
		self.LOG_FORMAT = '%(asctime)s : %(levelname)s : %(message)s'
		logging.basicConfig(filename='日志.log', level=logging.WARNING, format=self.LOG_FORMAT)
		self.su = ''
		self.nonce = ''
		self.rsakv = ''
		self.servertime = ''
		self.pcid = ''
		self.pubkey = ''
		self.door = ''
		self.sp = ''
		self.form = ''


	def get_LoginSu(self):
		'''
		获取 登录的账号 base64加密值
		:return: su
		'''
		s = base64.b64encode('账号'.encode('utf-8'))
		self.su = str(s,'utf-8')

		return self.su


	def get_LoginOtherParams(self):
		'''
		获取登录传递 nonce servertime, rsakv 的参数
		:return: nonce, rsakv
		'''
		# print('获取模拟登陆索要的参数')
		url = 'https://login.sina.com.cn/sso/prelogin.php?'
		headers = {
			'Host':'login.sina.com.cn',
			'Connection':'keep-alive',
			'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36',
			'Accept':'*/*',
			'Referer':'https://weibo.com/',
			'Accept-Encoding':'gzip, deflate, br',
			'Accept-Language':'zh-CN,zh;q=0.9',
			'Cookie':'cookie值',
		}

		params = {
			'entry':'weibo',
			'callback':'sinaSSOController.preloginCallBack',
			'su':self.su,
			'rsakt':'mod',
			'checkpin':'1',
			'client':'ssologin.js(v1.4.19)',
			'_':str(int(time.time()*1000)),

		}

		# print(params)
		urllib3.disable_warnings()
		res = self.session.get(url, headers=headers, params=params, verify = False)
		rep = res.text[35:-1]
		data = json.loads(rep)

		self.pcid = data['pcid']
		self.servertime = data['servertime']
		self.nonce = data['nonce']
		self.rsakv = data['rsakv']
		self.pubkey = data['pubkey']

		return self.pcid, self.servertime, self.nonce, self.rsakv, self.pubkey


	def get_LoginSp(self):
		password = '登录密码'
		message = str(self.servertime)+'\t'+str(self.nonce) + '\n' + password
		rsa_n = int(self.pubkey, 16)
		rsa_e = int('10001', 16)
		key = rsa.PublicKey(rsa_n, rsa_e)
		pass_key = rsa.encrypt(message.encode(), key)

		self.sp = binascii.b2a_hex(pass_key).decode()

		return self.sp

	def get_loginImageCode(self):
		'''
		获取登录图片的验证码的值
		'p':'tc-3394b50952ff332b97e7a55723dce2340960', # p就是pcid的值
		:return:
		'''
		url = 'https://login.sina.com.cn/cgi/pin.php?'
		# a = random.uniform(0,1)*1e8
		# r = random.randint(1,int(a))
		# 返回小于等于 random.random*1e8的整数
		r = math.floor(random.random()*1e8)
		params = {
			'r':str(r),
			's':'0',
			'p': self.pcid,
		}

		urllib3.disable_warnings()
		res = self.session.get(url, params=params, verify=False)
		with open('qrcode.png', 'wb')as f:
			f.write(res.content)

		qrcode = input('请输入验证码: ')

		self.door = qrcode
		return self.door



	def get_Request_Form(self):

		self.form = {
					'entry':'weibo',
					'gateway':'1',
					'from':'',
					'savestate':'7',
					'qrcode_flag':'false',
					'useticket':'1',
					'pagerefer':'https://login.sina.com.cn/crossdomain2.php?action=logout&r=https%3A%2F%2Fpassport.weibo.com%2Fwbsso%2Flogout%3Fr%3Dhttps%253A%252F%252Fweibo.com%26returntype%3D1',
					'pcid':self.pcid,
					'door':self.door,
					'vsnf':'1',
					'su':self.su,
					'service':'miniblog',
					'servertime':str(int(time.time())),
					'nonce':self.nonce,
					'pwencode':'rsa2',
					'rsakv':self.rsakv,
					'sp':self.sp,
					'sr':'1280*720',
					'encoding':'UTF-8',
					'prelt':str(int(random.randint(20,100))),
					'url':'https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
					'returntype':'META',
				}

		return self.form


	def loginSina(self):
		'''
		提交form表单 获取重定向 网址
		:return:
		'''

		url = 'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)'
		headers = {
			'Host':'login.sina.com.cn',
			'Connection':'keep-alive',
			'Content-Length':'824',
			'Cache-Control':'max-age=0',
			'Origin':'https://weibo.com',
			'Upgrade-Insecure-Requests':'1',
			'Content-Type':'application/x-www-form-urlencoded',
			'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36',
			'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
			'Referer':'https://weibo.com/',
			'Accept-Encoding':'gzip, deflate, br',
			'Accept-Language':'zh-CN,zh;q=0.9',
			'Cookie':'Cookie',

		}

		urllib3.disable_warnings()
		res = self.session.post(url, data=self.form, verify=False, headers=headers)
		d_url = re.findall('location.replace(.*?);', res.text)[0][2:-2]

		if d_url[8:13] == 'weibo':
			print('登录失败, 请重新登录')
			self.main()

		elif d_url[8:13] == 'login':
			# 请求post提交的重定向网页
			self.redirect_url(d_url)


	def redirect_url(self, url):
		print('正在登录中......')
		urllib3.disable_warnings()
		res = self.session.get(url)
		res.encoding = 'utf-8'
		d_url = re.findall('location.replace(.*?);', res.text)[0][2:-2]
		url = 'https://passport.weibo.com/wbsso/login?'

		if d_url[:39] == url:
			print('重定向成功, 正在跳转...')
			try:
				res = self.session.get(d_url,verify=False)
				data = res.text[87:-38]
				data_1 = json.loads(data)
				uniqueid = data_1['userinfo']['uniqueid']
				userdomain = data_1['userinfo']['userdomain']

				loginurl = 'https://weibo.com/u/'+ uniqueid +'/home'
				print('重定向成功, 正在跳转...')
				urllib3.disable_warnings()
				res = self.session.get(loginurl, verify=False)
				res.encoding='utf-8'
				html = res.text

				if html.find('我的首页'):
					print('登录成功')
					print('当前用户: ', re.findall("'用户(.*?)';", html)[0])
					print('当前主页: ', res.url)
					self.get_logindata()
				else:
					print('登录错误')
			except json.decoder.JSONDecodeError:
				print('访问出问题')
				self.main()



	def main(self):
		self.get_LoginSu()
		self.get_LoginOtherParams()
		self.get_LoginSp()
		self.get_loginImageCode()
		self.get_Request_Form()
		self.loginSina()

if __name__ == '__main__':
	app = WeiBo_GetAllParams()
	app.main()













