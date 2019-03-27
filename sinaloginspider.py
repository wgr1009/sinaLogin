import requests
import base64
import random
import time
import json
import math
import rsa
import binascii
import re



class WeiBo_GetAllParams():

	def __init__(self):
		self.session = requests.session()
		self.su = ''
		self.nonce = ''
		self.rsakv = ''
		self.servertime = ''
		self.pcid = ''
		self.pubkey = ''
		self.door = ''
		self.sp = ''
		self.form = ''

	def getSu(self):
		'''
		获取 登录的账号 base64加密值
		:return: su
		'''
		s = base64.b64encode('name'.encode('utf-8'))
		self.su = str(s,'utf-8')

		return self.su


	def getOther(self):
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
			'Cookie':'cookie',
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

		res = self.session.get(url, headers=headers, verify = False, params=params)
		rep = res.text[35:-1]
		data = json.loads(rep)

		self.pcid = data['pcid']
		self.servertime = data['servertime']
		self.nonce = data['nonce']
		self.rsakv = data['rsakv']
		self.pubkey = data['pubkey']

		return self.pcid, self.servertime, self.nonce, self.rsakv, self.pubkey

	# def getImage(self):
	# 	'''
	# 	获取登录图片的验证码的值
	# 	'p':'tc-3394b50952ff332b97e7a55723dce2340960', # p就是pcid的值
	# 	:return:
	# 	'''
	# 	url = 'https://login.sina.com.cn/cgi/pin.php?'
	# 	# a = random.uniform(0,1)*1e8
	# 	# r = random.randint(1,int(a))
	# 	# 返回小于等于 random.random*1e8的整数
	# 	r = math.floor(random.random()*1e8)
	# 	headers = {
	# 		'r':str(r),
	# 		's':'0',
	# 		'p': self.pcid,
	# 	}
	#
	# 	res = self.session.get(url, headers=headers, verify=False)
	# 	with open('qrcode.png', 'wb')as f:
	# 		f.write(res.content)
	#
	# 	qrcode = input('请输入验证码: ')
	#
	# 	self.door = qrcode
	# 	return self.door


	def getLoginSp(self):
		password = 'password'
		message = str(self.servertime)+'\t'+str(self.nonce) + '\n' + password
		rsa_n = int(self.pubkey, 16)
		rsa_e = int('10001', 16)
		key = rsa.PublicKey(rsa_n, rsa_e)
		pass_key = rsa.encrypt(message.encode(), key)

		self.sp = binascii.b2a_hex(pass_key).decode()

		return self.sp


	def getAllParams(self):

		self.form = {
					'entry':'weibo',
					'gateway':'1',
					'from':'',
					'savestate':'7',
					'qrcode_flag':'false',
					'useticket':'1',
					'pagerefer':'https://login.sina.com.cn/crossdomain2.php?action=logout&r=https%3A%2F%2Fpassport.weibo.com%2Fwbsso%2Flogout%3Fr%3Dhttps%253A%252F%252Fweibo.com%26returntype%3D1',
					# 'pcid':self.pcid,
					# 'door':self.door,  # door 验证码参数
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


	def login_Sina(self):
		'''
		提交form表单 获取重定向 网址
		:return:
		'''
		# self.getImage()
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
                        'cookie':'cookie',
		}

		# print(self.form)
		res = self.session.post(url, data=self.form, verify=False, headers=headers)
		res.encoding = 'gbk'
		d_url = re.findall('location.replace(.*?);', res.text)[0][2:-2]
		if d_url[8:13] == 'weibo':
			print('登录失败')
		elif d_url[8:13] == 'login':
			# 请求post提交的重定向网页
			self.redirect_url(d_url)


	def redirect_url(self, url):
		print('正在登录中......')
		res = self.session.get(url)
		res.encoding = 'utf-8'
		d_url = re.findall('location.replace(.*?);', res.text)[0][2:-2]
		url = 'https://passport.weibo.com/wbsso/login?'
		if d_url[:39] == url:
			print('重定向成功, 正在跳转...')
			res = self.session.get(d_url,verify=False)
			# print(res.url)
			data = res.text[87:-38]
			data = json.loads(data)
			# 'https://weibo.com/u/3991499912/home?wvr=5&lf=reg'
			uniqueid = data['userinfo']['uniqueid'],
			userdomain = data['userinfo']['userdomain']

			loginurl = 'https://weibo.com/u/'+ str(uniqueid) +'home'+userdomain
			print('重定向成功, 正在跳转...')
			res = self.session.get(loginurl, verify=False)
			res.encoding='utf-8'
			html = res.text
			print('登录成功')
			print('当前用户: ',html[767:779])
			# print(res.headers)


	def main(self):
		self.getSu()
		self.getOther()
		self.getLoginSp()
		self.getAllParams()
		self.login_Sina()

		# print(self.servertime)
		# print(str(int(time.time())))

		# form = self.form
		# return form


if __name__ == '__main__':
	app = WeiBo_GetAllParams()
	app.main()













