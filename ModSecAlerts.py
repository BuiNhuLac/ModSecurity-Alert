#!/usr/bin/python2.7
import smtplib
import base64
import string
import random
import os
from json import loads
import datetime

class Mails():
	def __init__(self, mailAddr, mailPass, mailServer='smtp.gmail.com', mailPort=587, parent=None):
		self.mailAddr = mailAddr
		self.mailPass = mailPass
		self.mailServer = mailServer
		self.mailPort = mailPort
		self.sender = None

	def sendMail(self, subject, content, sender=None, recipient=None):
		if not sender: sender = self.mailAddr
		if not recipient: recipient = self.mailAddr
		header = 'Subject: ' + subject + '\n'\
		 + 'From: ' + sender + '\n'\
		 + 'To: ' + recipient + '\n'
		content = header + content
		try:
			self.mail = smtplib.SMTP(self.mailServer, self.mailPort)
			self.mail.ehlo()
			self.mail.starttls()
			self.mail.login(self.mailAddr, self.mailPass)
			
			self.mail.sendmail(sender, recipient, content)
			self.mail.close()
			print str(datetime.datetime.now()) + '\tSuccessfully Sent Mail'
		except Exception:
			print str(datetime.datetime.now()) + '\tError: unable to send email'

	def sendMailWithFiles(self, subject, content, files, sender=None, recipient=None):
		if not sender: sender = self.mailAddr
		if not recipient: recipient = self.mailAddr
		marker = self.markerGenerator()
		__marker = '--' + marker
		__marker__ = __marker + '--'
		marker = '"' + marker + '"'
		with open(files, 'rb') as f:
			fContent = f.read()
		fContent = base64.b64encode(fContent)
		fileName = files.split('/')[-1]
		EL = '\n'

		# Define the main headers
		mainHeader	= 'Subject: ' + subject + EL
		mainHeader += 'From: ' + sender + EL
		mainHeader += 'To: ' + recipient + EL
		mainHeader += 'Content-Type: multipart/mixed; boundary=' + marker + EL * 2

		# Define the message action
		headerContent	= __marker + EL
		headerContent += 'Content-Type: text/plain' + EL * 2
		headerContent += content + EL * 2

		# Define the attachment section
		headerAttachment	= __marker + EL
		headerAttachment += 'Content-Type: munltipart/mixed; name="' + fileName + '"' + EL
		headerAttachment += 'Content-Transfer-Encoding: base64' + EL
		headerAttachment += 'Content-Disposition: attachment; filename="' + fileName + '"' + EL * 2
		headerAttachment += fContent + EL * 2
		headerAttachment += __marker__

		message = mainHeader + headerContent + headerAttachment

		try:
			self.mail = smtplib.SMTP(self.mailServer, self.mailPort)
			self.mail.ehlo()
			self.mail.starttls()
			self.mail.login(self.mailAddr, self.mailPass)
			self.mail.sendmail(sender, recipient, message)
			self.mail.close()
			print str(datetime.datetime.now()) + '\tSuccessfully Sent Mail with file'
		except Exception:
			print str(datetime.datetime.now()) + '\tError: unable to send email'

	def markerGenerator(self, size=12, chars=string.ascii_uppercase + string.digits):
		return 'Q572E412E49_' + ''.join(random.choice(chars) for _ in range(size))


class ModSecAlert():
	def __init__(self, mailAddr, mailPass, platform=None, logFile=None):
		self.mailAddr = mailAddr
		self.mailPass = mailPass

		if platform: self.platform = platform;
		else: self.platform = 'CentOS';

		if logFile: self.logFile = logFile;
		else: self.logFile = '/var/log/httpd/modsec_audit.log';
		# else: self.logFile = 'modsec_audit.log';

		self.mail = Mails(self.mailAddr, self.mailPass)

		# Mail:
		self.path = os.path.dirname(os.path.realpath(__file__))
		self.logLine = self.path + '/ModSecAlerts.conf'
		self.logData = None
		self.logNew = None
		self.line = None
		self.send = False
		self.alertHeader = None
		self.alertContent = ''
		self.alertFile = self.path + '/ModSec-Alert-Details.txt'
		self.checkConfigurationFile()
		self.attackCount = None
		self.miscellaneous = 'Please check the attached file for more details.'
		self.alertHeader = '''
._______________________________________________________________________________________________.
|										MODSEC DETECTED {attackCount} ATTACK TO THE SYSTEM
*-----------------------------------------------------------------------------------------------*
{alertContent}
	{miscellaneous}
._______________________________________________________________________________________________.
|														DONE
*-----------------------------------------------------------------------------------------------*
'''
		self.alertform = '''
	ATTACKING-IP:	{ATTACKING_IP}
	ATTACKING-HOST:	{ATTACKING_HOST}
	REQUEST_LINE:	{REQUEST_LINE}
	TIME-STAMP:		{TIME_STAMP}
	SRVERITY:		{SRVERITY}
	MATCH:			{MATCH}
	MESSAGE:		{MSG}
	RULE-FILE:		{RULE_FILE}
	REQ-HEADER:		{REQUEST_HEADERS}
	REQ-BODY:		{REQUEST_BODY}
	-----------------------------------------------------------------------------------------------
'''

	def checkConfigurationFile(self):
		if not os.path.isfile(self.logLine):
			with open(self.logLine, 'w+') as f:
				f.write('0')
		if not os.path.isfile(self.alertFile):
			with open(self.alertFile, 'w+') as f:
				pass

	def logAnalysis(self, createLog=True):
		with open(self.logLine) as l:
			self.line = int(l.readline())

		with open(self.logFile) as f:
			self.logData = f.readlines()

		lenlog = len(self.logData)

		if lenlog > self.line:
			self.send = True
			self.logNew = self.logData[self.line:]
			self.attackCount = len(self.logNew)

			with open(self.logLine, 'r+') as f:
				f.write(str(lenlog))

			for log in self.logNew:
				log = loads(log)
				self.initializationAlert(log)
				tmps = self.alertform.format(ATTACKING_IP=self.atIP, ATTACKING_HOST=self.atHost, \
				REQUEST_LINE=self.reqLine, TIME_STAMP=self.timeStamp, SRVERITY=self.severity, \
				MATCH=self.match, MSG=self.msg, RULE_FILE=self.ruleFile, REQUEST_HEADERS=self.reqHeaders, \
				REQUEST_BODY=self.reqBody)
				self.alertContent += tmps

			with open(self.alertFile, 'r+') as f:
				f.writelines(self.logNew)

	def initializationAlert(self, logs):
		transaction = logs['transaction']
		req = transaction['request']
		msg = transaction['messages'][0]
		self.atIP = transaction['client_ip']
		self.atHost = transaction['host_ip']
		self.reqLine = req['method'] + ' ' + req['uri'] + ' HTTP/' + str(req['http_version'])
		self.timeStamp = transaction['time_stamp']
		self.severity = msg['details']['severity']
		self.match = msg['details']['match']
		self.msg = msg['message']
		self.ruleFile = msg['details']['file']
		self.reqHeaders = req['headers']
		self.reqBody = req['body']

	def sendAlert(self, subject=None, content='', withFile=True):
		self.logAnalysis()

		if self.send and withFile:
			content += self.alertHeader.format(attackCount=self.attackCount, alertContent=self.alertContent, \
				miscellaneous=self.miscellaneous)
			self.mail.sendMailWithFiles(subject, content, self.alertFile)
		elif self.send and not withFile:
			content += self.alertHeader.format(attackCount=self.attackCount, alertContent=self.alertContent, \
				miscellaneous='')
			self.mail.sendMail(subject, content)
		else: print str(datetime.datetime.now()) + '\tNothing to alert!';

if __name__ == '__main__':
	mailAddr = 'xxxxxxxxxxxx@gmail.com'
	mailPass = '********'
	subject = 'MODSEC-NOTIFICATION'
	content = ''

	alert = ModSecAlert(mailAddr, mailPass)
	alert.sendAlert(subject, content)