from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import re
from datetime import datetime
from bs4 import BeautifulSoup
import string

class BurpExtender(IBurpExtender, IContextMenuFactory):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		self.context = None
		self.hosts = set()

		# start with something we know is common
		self.wordlist   = set(["password"])

		# we set up our extension
		callbacks.setExtensionName("BadGas")
		callbacks.registerContextMenuFactory(self)

		return

	def createMenuItems(self, contextMenu):
		self.context = contextMenu
		menu_list = ArrayList()
		menu_list.add(JMenuItem("Make Wordlist", \ actionPerformed=self.menuEvent))

		return menu_list

	def menuEvent(self, event):

		# grab the details of what the user clicked
		http_traffic = self.context.getSelectedMessages()

		for traffic in http_traffic:
			http_service = traffic.getHttpService()
			host = http_service.getHost()

			self.hosts.add(host)            

			httpResponse = traffic.getResponse()
			if httpResponse:
				self.words(httpResponse)

		self.printWordlist()
		return

	def words(self, httpResponse):

		headers, body = httpResponse.tostring().split('\r\n\r\n', 1)

		# skip non-text responses
		if headers.lower().find("content-type: text") == -1:
			return

		soup = BeautifulSoup(body, 'html.parser')
		words = soup.text.split(' ')

		for word in words:
			word = word.encode('ascii', 'ignore')
			#print word
			# filter out long strings
			wordlen = len(word)
			if wordlen <= 20 and wordlen >=3:
				self.wordlist.add(word.lower().replace('\n', '').replace(',', '').replace('}', '').replace('{', '').replace(')','').replace('(','').replace('\t', '').replace('/', '').replace("'","").replace(';',''))

		return

	def sufix(self, word):
		year = datetime.now().year
		suffixes = ["", "1", "!", year, "1!", "butts", "butts"+str(year), "12", "2@"]
		sufixed = []

		for password in (word, word.capitalize()):
			for suffix in suffixes:
				sufixed.append("%s%s" % (password, suffix))

		return sufixed

	def printWordlist(self):
		print "# BHP Wordlist for site(s) %s" % \ ", ".join(self.hosts)
		for word in sorted(self.wordlist):
			#if word.isalnum():

			for password in self.sufix(word):
				print password

		return
