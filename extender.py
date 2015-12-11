from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import re
from datetime import datetime
from bs4 import BeautifulSoup

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
				self.get_words(httpResponse)

		self.printWordlist()
		return

	def words(self, httpResponse):

		headers, body = httpResponse.tostring().split('\r\n\r\n', 1)

		# skip non-text responses
		if headers.lower().find("content-type: text") == -1:
			return

		soup = BeautifulSoup(html, 'html.parser')
		words = soup.text
		#print words

		for word in words:
			# filter out long strings
			if len(word) <= 12:
				self.wordlist.add(word.lower())

		return

	def mangle(self, word):
		year = datetime.now().year
		suffixes = ["", "1", "!", year, "1!", "butts", "12", "2@"]
		mangled = []

		for password in (word, word.capitalize()):
			for suffix in suffixes:
				mangled.append("%s%s" % (password, suffix))

		return mangled

	def printWordlist(self):
		print "# BHP Wordlist for site(s) %s" % \ ", ".join(self.hosts)
		for word in sorted(self.wordlist):
			for password in self.mangle(word):
				print password

		return