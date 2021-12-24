#!/usr/bin/env python

__author__ = ('Imam Omar Mochtar', 'omar@jabetto.com')
__version__ = (1,0)

"""
Script untuk parsing file cfg2html menjadi json yang akan dipakai dalam pembuatan PM Report (basic)
"""

import sys
import os
import re
import json
from glob import glob
from bs4 import BeautifulSoup
from pprint import pprint



CFG2HTML_EXT = '*.html'
NULL_TXT = '---'
# maksimal pada process list
MAX_TOP = 5


class JCollector(object):

	cursoup = None

	def __init__(self, targetdir):

		if not os.path.isdir(targetdir):
			raise Exception("%s is not a directory"%targetdir)

		self.targetdir = targetdir

	def getContent(self, name):
		"""
		Mendapatkan kontent <pre> berdasarkan judul A Name
		"""

		finda = self.cursoup.find('a', {'name': name})
		if finda:
			return finda.findNextSibling('pre').text
		return NULL_TXT

	def getParam(self, txt, ptrn):
		"""
		Mendapatkan parameter dengan separator =, contoh seperti berikut ini
		Hostname (short)= lsdb01.smartfren.com, jika tidak ada maka balikan None
		"""

		# replace tanda kurung agar tidak sama dengan pattern regex
		ptrn = re.sub(r'(\(|\))',r'\\\1', ptrn)
		match = re.search(r'{0}\s?=\s?(.*)$'.format( ptrn ), txt, re.MULTILINE)
		if match:
			return match.group(1).replace('"','')
		return NULL_TXT

	def initNull(self, keys):
		"""
		Inisialisasi NULL_TXT pada return parameter
		"""
		retval = {}
		for keyx,valuex in keys.iteritems():
			retval[keyx] = self.getContent(valuex)
		return retval


	def getGeneralInformation(self):

		inf = self.initNull({
				# => Operating System
				'osname': 'OS Specific Release Information (/etc/redhat-release)',
				# => Kernel
				'kernel': 'OS, Kernel version',
				# => hostname
				'hostname': 'uname & hostname',
				# => uptime
				'uptime': 'Uptime'
			})

		if inf['osname'] == NULL_TXT:
			osname = self.getContent('OS Specific Release Information (/etc/lsb-release)')
			desc = self.getParam(osname, 'DISTRIB_DESCRIPTION')
			codename = self.getParam(osname, 'DISTRIB_CODENAME')
			inf['osname'] = '%s (%s)'%(desc, codename)

		if inf['hostname'] != NULL_TXT:
			inf['hostname_short'] = self.getParam(inf['hostname'], 'Hostname (short)')
			inf['hostname_fqdn'] = self.getParam(inf['hostname'], 'Hostname (FQDN)')

		# set ke default setelah dipakai
		inf['hostname'] = NULL_TXT
			
		return inf



	def getDiskUsage(self):
		disk = self.getContent('Filesystems and Usage')
		if disk == NULL_TXT: return disk

		diskusage = []
		lines = disk.split('\n')
		for num in range(len(lines)):
			line = lines[num]
			if line.startswith('/dev'):
				splited = line.split()
				fulldev = [splited[0]]
				if len(splited) == 1:
					nline = lines[num+1].split()
				else:
					nline = splited[1:]

				fulldev.extend(nline)

				diskusage.append(fulldev)

		return diskusage

	def getMemoryUsage(self):
		mem = self.getContent('Used Memory and Swap')
		if mem == NULL_TXT: return mem

		memory = {}
		# ambil perintah free yang kedua
		takeme = False
		for line in mem.split('\n'):

			if line.startswith('Mem:'):
				splited = line.split()
				memory['mem_total'] = splited[1]
				memory['mem_used'] = splited[2]
				memory['mem_free'] = splited[3]
				memory['mem_shared'] = splited[4]
				memory['mem_buffers'] = splited[5]
				memory['mem_cached'] = splited[6]

			if line.startswith('-/+'):
				splited = line.split()
				memory['bc_used'] = splited[2]
				memory['bc_free'] = splited[3]


			if line.startswith('Swap'):
				splited = line.split()
				memory['swap_total'] = splited[1]
				memory['swap_used'] = splited[2]
				memory['swap_free'] = splited[3]

		return memory



	def getNetworkInformation(self):
		network = self.getContent('LAN Interfaces Settings (ip addr)')
		if network == NULL_TXT: return network

		interfaces = []

		re_interface = re.compile(r'^\d+:\s+(?P<interface>.*):.*?state\s+(?P<status>\w+)')
		# inet 192.168.44.3/24 brd 192.168.44.255 scope global eth0:1
		re_inet = re.compile(r'^inet\s+(?P<ipaddr>.*?)\s.*?global\s(?P<interface>.*?)$')

		lines = network.split('\n')

		for num in range(len(lines)):
			line = lines[num].strip()
			re_line = re_interface.search(line)

			if re_line:
				re_line = re_line.groupdict()
				status = 'UP'
				if re_line['status'] != 'UP': status = 'DOWN'
				interfaces.append({
				    'main_interface': re_line['interface'],
				    'macaddr': lines[num+1].split()[1],
				    'status': status,
				    'ip_addr': []
				})

			re_ip = re_inet.search(line)
			
			if re_ip:
				re_ip = re_ip.groupdict()
				# pprint(interfaces)
				# print line
				interfaces[-1]['ip_addr'].append({
				    'ip': re_ip['ipaddr'],
				    'interface': re_ip['interface']
				})

		return interfaces


	def getTop(self, cntx):
		daftar = self.getContent(cntx)
		if daftar == NULL_TXT: return daftar
		breakme = daftar.split('\n')
		tulis = []

		if len(breakme) >= MAX_TOP: 
			breakme = breakme[:MAX_TOP]

		for num in range(len(breakme)):
			tulis.append([num+1, breakme[num]])

		return tulis

	def getTopLoadProcess(self):
		return self.getTop('Top load processes')

	def getTopMemConsume(self):
		return self.getTop('Top memory consuming processes')

	def run(self):

		result = []
		searchptrn = os.path.join(self.targetdir, CFG2HTML_EXT)
		for cfg2html in glob(searchptrn):
			with open(cfg2html, 'r') as tmp:
				self.cursoup = BeautifulSoup(tmp.read()) 

			addme = {
				'information': self.getGeneralInformation(),
				'disk_usage': self.getDiskUsage(),
				'memory_usage': self.getMemoryUsage(),
				'network_status': self.getNetworkInformation(),
				'top_load_process': self.getTopLoadProcess(),
				'top_mem_consuming': self.getTopMemConsume(),
			}

			# pprint(addme)
			# print "\n"
			# print addme['disk_usage']

			result.append(addme)

		# pprint(result)
		print json.dumps(result)


if __name__ == '__main__':
	JCollector(targetdir=sys.argv[1]).run()