#!/usr/bin/python
import sys
import re
from optparse import OptionParser

def maybe_tab(report_layout):
	out = ""
	if report_layout != True:
		out = '\t'
	return out

def performInvertedSearch(record,regex):
	i=0
	vuln_found = True

	while i < len(record):
		m = re.match(regex,record[i])

		if m is not None:
			vuln_found = False
		i=i+1

	return vuln_found

def formatDataWithCommas(input_array):
	# put the extra_data onto the one line in string format, comma separated
	output = ""
	i=0
	while i < len(input_array):
		if i > 0:
			output = output + ", " + str(input_array[i])
		else:
			output = str(input_array[i])
		i=i+1

	return output

def determineDataPoints(record,regex_start,regex_end):
        data_points = []
        regex = regex_start

        i=0

        while i < len(record):
                m = re.match(regex,record[i])

                if m is not None:
                        data_points.append(i)
                        regex = regex_end
                        m = None
                        if len(data_points) > 1:
                                i = 9999
                i=i+1

        return data_points

def extractExtraInfo(vuln_data,record,report_layout):
	extra_info = ""
	i=0
	result = []
	tab_value = '\t' + maybe_tab(report_layout)
	
	data_points__ciphers = determineDataPoints(record,".*Testing 364 ciphers via OpenSSL plus sockets against the server, ordered by encryption strength.*",".*Running client simulations via sockets.*")
	data_points__testing_vulns = determineDataPoints(record,"Testing vulnerabilities",".*Testing 364 ciphers via OpenSSL plus sockets against the server, ordered by encryption strength.*")
	data_points__beast = determineDataPoints(record,".*BEAST.*\(CVE-2011-3389\).*",".*LUCKY13.*\(CVE-2013-0169\).*")
	data_points__beast[1] = data_points__beast[1]-1

	if vuln_data[0] == "SSL RC4 Cipher Suites Supported (Bar Mitzvah)":
		i=data_points__ciphers[0]
		regex = ".*RC4.*RC4.*_RC4_.*"

		while i < data_points__ciphers[1]:
			r = re.match(regex,record[i])
			if r is not None:
				m = re.search(regex,record[i]).group(0)
				m=m[7:42]
				m = re.search(' *(\w*RC4-\w*) *',m).group(1)
				x=0
				found = False
				while x < len(result):
					if result[x] == m:
						found = True
					x=x+1
				if found == False:
					result.append(m)
			i=i+1
		extra_info = formatDataWithCommas(result)

	elif vuln_data[0] == "Weak SSL Cipher Lengths":
		i=data_points__ciphers[0]
		print str(data_points__ciphers)
		regex = ".*128.*"

		while i < data_points__ciphers[1]:
			r = re.match(regex,record[i])
			if r is not None:
				m = re.search(regex,record[i]).group(0)
				m=m[7:42]
				m = re.search(' *(\S*) *',m).group(1)
				result.append(m)
			i=i+1
		extra_info = formatDataWithCommas(result)

	elif vuln_data[0] == "SSL/TLS Protocol Initialization Vector Implementation Information Disclosure Vulnerability (BEAST)":
		i=data_points__beast[0]
		# extract any text surrounded by spaces
		regex = ' *(.*) *'

		# remove any colour codes
		ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
		interim_ciphers = []
		interim_ciphers_2 = []

		while i < data_points__beast[1]:
			m = ansi_escape.sub('',record[i])
			m=m[30:]

			# extract any text surrounded by spaces
			num_spaces = m.count(' ')
			interim_ciphers.append(m.split(' '))

			s = re.search(regex,m).group(1)
			i=i+1

		i=0
		while i < len(interim_ciphers):
			# remove any items in array that contain nothing/are empty
			interim_ciphers[i] = filter(None,interim_ciphers[i])
			i=i+1

		x=0
		y=0
		z=-1
		while x < len(interim_ciphers):
			y=0
			# put each cipher into a 2D array with the protocol name (eg. SSLv3:) at the first item of each array
			while y < len(interim_ciphers[x]):
				if ":" in interim_ciphers[x][y]:
					z=z+1
					interim_ciphers_2.append([])
				interim_ciphers_2[z].append(interim_ciphers[x][y])
				y=y+1
			x=x+1	

		x=0
		while x < len(interim_ciphers_2):
			extra_info = extra_info + str(interim_ciphers_2[x][0]) + " "
			extra_info = extra_info + formatDataWithCommas(interim_ciphers_2[x][1:len(interim_ciphers_2[x])])
			if x < len(interim_ciphers_2)-1:
				extra_info = extra_info + '\n' + tab_value
			x=x+1

	elif vuln_data[0] == "SSL Certificate Signed Using Weak Hashing Algorithm":
		i=0

		while i < len(record):
			m = re.match(".* Signature Algorithm .*",record[i])

			if m is not None:
				# remove any colour codes
				ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
				r = ansi_escape.sub('',record[i])
				r=r[14:]
				print "MMM: " + r

				# extract any text surrounded by spaces
				s = re.search('  (\w.*\w)  ',r).group(1) # will need fixing here!
				result.append(s)

				i=9999
			i=i+1
		extra_info = formatDataWithCommas(result)

	return tab_value + extra_info


def vulnFinder(vuln_data,record,report_layout):
	result = []
	vuln_found = False
	extra_info = ""

	regex = ".*" + vuln_data[1] + ".*"

	i=0
	if vuln_data[0] == "SSL Certificate Signed Using Weak Hashing Algorithm":
		regexs = [".*MD2.*",".*MD4.*",".*MD5.*",".*SHA1.*"]

		while i < len(record):
			m = re.match(".* Signature Algorithm .*",record[i])

			if m is not None:
				x=0

				while x < len(regexs):
					r = re.match(regexs[x],record[i])

					if r is not None:
						vuln_found = True
						x=9999
					x=x+1
				i=9999
			i=i+1
	elif vuln_data[0] == "Certificates with RSA Keys Shorter than 2048 bits":
		i=0
		data=[]

		while i < len(record):
			m = re.match(regex,record[i])

			if m is not None:
				r = re.search(regex,record[i]).group(0)
				x=0
				data.append(r.split(' '))
				while x < len(data[0]):
#					print str(data[0])
					if "RSA" in str(data[0][x]):
						x=x+1
						
						outstring = str(data[0][x])
						if outstring.isdigit() == False:

							# remove any colour codes
							ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
							r = ansi_escape.sub('',record[i])

							# extract the actual key size number
							regex = "RSA (.+?) bits"
							outstring = re.search(regex,r).group(1)

						if int(outstring) < 2048:
							vuln_found = True
							extra_info = "RSA Key Size: " + str(data[0][x])
							x=9999
					x=x+1
				i=9999
			i=i+1

	else:
		# perform an inverted search if necessary
		if vuln_data[2] == True:
			vuln_found = performInvertedSearch(record,regex)
		else:
		# otherwise search for the specified vuln data in the testssl output
			while i < len(record):
				m = re.match(regex,record[i])

				if m is not None:
					vuln_found = True
				i=i+1

	if vuln_found == True and vuln_data[3] == True and (extra_info is None or extra_info is ""):
		extra_info = extractExtraInfo(vuln_data,record,report_layout)

	result.append(vuln_found)
	result.append(extra_info)
	return result


