#!/usr/bin/python
import sys
import re
from optparse import OptionParser
import vuln_find_logic as logic
from collections import Counter

# array layout is: ["Vuln Full Name","Vuln Searchbile Text In Testssl","Bool - is it an inverted search?","Boolean - whether extra data is required to be outputted"]
vuln_data = [["SSL RC4 Cipher Suites Supported (Bar Mitzvah)","RC4.*\(CVE-2013-2566, CVE-2015-2808\).*VULNERABLE \(NOT ok\)",False,True],
["SSL Version 3 Protocol in Use","SSLv3.*offered \(NOT ok\)",False,False],
["SSL Version 2 Protocol in Use","SSLv2.*offered \(NOT ok\)",False,False],
["SSLv3 Padding Oracle on Downgraded Legacy Encryption Vulnerability (POODLE)","POODLE, SSL.*\(CVE-2014-3566\).*VULNERABLE \(NOT ok\)",False,False],
["TLSv1.0 Protocol in Use","TLS 1 .*not offered",True,False],
["SWEET32 - SSL 64-bit Block Size Cipher Suites Supported","SWEET32.*\(CVE-2016-2183, CVE-2016-6329\).*VULNERABLE",False,False], # still to be added! - need to run Nessus to help determine!
["SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)","FREAK.*\(CVE-2015-0204\).*VULNERABLE",False,False],
["SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)","LOGJAM.*\(CVE-2015-4000\).*VULNERABLE",False,False],
["SSL/TLS Protocol Initialization Vector Implementation Information Disclosure Vulnerability (BEAST)","BEAST.*\(CVE-2011-3389\).*no SSL3 or TLS1",True,True],
["SSL Certificate Cannot Be Trusted (Self Signed)","Issuer.*self-signed.*\(NOT ok\)",False,False], 
["SSL Certificate Signed Using Weak Hashing Algorithm","N/A",False,False],
["Certificates with RSA Keys Shorter than 2048 bits","Server key size.*RSA",False,True], # will be True - need to run Nessus to help determine
["Expired Certificates","Certificate Validity \(UTC\).*expired",False,False],
["No Server Cipher Order","Has server cipher order?.*no",False,False],
["Heartbleed (CVE-2014-0160)","Heartbleed.*\(CVE-2014-0160\).*not vulnerable",True,False],
["CCS (CVE-2014-0224)","CCS.*\(CVE-2014-0224\).*not vulnerable",True,False],
["Ticketbleed (CVE-2016-9244)","Ticketbleed.*\(CVE-2016-9244\).*VULNERABLE",False,False],
["ROBOT (Return of Bleichenbacher's Oracle Threat)","ROBOT.*VULNERABLE",False,False],
["Secure Renegotiation (CVE-2009-3555)","Secure Renegotiation.*\(CVE-2009-3555\).*not vulnerable",True,False],
["Secure Client-Initiated Renegotiation","Secure Client-Initiated Renegotiation.*not vulnerable",True,False],
["CRIME, TLS (CVE-2012-4929)","CRIME, TLS.*\(CVE-2012-4929\).*not vulnerable",True,False],
["DROWN (CVE-2016-0800, CVE-2016-0703)","DROWN.*not vulnerable",True,False]]

# read contents of a file into an array
def readFromFile(filename):
        f = open(filename, "r") 
        lines = f.readlines()
        f.close()

        i=0
        while i<len(lines):
                #lines[i] = str(lines[i]).decode('string_escape')
                lines[i] = lines[i].rstrip()
                i=i+1

        return lines

	out = ""
	if options.report_layout != True:
		 out = '\t'
	return out

def printColour(colour,text):
	class bcolors:
		HEADER = '\033[95m'
		OKBLUE = '\033[94m'
		OKGREEN = '\033[92m'
		WARNING = '\033[93m'
		FAIL = '\033[91m'
		ENDC = '\033[0m'
		BOLD = '\033[1m'
		UNDERLINE = '\033[4m'
	
	if colour == "header":
		print bcolors.HEADER + text + bcolors.ENDC

	elif colour == "blue":
		print bcolors.OKBLUE + text + bcolors.ENDC

	elif colour == "green":
		print bcolors.OKGREEN + text + bcolors.ENDC

def optionalArg(arg_default):
    def func(option,opt_str,value,parser):
        if parser.rargs and not parser.rargs[0].startswith('-'):
            val=parser.rargs[0]
            parser.rargs.pop(0)
        else:
            val=arg_default
        setattr(parser.values,option.dest,val)
    return func

parser = OptionParser(description='Usage: ./ts_parser.py -f <filenames> ')

parser.add_option("-l", "--long-out",
                  action="store_true",
                  dest="simple_out", default="",
                  help="Print affected ciphers for every vulnerable host")
parser.add_option("-f", "--files",
                  action="callback",callback=optionalArg('xxxemptyxxx'),
                  dest="input_filenames", default="",
                  help="Name of testssl output to parse")
parser.add_option("-v", "--verbose",
                  action="store_true",
                  dest="verbose_out", default="",
                  help="Verbose output")
parser.add_option("-c", "--copyable-out",
                  action="store_true",
                  dest="report_layout", default="",
                  help="The optimal output for copying into a report (albeit more difficult to understand)")

(options, args) = parser.parse_args()

verbose = options.verbose_out

if verbose == True:
	print ""
	printColour("header","####################-START-#####################")
	print ""
	printColour("blue"," _/\_/\_- INPUT FILE NAMES: -_/\_/\_ ")
	print "\t" + str(options.input_filenames)

i=0
start_data = []
end_data = []

if (options.input_filenames != None) and (options.input_filenames != ""):
	lines = readFromFile(options.input_filenames)
else:
	parser.print_help()
	sys.exit(1)	

regex = ".*Start.*-->>.*<<--"

while i < len(lines):
	m = re.match(regex, lines[i])

	if m is not None:
		if len(start_data) > len(end_data):
			end_data.append(i)
			regex = ".*Start.*-->>.*<<--"
		else:
			start_data.append(i)
			regex = ".*Done.*-->>.*<<--"
	i=i+1

records = []
# records ( [ hostname , record data ] , ... )

i=0
x=start_data[0]
interim_array = []
temp_record = []

# puts testssl output for each host into an array
print ""
printColour("blue"," _/\_/\_- HOSTNAME/IP LIST: -_/\_/\_ ")

while i < len(start_data):
	x = start_data[i]
	while x < end_data[i]:
		interim_array.append(lines[x])
		x=x+1

	hostname = re.search('-->> (.+?) <<--', interim_array[0]).group(1)
	
	# determine whether the 'hostname' variable contains only an IP address or a hostname as well
	chars_found = list(Counter((hostname)).items()) # chars_found contains the chars present in the string
	
	chars=["0","1","2","3","4","5","6","7","8","9",".",":","(",")"," "]
	x=0
	y=0
	num_only_found = True

	while x < len(chars_found): # determine whether the 'hostname' string contains any characters that aren't specified in the 'chars' array, and therefore would be a hostname instead of a simple IP address
		y=0
		found = False
		while y < len(chars):
			if chars_found[x][0] == chars[y]:
				found = True
			y=y+1
		if found == False:
			num_only_found = False
			x=999
		x=x+1

	if num_only_found == True:
		hostname = hostname.split()[0]
	temp_record.append(hostname)
	print "\t" + str(hostname)
	temp_record.append(interim_array)
	records.append(temp_record)
	
	temp_record = []
	interim_array = []
	i=i+1


print "" 
printColour("blue", " _/\_/\_- OUPUT DATA: -_/\_/\_ ")
#print ""
vuln_title_printed = False
# iterate through each host and discover whether each vulnerability is present. 
# then print info on each vuln if present
if options.simple_out != True:
	i=0
	while i < len(vuln_data):
		x=0
		z=0
		interim_data=[[[''], ['']]] # [ the whole array [ 1 record [ 1 lot of ciphers ] [ 1 IP ] ] ]
		vuln_title_printed = False

		while x < len(records):
			result = logic.vulnFinder(vuln_data[i],records[x][1],options.report_layout)

			if (vuln_data[i][3] == True and result[1] is not None and result[1] is not "") or (vuln_data[i][3] == False):
				# if vuln is present and additional data should be added
				if (result[0] == True) and (vuln_data[i][3] == True):
					# if the vulnerability is present & the title hasn't already been printed, print the title
					if vuln_title_printed == False:
						if options.report_layout != True:
							print '\n' + str(vuln_data[i][0])
						else:
							print '\n- ' + str(vuln_data[i][0])
						vuln_title_printed = True
					# if the data to be added is unique, then
					y=0
					z=0
					different = False
					# arrange them into another array in correct order
					while y < len(interim_data):
						# check whether any previous data is the same as the current one
						if str(interim_data[y][0][0]) == str(result[1]):
							z=y
							different=True	
							y=9999
						y=y+1

					# if the data is different to previous entries, create a new item in array and add the current cipher to it
					if different == False and str(interim_data) != "[[[''], ['']]]":
						interim_data.append([[],[]])
						z=len(interim_data)-1
						interim_data[z][0].append(str(result[1])) # append the additional info

					# if the array is empty, then
					if str(interim_data) == "[[[''], ['']]]":
						interim_data[z][1][0] = logic.maybe_tab(options.report_layout) + str(records[x][0])
						interim_data[z][0][0] = str(result[1])
					else:				
						interim_data[z][1].append(logic.maybe_tab(options.report_layout) + str(records[x][0])) # append the IP

				# print only the IPs that are vulnerable instead (no ciphers/extra info is required)
				elif result[0] == True:
					# if the vulnerability is present & the title hasn't already been printed, print the title
					if vuln_title_printed == False:
						if options.report_layout != True:
							print '\n' + str(vuln_data[i][0])
						else:
							print '\n- ' + str(vuln_data[i][0])
						vuln_title_printed = True
					print logic.maybe_tab(options.report_layout) + str(records[x][0])
#					print ""
			x=x+1
#		print ""
		# if some ciphers have been queued to be printed, print each lot of IPs and ciphers
		if str(interim_data) != "[[[''], ['']]]":
			y=0
			while y < len(interim_data):
				z=0
				while z < len(interim_data[y][1]):
					# print every IP
					print str(interim_data[y][1][z])
					z=z+1
				print '\n' + logic.maybe_tab(options.report_layout)+"Affected Ciphers:"
				print str(interim_data[y][0][0])
				if z < 0:
					print "" # an extra line after Affected Hosts if there is more than 1
				y=y+1
		i=i+1

else:
# SIMPLIFIED OUTPUT
	i=0
	while i < len(vuln_data):
		x=0
		print str(vuln_data[i][0])
		while x < len(records):
			result = logic.vulnFinder(vuln_data[i],records[x][1],options.report_layout)
			if (vuln_data[i][3] == True and result[1] is not None and result[1] is not "") or (vuln_data[i][3] == False):
				if result[0] == True:
					print logic.maybe_tab(options.report_layout) + str(records[x][0])
					if vuln_data[i][3] == True:
						print str(result[1])
			x=x+1
		print ""
		i=i+1

#if result == False:
#	print ""

#array - each record
#	array - each section
#		1 - Testing protocols
#		2 - Test cipher catagories
#		3 - Testing robust (perfect) forward secrecy
#		4 - Testing server preferences
#		5 - Testing server defaults
#		6 - Testing HTTP header response
#		7 - Testing vulnerabilities
#		8 - Testing 364 ciphers via OpenSSL plus sockets against the server, ordered by encryption strength
#		9 - Running client simulations via sockets
print ""
if verbose == True:
	printColour("header","#####################-END-######################")
	print ""

