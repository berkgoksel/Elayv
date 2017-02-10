# -*- coding: utf-8 -*-
import urllib2
import sys
import re
from netaddr import IPNetwork
from sys import stdout
#Requires netaddr.
# If you don't have it, use > pip install netaddr

###############Elayv_V2.0######################
#Author: Berk Cem Goksel
#Initially made by Alper Basaran
#Special thanks to Usama Saqib
###############################################


def scan(addr):

 try:
   boolean = False
   user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
   headers = {'User-Agent': user_agent}
   url = "http://" + str(addr)
   req = urllib2.Request(url, None, headers)
   response = urllib2.urlopen(req, timeout=0.5)
   rcode = response.getcode()
   #print addr, "looks like there's something here: ", rcode
   if rcode == 200:
       boolean = True
       return boolean

   return boolean

 except Exception as e:
    sys.exc_clear()#or pass




def search(html, words):

 try:
   user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
   headers = {'User-Agent': user_agent}
   url = "http://" + str(html)
   req = urllib2.Request(url, None, headers)

   response = urllib2.urlopen(req)
   source = response.read()

   match = None 

   for word in words:
        expression = r'.*\s*'+word+'\s*.*'
        match = re.search( expression, source)
        if ( match != None):
            #print( url, ": ", word, " found.") #Uncomment to see which words matched.
            print url + "\tLooks like this website belongs to the same company/person"
            break

 except Exception as e:
    sys.exc_clear()



def run():
    global addr
    print " "
    print " "
    print " "
    print " *****************************************************"
    print " *****************************************************"
    print " ***         ELAYV    V2.0 ***************************"
    print " *****************************************************"
    print " *************************OSINT Web Page Scanner******"
    print " *****************************************************"
    print " "
    print "Searches for the IP adresses that respond to port 80 in the specified "
    print "subnet and checks if the IP adresses belong to the same person/company"
    print " "
    print " "
    print " "

    ip_input = str(raw_input('Enter IP adress range to scan (ex:10.1.1.0/24): '))

    verification = re.search(r'^(2[0-5]{2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{0,2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{0,2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{2}|2[0-4][0-9]|[01]?[0-9]{0,2})/[0-9]+$', ip_input)
    while ( verification == None):
        ip_input = raw_input( "Please Enter correct formatt:")
        verification = re.search(r'^(2[0-5]{2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{0,2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{0,2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{2}|2[0-4][0-9]|[01]?[0-9]{0,2})/[0-9]+$', ip_input)

    ip_range = IPNetwork(ip_input)
    iplist = list(ip_range)

    valid_ips = list()
    present = False
    addrUp = 0
    scanned = 1


    for addr in iplist:
        present = scan(addr)
        printProgress( scanned, len(iplist))
        if present == True:
            valid_ips.append(addr)
            addrUp = addrUp + 1

        scanned = scanned + 1

    print "\n" + str(addrUp) + " addresses are up."
    for ip in valid_ips:
        print str(ip) + " is up."




    query_value = query_yes_no(question="\nDo you want to check if the websites belong to the same person/company? ")


    if query_value == True:


        print( "Enter keyword(s) about the target. Press Enter after each entry. To signal completion, enter -1")

        words = list()
        data = None

        while ( data != "-1"):
            if ( data != None):
                words.append(data)
            data = str(raw_input())


        for address in valid_ips:
            html = address
            search(html, words)






    print "\nFinished."

#Ripped the following off
def query_yes_no(question, default="yes"):

    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")




def printProgress(scanned, length):
    sys.stdout.write(str(scanned) + " of " + str(length) + " adresses scanned.")
    sys.stdout.write( "\r")
    sys.stdout.flush()




def start():
    try:
        run()
    except KeyboardInterrupt:
        sys.exit("Exiting...")

start()








