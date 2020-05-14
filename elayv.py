import ipaddress
import netaddr
import queue
import re
import socket
import sys
import urllib.request
from threading import Thread
from urllib.error import URLError, HTTPError

# Authors: Berk Cem Göksel and Usama Saqib
# Kudos for the name and idea: https://github.com/alperbasaran/elayv/commits/master/elayv.py


timeout = 8.0
results = {}

ip = r'(2[0-5]{2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{0,2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{0,2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{2}|2[0-4][0-9]|[01]?[0-9]{0,2})'
ip_range = r'^(2[0-5]{2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{0,2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{0,2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{2}|2[0-4][0-9]|[01]?[0-9]{0,2})-(2[0-5]{2}|2[0-4][0-9]|[01]?[0-9]{0,2})$'
ip_mask = r'^(2[0-5]{2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{0,2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{0,2}|2[0-4][0-9]|[01]?[0-9]{0,2})\.(2[0-5]{2}|2[0-4][0-9]|[01]?[0-9]{0,2})/[0-9]{1,2}$'

prog_ip_range = re.compile(ip_range)
prog_mask = re.compile(ip_mask)
prog_ip = re.compile(ip)

googlebot_user_agent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'


def scan(addr, word_list):
    rcode = -1
    source = ""
    try:
        error = False;
        socket.setdefaulttimeout(timeout)
        user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
        headers = {'User-Agent': user_agent}
        url = "http://" + str(addr)
        req = urllib.request.Request(url, None, headers)

        with urllib.request.urlopen(req) as response:
            rcode = response.code
            source = response.read()
            source = source.decode('utf-8')
            print(source)

    except HTTPError as e:
        rcode = e.code
    # print('Error code: ', e.code)

    except URLError as e:
        error = True
    # print('We failed to reach a server.')
    # print('IP: ', addr, 'Reason: ', e.reason)

    except Exception as e:
        error = True
    # print( e)

    finally:
        present = False
        if (not error and rcode != -1):
            if word_list:
                present = searchForWords(word_list, source, url)

            results[str(addr)] = (rcode, present)


def searchForWords(words, source, url):
    match = None
    for word in words:
        match = re.search(word, source, re.IGNORECASE)
        if (match != None):
            print( url, ": ", word, " found.") #Uncomment to see which words matched.
            return True

    return False


def scanIps(ip_list, word_list):
    threads = list()
    for addr in ip_list:
        # print("Probing " + str(addr) + ".")
        t = Thread(target=scan, args=(addr, word_list))
        threads.append(t)
        t.start()

    return threads


def ipAddresses():
    ip_list = list()

    if (sys.argv[1] == '-m'):
        if (validIpMask(sys.argv[2])):
            net1 = ipaddress.ip_network(sys.argv[2])
            for x in net1.hosts():
                ip_list.append(str(x))

    elif (sys.argv[1] == '-l'):
        for x in range(2, len(sys.argv)):
            if (sys.argv[x] == '-t'):
                break
            else:
                ip_list.append(sys.argv[x])

    elif (sys.argv[1] == '-r'):
        if (validIpRange(sys.argv[2])):
            r = re.split('-', sys.argv[2])
            for num in range(int(r[1])):
                ip = r[0][:-1] + str(num)
                ip_list.append(ip)

    elif (sys.argv[1] == '-i'):
        with open(sys.argv[2], 'r') as file:
            f = file.read().split('\n')
            ip_list = list(filter(None, f))

    elif (sys.argv[1] == '-W'):
        with open(sys.argv[2], 'r') as file:
            # f = file.read().split('\n')
            # file.read().split('inetnum')
            for line in file:
                if "inetnum" in line:
                    ips = prog_ip.findall(line)
                    startip = ips[0]
                    startip = startip[0] + '.' + startip[1] + '.' + startip[2] + '.' + startip[3]
                    endip = ips[1]
                    endip = endip[0] + '.' + endip[1] + '.' + endip[2] + '.' + endip[3]
                    cidrs = netaddr.iprange_to_cidrs(startip, endip)
                    net2 = ipaddress.ip_network(cidrs[0])
                    for x in net2.hosts():
                        ip_list.append(str(x))

    else:
        print("Invalid arguments!")
        sys.exit(1);

    return ip_list


def wordList():
    word_list = list()

    start = 0
    for arg in range(len(sys.argv) - 1, -1, -1):
        if sys.argv[arg] == '-w':
            start = arg + 1

    if start > 0:
        for x in range(start, len(sys.argv)):
            if sys.argv[x] == '-t':
                break
            else:
                word_list.append(sys.argv[x])




    return word_list


def validIpRange(ran):
    verification = prog_ip_range.search(ran)
    if verification == None:
        print("Invalid IP range: ", ran)
        sys.exit(1)

    return True


def validIpMask(mask):
    ver = prog_mask.search(mask)
    if ver == None:
        print("Invalid IP mask: ", mask)
        sys.exit(1)

    return True


def validIpList(l):
    for ip in l:
        verification = prog_ip.search(ip)
        if verification == None:
            print("Invalid IP adress: ", ip)
            sys.exit(1)

    return True


def tallyIpResults(wordListPresent):
    x = 0
    for r in results:
        if (results[r][0] != -1):
            x = x + 1
        if (wordListPresent):
            print(r, "\trcode: ", results[r][0], "\ttarget: ", results[r][1])
        else:
            print(r, "\trcode: ", results[r][0])

    print("\n")
    print(str(x), " IP adresses are up")
    print("\n")


def save(wordListPresent, filename):
    x = 0
    with open(filename, 'w') as file:
        for r in results:
            if (results[r][0] != -1):
                x = x + 1

            if (wordListPresent):
                value = r + "\trcode: " + str(results[r][0]) + "\ttarget: " + str(results[r][1]) + "\n"
                file.write(value)
            else:
                value = r + "\trcode: " + str(results[r][0]) + "\n"
                file.write(value)

        file.write("\n" + str(x) + " IP adresses are up.")


def message():
    print("")
    print(" ***************************************************")
    print(" *                      ELAYV                      *")
    print(" *                                                 *")
    print(" *              OSINT Web Page Finder              *")
    print(" ***************************************************")
    print("")
    print("Searches for the IP adresses that respond to port 80 in the specified ")
    print("subnet and checks if the IP adresses belong to the same person/company")
    print("")


def findMaxIterations(length):
    MaxNumOfThreads = length

    for x in range(len(sys.argv)):
        if (sys.argv[x] == '-t'):
            MaxNumOfThreads = int(sys.argv[x + 1])
            break

    iterations = length // MaxNumOfThreads

    if (length % MaxNumOfThreads != 0):
        iterations = iterations + 1

    return (iterations, MaxNumOfThreads)


def run():
    message()
    ip_list = ipAddresses()
    info = findMaxIterations(len(ip_list))
    iterations = info[0]
    MaxNumOfThreads = info[1]

    length_ip_list = len(ip_list)
    start = 0
    end = MaxNumOfThreads
    run_search = False

    word_list = wordList()

    for x in range(iterations):
        valid_ips = scanIps(ip_list[start:end], word_list)

        for ip in valid_ips:
            ip.join()

        if (length_ip_list - end) >= MaxNumOfThreads:
            start = end
            end = end + MaxNumOfThreads
        else:
            start = end
            end = length_ip_list

    wordListPresent = False
    if not word_list:
        wordListPresent = False
    else:
        wordListPresent = True

    saveToFile = False
    for x in range(len(sys.argv)):
        if sys.argv[x] == '-o':
            saveToFile = True
            filename = sys.argv[x + 1]
            break

    if saveToFile:
        save(wordListPresent, filename)
    else:
        tallyIpResults(wordListPresent)

    print("---FINISHED---")


def help_function():
    print("Help shall be given, if ye but ask.\n")
    print("USAGE:")
    print("NOTE: IP ADDRESS MUST BE GIVEN FIRST. AFTER THAT THE ORDER OF ARGUMENTS DO NOT MATTER")
    print("-l list of IP adresses passed one by one")
    print("-m CIDR range in the form: 192.169.1.0/24")
    print("-r IP range in the form: 192.168.1.35-60")
    print("-w list of words seperated by space. -w word1 word2")
    print("-t limit for the number of threads. -t 50")
    print("-i specify an input file to read from")
    print("-W specify single WHOIS output as an input file in order to scan the inetnum range.")
    print("-o output file. -o results.txt\n")

    print("EXAMPLES:")
    print("python3 elayv.py -m 192.168.1.0/24 -w microsoft google -t 50")
    print("python3 elayv.py -l 10.0.0.1 192.168.1.14 127.0.0.1 8.8.8.8 -w Computer Company-Name Tech")
    print("python3 elayv.py -r 192.168.1.5-35 -w rap rock pop jazz -o output.txt")
    print("python3 elayv.py -W whois-output.txt")


if __name__ == "__main__":
    if (sys.argv[1] == '-h'):
        help_function()
    else:
        run()