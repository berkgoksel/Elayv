# Elayv
Find Webpages on a Certain IP Range (especially for huge ranges)

Searches for the IP adresses that respond to port 80 in the specified subnet 
and checks if the IP adresses belong to the same company.

# Dependencides
You can install the dependencies using pip.

>pip3 install -r requirements.txt

# Usage 
python3 <scan_type> <range/input_file> <args>

-l list of IP adresses passed one by one
-m CIDR range in the form: 192.169.1.0/24
-r IP range in the form: 192.168.1.35-60
-w list of words seperated by space. -w word1 word2
-t limit for the number of threads. -t 50
-i specify an input file to read from
-W specify single WHOIS output as an input file in order to scan the range specified in inetnum. 
-o output file. -o results.txt


Examples:

python3 elayv.py -m 192.168.1.0/24 -w microsoft google -t 50
python3 elayv.py -l 10.0.0.1 192.168.1.14 127.0.0.1 8.8.8.8 -w Computer Company-Name Tech
python3 elayv.py -r 192.168.1.5-35 -w rap rock pop jazz -o output.txt
python3 elayv.py -W whois-output.txt
