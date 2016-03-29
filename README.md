# HIDPS
A Python based Intrusion Detection and Prevention System. Uses Scapy to sniff packets at a specific interface, extract the remote IPs, scans them using the VirusTotal API and puts them into a Whitelist, Blacklist or Greylist depending on the rating threshold.


requirement:
+ Python 2.7
+ Tkinter, netfilter, urllib2, urllib, simplejson, fcntl, easygui (you can install manually using pip)
