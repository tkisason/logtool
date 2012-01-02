import urllib2



def is_tor_exit(ip):
    list = "http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv"
    list = urllib2.urlopen(list).read()
    list = list.split("\n")
    print list
