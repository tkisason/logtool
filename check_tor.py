import urllib2



def is_tor_exit(ip):
    list = "http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv"
    list = urllib2.urlopen(list).read()
    list = list.split("\n")
    if ip in list:
        return 1
    else:
        return 0

def is_tor_server(ip):
    list = "http://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv"
    list = urllib2.urlopen(list).read()
    list = list.split("\n")
    if ip in list:
        return 1
    else:
        return 0


