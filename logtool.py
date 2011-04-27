#!/usr/bin/python

import sys
import re
import socket
import time
import thread

def riplookup(ipt={}):
    for i in ipt:
        try:
            ipz = str( socket.gethostbyaddr(i)[0] )
        except:
            ipz = "???"
        print i + "\t\t" + str(ipt.get(i)) + "\t\t" + str(ipz)

def rdns(ip):
        try:
            ipz = str( socket.gethostbyaddr(ip)[0] )
        except:
            ipz = "???"
        return ipz


def gr(item,regex):
	if re.search(regex,item, re.IGNORECASE):
		return item
	else:
		return ''

def p(var):	
	sys.stdout.write(var)
			
def mgr(item,regexen = []):
	for reg in regexen:
		it = gr(item,reg)
		if it == '':
			return ''
	return it
	
def wc(logfile = [],regexen = []):
	cnt = 0
	for line in logfile:
		if(mgr(line,regexen) != ''):
			cnt = cnt+1
	logfile.seek(0)
	return cnt

def userstats(log,users = []):
    print "User Statistics:"
    print "usr\t\tOK\t\tNOK\t\t%OK\t\t%NOK"
    for user in users:
        acc = wc(log,[user,"accept"])
        fai = wc(log,[user,"failed"])
#       print user + "\t\t\t" + str(acc) + "\t" + str(fai) + "\t" + str(float(acc)/float(acc+fai)*100)[:5] + "%" + "\t" + str(float(fai)/float(acc+fai)*100)[:5] + "%"
        print "%-15s\t%-10s\t%-10s\t%-10s\t%-10s"%(user,str(acc),str(fai),str(float(acc)/float(acc+fai)*100)[:5],str(float(fai)/float(acc+fai)*100)[:5])

def return_ips(log):
    item = []
    ips = {}
    for i in log:
        item.append(str(re.findall('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',i))[2:-2])
    for i in item:
        if not ips.has_key(i):
            ips[i] = 0
        ips[i] = ips[i] + 1
    ips.__delitem__("")
    ips.__delitem__("127.0.0.1")
    ips.__delitem__("0.0.0.0")
    
    return ips


def ipstats(filename,log):
    FILE = open(filename,"w")
    ips = return_ips(log)
    FILE.write("IP\t\tOK\tNOK\t%OK\t%NOK\ttotal:\thost:+\n")
    for i in ips:
        nok = wc(log,[i,"Failed"])
        ok = wc(log,[i,"Accepted"])
        tot = ok + nok
        if ((nok > ok) and (tot>0)):
            FILE.write(str(i) + "\t" + str(ok) + "\t" + str(nok) + "\t" + str(((float(ok)/float(tot))*100))[:5] + "\t"  + str(((float(nok)/float(tot))*100))[:5] + "\t" + str(tot) + "\t" + str(rdns(i))+"\n")
            FILE.flush()
        elif (tot > 0):
            FILE.write(str(i) + "\t" + str(ok) + "\t" + str(nok) + "\t" + str(((float(ok)/float(tot))*100))[:5] + "\t"  + str(((float(nok)/float(tot))*100))[:5] + "\t" + str(tot) + "\t"+ str(rdns(i))+"\n")
            FILE.flush()
    FILE.close()     

def user_ipstats(filename,log):
    ips = return_ips(log)
    FILE = open(filename,"w")
    FILE.write("IP\t\tOK\tNOK\t%OK\t%NOK\ttotal:\thost:\n")
    for i in ips:
        nok = wc(log,[i,"Failed"])
        ok = wc(log,[i,"Accepted"])
        tot = ok + nok
        if ((nok > ok) and (tot>0)):
            FILE.write(str(i) + "\t" + str(ok) + "\t" + str(nok) + "\t" + str(((float(ok)/float(tot))*100))[:5] + "\t"  + str(((float(nok)/float(tot))*100))[:5] + "\t" + str(tot) + "\t" + str(rdns(i))+"\n")
            for out in uip_correlate(log,i):
                FILE.write("\t" + out+"\n")
            FILE.flush()
        elif (tot > 0):
            FILE.write(str(i) + "\t" + str(ok) + "\t" + str(nok) + "\t" + str(((float(ok)/float(tot))*100))[:5] + "\t"  + str(((float(nok)/float(tot))*100))[:5] + "\t" + str(tot) + "\t"+ str(rdns(i))+"\n")
            for out in uip_correlate(log,i):
                FILE.write("\t" + out+"\n")
            FILE.flush()
    FILE.close()
        


def return_users(log):
    usernames = [];
    for i in log:
        a = (str(re.findall('for.+from',i)).replace('invalid user ',''))[6:-7]
        if a != '':
            usernames.append(a)
    return usernames

def uip_correlate(log,ip):
    a = []
    for i in log:
        a.append(mgr(i,[ip]))
    a = list(set(return_users(a)))
    return a


def write_users(file,log):
    usrlist = list(set(return_users(log)))
    FILE = open(file,"w")
    for elem in usrlist:
        FILE.write(elem+"\n")
        FILE.flush()
    FILE.close()

usage =  """
logtool, find interesting patterns in authpriv files
useful for finding compromised machines/users
written by: tonimir kisasondi

usage: logtool.py [infile] [option] [outfile]
options:
-u : print usernames
-i : print ip statistics
-s : print user/ip correlated statistics
"""

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print usage
    if len(sys.argv) == 4:
        log=open(sys.argv[1],'r')
        filename = sys.argv[3]
        opt = sys.argv[2]
        if opt == "-u":
            write_users(filename,log)
            print "[+] usernames written to " + filename 
        if opt == "-i":
            print "[+] grab a cup of coffee, this might take some time..."
            ipstats(filename,log)
            print "[+] ip statistics written to " + filename
        if opt == "-s":
            print "[+] grab a cup of coffee, this might take some time..."
            user_ipstats(filename,log)
            print "[+] user/ip statistics written to " + filename



