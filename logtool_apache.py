#!/usr/bin/python
import  re
import sys
import urllib2



def is_tor_exit(ip):
    list = "http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv"
    list = urllib2.urlopen(list).read()
    list = list.split("\n")
    print list
    ip_tor_exit=False
    for i in range(len(list)):
        if list[i]==ip:
            return True
        
        

def readLogLine(pathToLog):
    f = open(pathToLog, 'r')
    row=[]
    for line in f:
        #print line
        row.append(re.findall('\[[^\]]*\]|\"[^\"]*\"|\S+', line))
    f.close()
    return row
    #print line.split(" ")
    #print f.readline()
    
def printLines(logRows):
    #ispisujemo samo korisne podatke
    #0 - ip koji je pristupao
    #3 - vrijeme i datum kada se pristupalo
    #4 - request 
    #5 - http status
    #7 - referer
    #8 - agent
    for row in range(len(logRows)):
        print str(logRows[row][0])+"\t"+str(logRows[row][3])+"\t"+str(logRows[row][4])+"\t"+str(logRows[row][5])+"\t"+str(logRows[row][7])+"\t"+str(logRows[row][8])
    

if __name__ == '__main__':
     if len(sys.argv) != 2:
          print('Problem with Apache access log path\n')
          print('Debug info:'+str(sys.argv)+'\n')
     elif len(sys.argv) == 2:
          logRows=readLogLine(sys.argv[1])
          print 'Lines:'+str(len(logRows))
          print is_tor_exit('212.13.195.157')
          #printLines(logRows)

        
