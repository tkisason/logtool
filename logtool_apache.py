#!/usr/bin/python
import  re
import csv
import sys
import urllib2
from compiler.syntax import check
from uasparser import UASparser  

def tor_exit_nodes():
    tor_exit_nodes = "http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv"
    list_tor_exit_nodes = urllib2.urlopen(tor_exit_nodes).read()
    list_tor_exit_nodes = list_tor_exit_nodes.split("\n")
    #print list
    return list_tor_exit_nodes
    
def is_tor_exit(ip):
    list = "http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv"
    list = urllib2.urlopen(list).read()
    list = list.split("\n")
    #print list
    ip_tor_exit = False
    for i in range(len(list)):
        if list[i] == ip:
            return True
                
def check_tor_nodes(logRows):
    #check for tor exit nodes present in the log used for requesting data 
    list_tor = []
    list_tor = tor_exit_nodes()
    for tor_ip in range(len(list_tor)):
        for row in range(len(logRows)):
            if str(logRows[row][0]) == str(list_tor[tor_ip]):
                 print str(logRows[row][0]) + "\t" + str(logRows[row][3]) + "\t" + str(logRows[row][4]) + "\t" + str(logRows[row][5]) + "\t" + str(logRows[row][7]) + "\t" + str(logRows[row][8])
                 #todo:save in file

def readLogLine(pathToLog):
    f = open(pathToLog, 'r')
    row = []
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
        print str(logRows[row][0]) + "\t" + str(logRows[row][3]) + "\t" + str(logRows[row][4]) + "\t" + str(logRows[row][5]) + "\t" + str(logRows[row][7]) + "\t" + str(logRows[row][8])
        
def uas_parser(logRows=[]):
    uas_parser = UASparser()  
    total_rows_in_log=len(logRows)
    #only 'ua_icon' or 'os_icon' or both are allowed in entire_url
    
    out = open('ua.log', 'w')
    for row_log in range(total_rows_in_log):
        #todo : progress bar
        #perc=(float(row_log)/float(total_rows_in_log))*100
        #progress(perc)
        sys.stdout.write("\rParsing row log #%s of %s" % (str(row_log),str(total_rows_in_log)))
        sys.stdout.flush()   
        ua_string = str(logRows[row_log][8])
        parsed_ua = uas_parser.parse(ua_string)
        if(parsed_ua['ua_name'] == "unknown"):
            out.write("%s\t%s\t%s\t%s\n" % (parsed_ua['typ'], parsed_ua['ua_name'], parsed_ua['os_name'], ua_string))
        else:
            out.write("%s\t%s\t%s\n" % (parsed_ua['typ'], parsed_ua['ua_name'], parsed_ua['os_name']))
        #save in file
    out.close()
       
usage = """
        ----------------------------------------------------------------------
        logtool apache, find interesting patterns in apache access log files
            
        usage: logtool_apache.py [infile] 
        options:
        1. check for tor nodes in log file
        2. export user agents
        3. ...
        4. ...
        5. exit app
        ----------------------------------------------------------------------
      """
if __name__ == '__main__':
    option = -1
    if len(sys.argv) != 2:
         print('Problem with Apache access log path\n' + 'Debug info:' + str(sys.argv) + '\n')
    elif len(sys.argv) == 2:
         logRows = readLogLine(sys.argv[1])
         print 'Log:' + sys.argv[1]
         print 'No of records in log:' + str(len(logRows))
         while(int(option) == -1):
             option = raw_input('Enter you choice (for help enter 0):')
             if int(option) == 0:
                  print usage
                  option = -1
             elif int(option) == 1:
                  print check_tor_nodes(logRows)
                  option = -1
             elif int(option) == 2:
                  ua_list = uas_parser(logRows)
                  option = -1
             elif int(option) == 5:
                break     
             else:
                  print 'Problem with option see usage instructions!\n'   
        
          #printLines(logRows)
          #UAlist()
        
