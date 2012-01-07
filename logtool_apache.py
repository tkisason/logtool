#!/usr/bin/python
import  re
import csv
import sys
import urllib2
from compiler.syntax import check

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

def use_rest_ua_detect(strUA):
    url_api = "http://www.useragentstring.com/?uas=" + strUA + "&getText=all"
    print "debuh url_api: " + url_api
    list = urllib2.urlopen(url_api).read()
    print "debug list: " + list
    list = list.split(";")
    
               

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
    
def UA_match(logRows, UA):
    #checking user agents
    found_UA = False
    not_recognized_UA = []
    for row_log in range(len(logRows)):
        for row_csv in range(len(UA)):
            UA_log = str(logRows[row_log][8].replace('"', ''))    
            UA_csv = str(UA[row_csv][1])
            #print "cur_row_log:    " + cur_row_log + "    csv r:    " + csv_row + "\n"
            if UA_log == UA_csv:
                found_UA = True
                print UA[row_csv][0] + "\t" + UA[row_csv][6]
            else:
                not_recognized_UA.append(row_log)
                    
   
        #print 'Defected or unknown user agent'
        #add to some list for further analysis
            
    
def UA_list():
    #usage
    #ua=list_User_Agents()
    #ua[123][0]+ua[123][1]+ua[123][3]
    
    uaCvs = 'browscap.csv'
    uaList = csv.reader(open(uaCvs, 'rb'), delimiter=',')
    UA = []
    for row in uaList:
        UA.append(row)
    return UA
    
usage = """
        ----------------------------------------------------------------------
        logtool apache, find interesting patterns in apache access log files
            
        usage: logtool.py [infile] 
        options:
        1. check for tor nodes in log file
        2. export user agents 
        ----------------------------------------------------------------------
      """
if __name__ == '__main__':
   
    if len(sys.argv) != 2:
         print('Problem with Apache access log path\n' + 'Debug info:' + str(sys.argv) + '\n')
    elif len(sys.argv) == 2:
         logRows = readLogLine(sys.argv[1])
         print 'Log:' + sys.argv[1]
         print 'No of records in log:' + str(len(logRows))
         option = raw_input('Enter you choice (for help enter 0):')
         if int(option) == 0:
              print usage
              option = raw_input('Enter you choice (for help enter 0):')
         elif int(option) == 1:
              print check_tor_nodes(logRows)
              option = raw_input('Enter you choice (for help enter 0):')
         elif int(option) == 2:
              UAList = UA_list()
              UA_match(logRows, UAList)
              option = raw_input('Enter you choice (for help enter 0):')
         else:
              print 'Problem with option see usage instructions!\n'   
        
          #printLines(logRows)
          #UAlist()
        
