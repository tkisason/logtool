#!/usr/bin/python
from compiler.syntax import check
from uasparser import UASparser
from datetime import datetime, date, time  
import  re
import csv
import sys
import urllib2
import pygeoip
import matplotlib.pyplot as plt
import numpy as np

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
    row = 0
    list_tor = tor_exit_nodes()
    now = str(date.strftime(datetime.now(), '%d%m%y%H%M'))
    out = open('tor_' + now + '.log', 'w')
    total_rows_log = len(logRows)
    total_tor_nodes = len(list_tor)
    for tor_ip in range(total_tor_nodes):
        for row in range(total_rows_log):
            sys.stdout.write("\rTrying Tor node #%s of #%s with log row  #%s " % (str(tor_ip), str(total_tor_nodes), str(row)))
            sys.stdout.flush()   
            if str(logRows[row][0]) == str(list_tor[tor_ip]):
                 print '\nMatch found writing to file ... \n'
                 out.write("%s\t%s\t%s\t%s\t%s\t%s\n" % (logRows[row][0], logRows[row][3], logRows[row][4], logRows[row][5], logRows[row][7], logRows[row][8]))
    out.close()    
    


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
    total_rows_in_log = len(logRows)
    #only 'ua_icon' or 'os_icon' or both are allowed in entire_url
    now = str(date.strftime(datetime.now(), '%d%m%y%H%M'))
    out = open('ua_' + now + '.log', 'w')
    for row_log in range(total_rows_in_log):
        #todo : progress bar
        #perc=(float(row_log)/float(total_rows_in_log))*100
        #progress(perc)
        sys.stdout.write("\rParsing row log #%s of %s" % (str(row_log), str(total_rows_in_log)))
        sys.stdout.flush()   
        ua_string = str(logRows[row_log][8])
        parsed_ua = uas_parser.parse(ua_string)
        if(parsed_ua['ua_name'] == "unknown"):
            out.write("%s\t%s\t%s\t%s\n" % (parsed_ua['typ'], parsed_ua['ua_name'], parsed_ua['os_name'], ua_string))
        else:
            out.write("%s\t%s\t%s\n" % (parsed_ua['typ'], parsed_ua['ua_name'], parsed_ua['os_name']))
        #save in file
    out.close()
    
#Distributions of User agent attributes based on formatted output given by the function uas_parser
def dist_ua(ua_log):
    #finds known UA and return distribution as a dictionary
    list_log = listify_ua_log(ua_log)
    len_list = len(list_log)
    unique_ua = []
    for i in range(len_list):
        if str(list_log[i][1]) in unique_ua or str(list_log[i][1]) == 'unknown':
            #print 'line:'+str(i)
            continue
        else:
            unique_ua.append(str(list_log[i][1]))
    len_browser = len(unique_ua)
    counter = 0
    dist_browser = {}
    for i in range(len_browser):
        for line in range(len_list):
            if str(unique_ua[i]) == str(list_log[line][1]):
                counter = counter + 1
                dist_browser[str(unique_ua[i])] = counter
    return dist_browser

def listify_ua_log(ua_log):
    file = open(ua_log, 'r')
    list_log = []
    for line in file:
        line = line.split('\t')
        list_log.append(line)
    return list_log

def dist_os(ua_log):
    #find operating sys from log
    list_log = listify_ua_log(ua_log)
    len_list = len(list_log)
    unique_os = []
    for i in range(len_list):
        str_os = str(list_log[i][2]).replace('\n', '')
        if str_os in unique_os or str_os == 'unknown':
            #print 'line:'+str(i)
            continue
        else:
            unique_os.append(str_os)
    len_os = len(unique_os)
    counter = 0
    dist_os = {}
    for i in range(len_os):
        for line in range(len_list):
            curr_os = str(list_log[line][2]).replace('\n', '')
            if str(unique_os[i]) == curr_os:
                counter = counter + 1
                dist_os[str(unique_os[i])] = counter
    return dist_os

def dist_weird_ua(ua_log):
    #find weird_ua
    list_log = listify_ua_log(ua_log)
    len_list = len(list_log)
    dist__weird_ua = {}
    unique_weird_ua=[]
    for line in range(len_list):
        if str(list_log[line][2])=='unknown':
            weird_ua=str(list_log[line][3]).replace('\n', '')
            if weird_ua not in unique_weird_ua:
                unique_weird_ua.append(weird_ua)
    len_ua = len(unique_weird_ua)
    counter = 0
    dist_weird_ua = {}
    for i in range(len_ua):
        for line in range(len_list):
            if str(list_log[line][2])=='unknown':
                curr_ua=str(list_log[line][3]).replace('\n', '')
            else:
                continue
            if str(unique_weird_ua[i]) == curr_ua:
                counter = counter + 1
                dist_weird_ua[str(unique_weird_ua[i])] = counter
    return dist_weird_ua

def plot_dist(dist={}):
#    data = [ ("data1", 34), ("data2", 22),
#            ("data3", 11), ( "data4", 28),
#            ("data5", 57), ( "data6", 39),
#            ("data7", 23), ( "data8", 98)]
    N = len(dist)
    x = np.arange(1, N+1)
    y = dist.values()
    labels = dist.keys()
    labs=tuple(labels)
    xt=tuple(x)
    width = np.arange(0,N)+0.5
    bar1 = plt.bar(x, y,width,color='grywbcmr')
    plt.legend(labs)
    plt.ylabel('Frequency')
    plt.show()
  
def geoip(strIP):
    ##using http://code.google.com/p/pygeoip/wiki/Usage
    gi = pygeoip.GeoIP('/home/amb/workspace/logtool/GeoIP.dat')
    country = gi.country_name_by_addr(strIP)
    return country
   
def detect_attacks(logRows=[]):
    xss_re='/((\%3C)|<)((\%2F)|\/)*W+((\%3E)|>)/ix'
    inj_flaw='/(\')|(\%27)|(\-\-)|(#)|(\%23)/ix'
    mal_file_exec='/(https?|php|data):/i'
    dir_obj_reference='/(\.|(%|%25)2E)(\.|(%|%25)2E)(\/|(%|%25)2F|\\|(%|%25)5C)/i'
    rfi='(\.\.\/)'
    bad_req=[]
    for row in range(len(logRows)):
       curr_row=str(logRows[row][4])
       if re.match(xss_re,curr_row) is not None:
           bad_req.append(curr_row)
       if re.match('(\.\.\/)+',curr_row) is not None:
           bad_req.append(curr_row)
    return bad_req
           
    
              
usage = """
        ----------------------------------------------------------------------
        logtool apache, find interesting patterns in apache access log files
            
        usage: logtool_apache.py [infile] 
        options:
        1. check for tor nodes in log file
        2. Export user agents
        3. Query Geoip for IP's country
        4. Return unique browsers
        5. Find xss attempts
        6. Exit
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
             option = raw_input('Enter you choice (for help enter 0):\t')
             if int(option) == 0:
                  print usage
                  option = -1
             elif int(option) == 1:
                  print check_tor_nodes(logRows)
                  option = -1
             elif int(option) == 2:
                  ua_list = uas_parser(logRows)
                  option = -1
             elif int(option) == 3:
                  ip = raw_input('Enter IP:\t')
                  c = geoip(str(ip))
                  print c
                  option = -1
             elif int(option) == 4:
                 ua_log = raw_input('Name of log to parse:\t')
                 lua = []
                 lua = dist_ua(ua_log)
                 plot_dist(lua)
                 option = -1
             elif int(option) == 5:
                print detect_attacks(logRows)
             elif int(option) == 6:
                break     
             else:
                  print 'Problem with option see usage instructions!\n'   
        
          #printLines(logRows)
          #UAlist()
        
