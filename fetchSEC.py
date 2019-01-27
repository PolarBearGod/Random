#!/usr/bin/python -u

import sys
import urllib
import httplib2
import time
import re
import argparse
from time import localtime,strftime
from xml.dom import minidom
import json

#argument parser for earliest and latest parameters
parser = argparse.ArgumentParser(description='Create Query, Execute, and Retrieve Data - parameters are earliest and latest')
parser.add_argument('-e','--earliest', help='Input earliest query time, ie. 09/01/2015:00:00:00',required=True)
parser.add_argument('-l','--latest', help='Input latest query time, ie. 09/02/2015:00:00:00',required=True)
args = parser.parse_args()

#Date Formatting for filename
earliestsplit=re.split('/|:',args.earliest)
earliestdate=("%s%s%s" % (earliestsplit[2],earliestsplit[0],earliestsplit[1]))
latestsplit=re.split('/|:',args.latest)
latestdate = ("%s%s%s" % (latestsplit[2],latestsplit[0],latestsplit[1]))

#output file location and name
f = open('/hadoop/temp/SEC_%s%s.csv' %(earliestdate,latestdate),'w')
sys.stdout = f

#Server Information
baseurl = 'SPLUNK_SERVER_ADDRESS:PORT (8089 usually)'
username = 'USERNAME'
password = 'PASSWORD'

myhttp = httplib2.Http()

#Step 1: Get a session key
#servercontent = myhttp.request(baseurl + '/services/auth/login', 'POST',
servercontent = httplib2.Http(disable_ssl_certificate_validation=True).request(baseurl + '/services/auth/login', 'POST',
headers={}, body=urllib.urlencode({'username':username, 'password':password}))[1]
sessionkey = minidom.parseString(servercontent).getElementsByTagName('sessionKey')[0].childNodes[0].nodeValue
#print "====>sessionkey:  %s  <====" % sessionkey

#Step 2: Create a search job
searchquery = 'QUERY STRING earliest=%s latest=%s | sort 0 _time | table _time _raw'  % (args.earliest,args.latest)
if not searchquery.startswith('search'):
    searchquery = 'search ' + searchquery

searchjob = httplib2.Http(disable_ssl_certificate_validation=True).request(baseurl + '/services/search/jobs','POST',
headers={'Authorization': 'Splunk %s' % sessionkey},body=urllib.urlencode({'search': searchquery}))[1]
sid = minidom.parseString(searchjob).getElementsByTagName('sid')[0].childNodes[0].nodeValue
#uncomment below to debug
#print "====>sid:  %s  <====" % sid

#Step 3: Get the search status
httplib2.Http(disable_ssl_certificate_validation=True).add_credentials(username, password)
servicessearchstatusstr = '/services/search/jobs/%s/' % sid
isnotdone = True
while isnotdone:
    searchstatus = httplib2.Http(disable_ssl_certificate_validation=True).request(baseurl + servicessearchstatusstr, 'GET', headers={'Authorization': 'Splunk %s'% sessionkey}, body=urllib.urlencode({'search': searchquery}))[1]
    isdonestatus = re.compile('isDone">(0|1)')
    isdonestatus = isdonestatus.search(searchstatus).groups()[0]
    if isdonestatus == '1':
        isnotdone = False
#uncomment below to debug
#print "====>search status:  %s  <====" % isdonestatus

#Step 4: Get the search results
offsetbase = 0
searchresults=0
while searchresults!='':
	services_search_results_str = '/services/search/jobs/%s/results?output_mode=csv&offset=%i&count=49999' % (sid,int(offsetbase))
	searchresults = httplib2.Http(disable_ssl_certificate_validation=True).request(baseurl + services_search_results_str, 'GET',  headers={'Authorization': 'Splunk %s'% sessionkey}, body=urllib.urlencode({'search': searchquery}))[1]
	print searchresults
	offsetbase = offsetbase + 50000
