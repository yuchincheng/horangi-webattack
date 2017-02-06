#===========================================================#
#   Python IIS Log Parser and filter 
#===========================================================#
# Copyright 2017, Julia YuChin Cheng (julia.yc.cheng@gmail.com)
# spilp is distributed under the terms of GNU General Public License v3
# A copy of GNU GPL v3 license can be found at http://www.gnu.org/licenses/gpl-3.0.html
#
# Created - 02/02/2017

#!/usr/bin/python

import os
import json
import re
import socket
import sys
import time
import urllib
import ast
from elasticsearch import Elasticsearch


try:
    import xml.etree.cElementTree as etree
except ImportError:
    import xml.etree.ElementTree as etree
    
logfile = "exam1.log" #log file to be parsed and matched
xmlfilterfile = "idsSig.xml" # filter rules to detect web attacks

names = {
    'xss'   : 'Cross-Site Scripting',
    'sqli'  : 'SQL Injection',
    'csrf'  : 'Cross-Site Request Forgery',
    'dos'   : 'Denial Of Service',
    'dt'    : 'Directory Traversal',
    'spam'  : 'Spam',
    'id'    : 'Information Disclosure',
    'rfe'   : 'Remote File Execution',
    'lfi'   : 'Local File Inclusion',
    'ws'    : 'Web Shell'
}

html_header = """<html><head><style type="text/css"> 
body { font: normal 11px auto "Helvetica", Verdana, Arial, Helvetica, sans-serif; color: #4f6b72; background: #E6EAE9; } 
a { color: #c75f3e; }
#mytable { width: 800px; padding: 0; margin: 0; style="word-break:break-all" } 
caption { padding: 0 0 5px 0; width: 800px; font: Helvetic 11px "Helvetica", Verdana, Arial, Helvetica, sans-serif; 
    text-align: left; } 
th { style="word-break:break-all" font: bold 11px "Arial", Verdana, Arial, Helvetica, sans-serif; color: #4f6b72; border-right: 1px solid #C1DAD7; 
    border-bottom: 1px solid #C1DAD7; border-top: 1px solid #C1DAD7; letter-spacing: 2px; text-align: left; padding: 6px 6px 6px 12px; background: #CAE8EA; } 
th.nobg { border-top: 0; border-left: 0; border-right: 1px solid #C1DAD7; background: none; } 
td { style="word-break:break-all" border-right: 1px solid #C1DAD7; border-bottom: 1px solid #C1DAD7; background: #fff; font-size:11px; padding: 6px 6px 6px 12px; 
    color: #4f6b72; } 
td.alt { background: #F5FAFA; color: #797268; } 
th.spec { border-left: 1px solid #C1DAD7; border-top: 0; background: #fff; font: bold 10px "Helvetica", Verdana, Arial, Helvetica, sans-serif; } 
th.specalt {  border-left: 1px solid #C1DAD7; border-top: 0; background: #f5fafa; 
font: bold 10px "Helvetica", Verdana, Arial, Helvetica, sans-serif; color: #797268; } 
html>body td {font-size:11px;} 
</style></head><body>"""
    
#Regular expression to parse the IIS fileds
def fieldsParser ():
    regex=re.compile(r"(?P<date>^\d+[-\d+]+ [\d+:]+)\s(?P<serversite>\S+)\s(?P<method>\S+)\s(?P<page>/\S*)\s(?P<querystring>([\S*\s]*)(?=443|80))(?P<port>\d+)\s(?P<username>\S+)\s(?P<clienthost>[\d*.]*)\s(?P<useragent>([\S*\s]*)(?=http|-))(?P<referrer>([\S*\s]*)(?=[0-9]{3}))(?P<response>\d+)\s(?P<subresponse>\d+)\s(?P<scstatus>\d+)\s(?P<time_taken>\d+)")
    
    return regex

#Check file extensions to filter unsuspicious pages        
def checkExtensions (path):
    PATH_EXTENTIONS = set (('gif jpg jpeg png bmp ico svg svgz ttf otf eot woff woff2 class css js xml robots.txt webp').split())
    try:
        fileext = path.split('.')[1]
    except IndexError:
        fileext = ""
    
    if fileext in PATH_EXTENTIONS:
        pathcode = 1
    else:
        pathcode = 0
        
    return pathcode
    
 #Process log to JSON format and extarct the urls list           
def getFields (logstr):
    relist = fieldsParser().findall(logstr) #re.compile matching
    try:
        JsonResult = {
            "date":         relist[0][0],
            "serversite":   relist[0][1],
            "method":       relist[0][2],
            "page":         relist[0][3],
            "querystring":  relist[0][4],
            "port":         relist[0][6],
            "username":     relist[0][7],
            "clienthost":   relist[0][8],
            "useragent":    relist[0][9],
            "referer":      relist[0][11],
            "response":     relist[0][13],
            "subresponse":  relist[0][14],
            "scstatus":     relist[0][15],
            "time_taken":   relist[0][16],
            "pathcode":     checkExtensions(relist[0][3])
        }
        return JsonResult
    except IndexError:
        JsonResult = {
            "nullmessage": relist,
            "pathcode": 0
        }
        return JsonResult
        
    
    
def getURLpath (JsonResult):
    if "nullmessage" not in JsonResult:
        if JsonResult['pathcode'] == 0 :  #not includ pre-defined file extentions
            if JsonResult['querystring'].strip()!="-":
                path = JsonResult['page'].strip()+"?"+JsonResult['querystring'].strip()
                return path
            else:
                path = JsonResult['page'].strip()
                return path
    else:
        path= ""
        return path
    
#Write file functions
def writeTofile(data,resultfilename):
     json.dumps(data, encoding='latin-1')
     f = open (resultfilename)
     f.write(data)
     

    
#XML Parser to get the object in dict
def xmlparse(xml_file):
    try:
        xml_handler = open(xml_file, 'r')
        doc = etree.parse(xml_handler).getroot()
        xml_handler.close()
        object_dict = {doc.tag: parse_node(doc)}
        #print object_dict
        return object_dict
    except IOError:
        print "error: problem with the filter's file"
        return {}

# XML object parser to get child nodes
def parse_node(node):
    tmp = {}
    # save attrs and text, hope there will not be a child with same name
    if node.text:
        tmp['value'] = node.text
    for (k,v) in node.attrib.items():
        tmp[k] = v
    for ch in node.getchildren():
        cht = ch.tag
        chp = parse_node(ch)
        if cht not in tmp: # the first time, so store it in dict
            tmp[cht] = chp
            continue
        old = tmp[cht]
        if not isinstance(old, list):
            tmp.pop(cht)
            tmp[cht] = [old] # multi times, so change old dict to a list
        tmp[cht].append(chp) # add the new one
    return    tmp


def get_value(array, default):
    if 'value' in array:
        return array['value']
    return default

#Store filter rules with dict in a list 
def xml_rule_filter(xmlobj):
    for group in xmlobj:
        for f in xmlobj[group]:
            if f == 'filter':
                if type(xmlobj[group][f]) == type([]):
                    filterlist = []
                    for elmt in xmlobj[group][f]:
                        filters={}
                        rule, impact, description, tags = "",-1,"",[]
                        
                        if 'id' in elmt:
                            idnum = get_value(elmt['id'], -1)
                            filters['id'] = idnum
                        
                        if 'impact' in elmt:
                            impact = get_value(elmt['impact'], -1)
                            filters['impact'] = impact
                        
                        if 'rule' in elmt:
                            rule = get_value(elmt['rule'], "")
                            filters['rule'] = rule

                            
                        if 'description' in elmt:
                            description = get_value(elmt['description'], "")
                            filters['description'] = description
                            
                        if 'tags' in elmt and 'tag' in elmt['tags']:
                            if type(elmt['tags']['tag']) == type([]):
                                for tag in elmt['tags']['tag']:
                                    tags.append(get_value(tag, ""))
                            else:
                                tags.append(get_value(elmt['tags']['tag'], ""))
                                
                            filters['tag'] = tags
                        
                        filterlist.append(filters)
                        
    return filterlist
                            
 #Web attacks detection through URL matching with signature                           
def matcher (urlp, rulelist):
    result = []
    for p in rulelist:
        t =re.compile(str(p['rule'])).search(urlp)
        if t:
           ruleMatch ={
                "Impact": p['impact'],
                "id"    : p['id'],
                'tags'  : p['tag']
           }
           result.append(ruleMatch)
    
    return result

 # Analyze Impact Level: get matchedID, description and attack category    
def impact_analysis (matcherList, xmlrulelist):
    ImpactLevel = [[],[],[],[],[],[],[]]
    
    for matchitem in matcherList:
        URL = getURLpath (matchitem)
        
        for item in matchitem['analysis']:
           matchFilter = (dictitem  for dictitem in xmlrulelist if dictitem['id'] == item['id'] ).next()
           impact_index = int(item['Impact'])-1
           #print matchFilter
           
           if not any(d['URL'] == URL for d in ImpactLevel[impact_index]):
                itemDict = {
                    'URL' : URL,
                    'referer': [matchitem['referer'].strip()],
                    'filterItem': [{ 'matchedID': item['id'], 'description': matchFilter['description'],'tag' : matchFilter['tag']}],
                    'clienthost': [ matchitem['clienthost'] ] }
                ImpactLevel[impact_index].append(itemDict)
           else:
                for d in ImpactLevel[impact_index]:
                    if d['URL'] ==URL:
                       if not any(t['matchedID'] == item['id'] for t in d['filterItem']) :
                            d['filterItem'].append({'matchedID': item['id'], 'description': matchFilter['description'], 'tag' : matchFilter['tag']})
                       
                       if matchitem['clienthost'] not in d['clienthost']:
                            d['clienthost'].append(matchitem['clienthost'])
                       
                       if matchitem['referer'] not in d['referer']:
                            d['referer'].append(matchitem['referer'].strip())
           
           
           
    return ImpactLevel

#Attack category analysis
def attack_analysis (matcherList, xmlrulelist):
    attackDict = {}
    for matchitem in matcherList:
        URL = getURLpath(matchitem)
        clienthost=matchitem['clienthost']
        referer = matchitem['referer'].strip()
        
        if URL not in attackDict:
            attackDict[URL] = [[],[clienthost], [referer]]
            for item in  matchitem['analysis']:
                if item['id'] not in attackDict[URL][0]:
                    attackDict[URL][0].append({ 'matchedID': item['id'], 'impact':item['Impact']})
        else:
            if clienthost not in attackDict[URL][1]:
                attackDict[URL][1].append(clienthost)
                
            if referer not in attackDict[URL][2]:
                attackDict[URL][2].append(referer)
                
            for item in matchitem['analysis']:
                if item['id'] not in attackDict[URL][0]:
                    attackDict[URL][0].append({ 'matchedID': item['id'], 'impact':item['Impact']})
 
    return attackDict

#Dispatch URLs, signature ID, clienthost and referer into attack categories
def dispatchDataToResult(dictdata,urldict):
    Result = {
        'xss':[],
        'sqli':[],
        'csrf':[],
        'dos':[],
        'dt':[],
        'spam':[],
        'id':[],
        'rfe':[],
        'lfi':[],
        'ws' : []
    }
    
    for i in urldict.keys():
        clienthost = urldict[i][1]
        referer = urldict[i][2]
        
        for j in urldict[i][0]:
            for k in dictdata :
                if k['id'] == j['matchedID']:
                    for z in k['tag']:
                        #try:
                        isUrlExist =False
                        for q in Result[z] :
                            if q['URL'] == i :
                                q['MatchID'].append(j)
                                isUrlExist =True
                                
                        if isUrlExist == False:
                            additem = {
                                'URL':i,
                                'MatchID':[j],
                                'ClientHost':clienthost,
                                'referer': referer
                            }
                            Result[z].append(additem)
    
    #Calculate the maximum impact of for each URL
    for i in Result:
        for j in Result[i]:
            impactlist = []
            for t in j['MatchID']:
                impactlist.append(t['impact'])
            maxImpact = max(impactlist)
            j['maxImpact']= maxImpact
    
    return Result



def generate_text_file(AttackResult, ImpactLevel):
    curtime = time.strftime("%Y-%m-%d", time.gmtime())
    fname = '%s_analysis_impact.txt' % (curtime)
    
    
    txt_header = "IIS log analysis based on IDS signature matching\n\n"

    try:
        out = open(fname, 'w')
        out.write(txt_header)
        
        logfile = "exam1.log" #log file to be parsed and matched

        out.write("Log file: %s\n" % logfile)
        out.write("IDS Signature: %s\n" % xmlfilterfile)
        out.write("Creation date: %s\n\n\n" % curtime)
        out.write("* This detection is based on IDS signature matching and the result only list maxImpact of URL higher than 4 !\n")
        out.write("* Determine the web attacks:  \n")
        out.write("         (1) No referer or suspicious referer \n")
        out.write("         (2) multiple signatures matched \n")
        out.write("         (3) higher impact score.\n\n")
        
        out.write("Summary:\n")
        for attname in AttackResult:
            out.write("\n===========================================================\n")
            out.write("%s : %s\n\n " % (attname, names[attname]))
            
            for t in AttackResult[attname]:
                if int(t['maxImpact']) > 3: 
                    out.write("URL = %s\n " %  t['URL'] )
        
        
        out.write("\n\n===========================================================\n")
        out.write("                     Detailed:\n\n")
        for attname in AttackResult:
            out.write("\n===========================================================\n")
            out.write("%s : %s\n\n " % (attname, names[attname]))
            
            for t in AttackResult[attname]:
                if int(t['maxImpact']) > 4: 
                    out.write("URL = %s\n " %  t['URL'] )
                    out.write("maxImpact = %d\n" %  int(t['maxImpact']))
                    out.write("Referer = %s\n" % t['referer'])
                    out.write("ClientHosts: %s\n" % t['ClientHost'])
                    idlist = []
                    for j in t['MatchID']:
                        idlist.append(j['matchedID'])
                    out.write("Matched ID: %s\n\n" %  set(idlist))
                
        out.close()
    except IOError:
        print("Cannot open the file:", fname)
    return


#Output HTML page to show results
def generate_html_Impact(AttackResult,ImpactLevel):
    
    curtime = time.strftime("%Y-%m-%d", time.gmtime())
    fname = '%s_analysis_impact.html' % (curtime)
    level = 6
    #fname = os.path.abspath(odir + os.sep + fname)
    try:
        out = open(fname, 'w')
        out.write(html_header)
        out.write("<h1>Web Log Analysis Report by Attack  & Impact - %s </h1><br>" % (curtime))
        #out.write(" <div class='block highlight'>\n")
        
        out.write("<h2>Web Attack Detection Results</h2>\n\n")
        out.write("<b>* To decrease false alarm, list maxImpact of URL higher than 4</b><br>")
        out.write("<b>* How to determine the web attacks ? (1) No referer (2) multiple matched signatures (3)higher impact score </b><br>")

        for attname in AttackResult:
            out.write("<table id='mytable' cellspacing='0' width=800px style='word-break:break-all'><caption align='left'><h2>%s : %s </h2></caption>" % (attname, names[attname]))
            
            for t in AttackResult[attname]:
                if int(t['maxImpact']) > 4: 
                    t['URL'] = urllib.quote_plus(t['URL'])
                    out.write("<tr><th scope='row' abbr='Model' class='spec'>%s</th></tr>" %  t['URL'] )
                    out.write("<tr><th scope='row' abbr='Model' class='spec'>maxImpact: %d</th></tr>" %  int(t['maxImpact']))
                    out.write("<tr><th scope='row' abbr='G5 Processor' class='specalt'>Referer: %s</th></tr>" % t['referer'])
                    out.write("<tr><th scope='row' abbr='G5 Processor' class='specalt'>ClientHosts: %s</th></tr>" % t['ClientHost'])
                    idlist = []
                    for j in t['MatchID']:
                        idlist.append(j['matchedID'])
                    out.write("<tr><th scope='row' abbr='G5 Processor' class='specalt'>Matched ID: %s</th></tr>" %  set(idlist))
                
            out.write("</table>")
            out.write("<br><br>")
            
               #out.write("</table>")
               #out.write("<br><br>")
        
        out.write("<hr size='10'><br><br>")
        out.write("<h2>Web Attack Impact:</h2>\n\n")
        
        for xlevel in ImpactLevel:
            out.write("<table id='mytable' cellspacing='0' width=800px style='word-break:break-all'><caption align='left'><h2>Impact %d</h2></caption>" % (int(level)+1))
            if xlevel:
                for impactdict in xlevel:
                    impactdict['URL'] = urllib.quote_plus(impactdict['URL'])
                    out.write("<tr><th scope='row' abbr='Model' class='spec' colspan=3>%s</th></tr>" %  impactdict['URL'] )
                    out.write("<tr><th scope='row' abbr='G5 Processor' class='specalt'>Referer:</th><th scope='row' abbr='G5 Processor' class='specalt' colspan=2>%s</th>" % impactdict['referer'])
                    out.write("<tr><th scope='row' abbr='G5 Processor' class='specalt'>ClientHosts:</th><th scope='row' abbr='G5 Processor' class='specalt' colspan=2>%s</th>" % impactdict['clienthost'])
                    
                    for f in impactdict['filterItem']:
                        out.write("<tr><th scope='row' abbr='G5 Processor' class='specalt'>Matched ID: %s</th><td class='alt'>%s</td><td class='alt'>Attack Name:%s</td>" % ( f['matchedID'],f['description'], f['tag']))
                out.write("</table>")
                out.write("<br><br>")
            else:
               out.write("</table>")
               out.write("<br><br>")
               
            level =level -1
 
        #out.write(html_footer)
        out.close()
    except IOError:
        print("Cannot open the file:", fname)
    return
    
def getMalIP(AttackResult):
    malip = []
    for names in AttackResult:
        for item in Attack[name]:
            if item['maxImpact'] > 4:
                for ip in item['ClientHost']:
                    malip.append(ip)
    return set(malip)

def getDictData(strdata):
    XmlDict =ast.literal_eval(strdata)
    return XmlDict

def main():
    print("Ready to Load Ids Singature file '%s'..." % xmlfilterfile)
    xmlobj =  xmlparse(xmlfilterfile)
    xmlrulelist = xml_rule_filter(xmlobj)
    print("Total Singatures are %d..." % len(xmlrulelist))
    
    matcherList = []
        
    linecount = len(open(logfile).readlines())     
    print(" Start to read and parse logs ! Total logs are %d..." % linecount)
    
    for line in open(logfile).xreadlines():
        JsonResult = getFields(line)
        urlp = getURLpath (JsonResult)

        if urlp and len(str(urlp)) >0 :
            result = matcher(urlp, xmlrulelist)
            if result :
                JsonResult['analysis'] = result
                matcherList.append(JsonResult)
    
    #print matcherList
            
    ImpactLevel = impact_analysis (matcherList, xmlrulelist)
    
    attackDict =attack_analysis (matcherList, xmlrulelist)
    XmlDict = getDictData(str(xmlrulelist))
    AttackResult =dispatchDataToResult(XmlDict,attackDict)
    malip = getMalIP(AttackResult)
    print malip
    
    '''
    print("============================================")
    for name in AttackResult:
        print ("%s Attack: %s \n" % (name, names[name]))
        for t in AttackResult[name]:
            if int(t['maxImpact']) > 4: 
                print ("attack:%d  %s" % (int(t['maxImpact']), t['URL']))
        
        print("============================================")
    generate_html_Impact(AttackResult, ImpactLevel)
    generate_text_file(AttackResult, ImpactLevel)
    '''

if __name__ == "__main__":
    main()