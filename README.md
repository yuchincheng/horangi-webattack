# horangi-webattack
Web log analyzer for detecting web attacks by signature matching

[!(https://github.com/yuchincheng/horangi-webattack/blob/master/Flowcharts.png)]((https://github.com/yuchincheng/horangi-webattack/blob/master/Flowcharts.png))

# Description #
After parsing web logs into (fields: Value) and filtering out the urls with the extensions ('gif jpg jpeg png bmp ico svg svgz ttf otf eot woff woff2 class css js xml robots.txt webp'), signatures matching is used to
detect web attacks and its severity.  The attack categories include {
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
}.

The severity (called 'Impact' in the code) is from 1-7. 7 is the highest level.  Using signatures matching will cause high false-alarm rate. Therefore, in order to recoginize the real attack URL string, we combine the following factors for the analysis:

- maxImpact: The maximum impact of matched signatures. The URL will match several signatures. Get the maximum of impact of these signatures will be recognize how dangerous it is.
- count of matched signature: The more signatures matched, the more characteristics recognized.
- referer: Unusual web access did come with non-referer or suspicious referer.
- (NOT COMPLETE) HTTP status code: Status code can analyze whether the website is "infected" or "tempting attempts" 

In addition to pattern matching, we also ship log data to Elasticseach for bottom frequency analysis, POST analysis and malicious IP tracing. Because signature matching only can explore parts of malicous web url, bottom frequency analysis could be a good way to get more information. Also tracing all of the requests performing by malicious IP triggers more suspicous attacks.

idsSig.xml is used to maintain attack signatures. It was orginally downloaded from https://github.com/PHPIDS/PHPIDS/blob/master/lib/IDS/default_filter.xml.  In order to decrease the false alarm, the regular expressions were modified and web shell detection signatures were included by this Project.

The analysis results are stored in JSON format, and output in HTML and TXT format in current version. JSON format is easily to index in elsticsearch. That's could be developed in XML and DB format in the future.

TODO:
I think pattern patching could do general attack strings detection. For deeper analysis,  modeling the user behavior, frequency and user query patterns is good method for web attack detections.


# File path: #

change to your log file path and attack signature path
```
logfile = "exam1.log" #log file to be parsed and matched
xmlfilterfile = "idsSig.xml" # filter rules to detect web attacks
```

# Execution: #
```
python detector.py
```

# TXT format Output: 2017-02-06_analysis_impac.txt #
```

URL = %2Fwp-content%2Fuploads%2F2014%2F06%2Fwp-index.php%3F450699%26babaraba%3Dvb%26php4%26root%26upl%26wphp4%26abdullkarem%26wp%26module%26php%26php5%26wphp5
maxImpact = 6  #Maximum Impact of matched ID
Referer = ['-'] #no referer
ClientHosts: ['67.213.222.143']  # WHo perfom this request
Matched ID: set(['80', '79']) #Matched ID
```

# HTML format Output: 2017-02-06_analysis_impac.html #
```

```
