"""
Exec Hawk — Burp Suite Extension
Burp -> Exec Hawk bridge for automated finding import
"""
from burp import IBurpExtender, ITab, IHttpListener
import json, urllib2

EXEC_HAWK_API = "http://localhost:8443/api/findings"

class ExecHawkBurp(IBurpExtender, ITab, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Exec Hawk Bridge")
        callbacks.registerHttpListener(self)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
            
        # Analyze responses for findings
        response = self._helpers.analyzeResponse(
            messageInfo.getResponse())
        
        statusCode = response.getStatusCode()
        headers = response.getHeaders()
        
        findings = []
        
        # Check for CORS misconfig
        for header in headers:
            if "access-control-allow-origin: *" in header.lower():
                findings.append({
                    "title": "CORS Wildcard",
                    "severity": "MEDIUM",
                    "type": "CORS"
                })
        
        # Check for info disclosure
        for header in headers:
            if "server:" in header.lower():
                findings.append({
                    "title": "Server Header Disclosure",
                    "severity": "LOW",
                    "type": "Info Disclosure"
                })
        
        # Send to Exec Hawk
        for f in findings:
            try:
                req = urllib2.Request(
                    EXEC_HAWK_API,
                    json.dumps(f),
                    {"Content-Type": "application/json"}
                )
                urllib2.urlopen(req)
            except:
                pass