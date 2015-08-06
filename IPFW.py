import os
import sys
import getpass
import datetime
import socket
import threading
import urllib2
import types
from stat import *
from threading import Thread
from time import sleep

history_LogLocation = "/Users/God/Library/Logs/IPFW_NewRules.txt"
debug_LogLocation = "/Users/God/Library/Logs/IPFW_debug.txt"
error_LogLocation = "/Users/God/Library/Logs/IPFW_error.txt"

def history_log(entry):
    logFile = open(history_LogLocation, "a")
    logFile.write(str(datetime.datetime.now()) + " " + entry + "\n")
    logFile.close()

def debug_log(entry):
    logFile = open(debug_LogLocation, "a")
    logFile.write(str(datetime.datetime.now()) + " " + entry + "\n")
    logFile.close()

def error_log(entry):
    logFile = open(error_LogLocation, "a")
    logFile.write(str(datetime.datetime.now()) + " " + entry + "\n")
    logFile.close()

def clearCache():
    global cachedRangeRules
    global cachedSingleRules
    global cachedRangeRulesNumber
    global cachedSingleRulesNumber
    global cachedOtherRules

    cachedRangeRules = []
    cachedSingleRules = []
    cachedRangeRulesNumber = 4000
    cachedSingleRulesNumber = 3000
    cachedOtherRules = []

def countryLookup(ip):
    global database

    ##Binary search through static database
    
    low = 0
    high = len(database)-1
    mid = high / 2
    
    while high >= low:
        if ip >= database[mid][0] and ip <= database[mid][1]:
            return database[mid][2]
        elif ip > database[mid][0]:
            low = mid + 1
        else:
            high = mid -1
        mid = (low + high) / 2

    ## Ask online service (Limit 1000 per day)
    try:
        ipLookup = urllib2.build_opener()
        ipLookup.addheaders = [('Users-agent', 'curl')]
        result = ipLookup.open("http://ipinfo.io/" + ip)
        result = result.read()
    
        start = result.find('"country": "')
        if start != -1:
            start += len('"country": "')
            stop = result.find('"', start)
            return result[start:stop]
    except:
        pass
        
    return 'Unknown'
    
def readCountryDatabase():
    global database
    database = []
    dataFile = open('GeoIPCountryWhois.csv', 'r')
    data = dataFile.read()
    lines = data.split('\r')
    for ranges in lines:
        database.append(ranges.split(','))
    dataFile.close()

class IPFW_Watcher:
    
    def doIt(self, manualIP):
        global cachedRangeRules
        global cachedSingleRules
        global cachedRangeRulesNumber
        global cachedSingleRulesNumber
        global cachedOtherRules
        
        if testing:
            debug_log("Cache Size: " + str(len(cachedRangeRules)) + str(len(cachedSingleRules)) ) 
        
        if testing:
            debug_log("Starting IPFW")
            
        ## Get existing Rules
        if len(cachedRangeRules) + len(cachedSingleRules) == 0:
            self.getCurRules()
            cachedOtherRules = self.otherRules
            cachedSingleRules = self.alreadyBlockedSingles
            cachedRangeRules = self.alreadyBlockedRanges
            cachedRangeRulesNumber = self.lastRangeRuleNumber
            cachedSingleRulesNumber = self.lastSingleRuleNumber
        else:
            if testing:
                debug_log("Using cached rules.")
            self.alreadyBlockedRanges = cachedRangeRules
            self.alreadyBlockedSingles = cachedSingleRules
            self.lastRangeRuleNumber = cachedRangeRulesNumber
            self.lastSingleRuleNumber = cachedSingleRulesNumber
            self.otherRule = cachedOtherRules

        if testing:
            debug_log("Other blocks that are ignored: " + str(self.otherRules))
            debug_log("Already Blocked Singles: \n" + '\n'.join(self.alreadyBlockedSingles))
            debug_log("Already Blocked Ranges: \n" + '\n'.join(self.alreadyBlockedRanges))
            
        if manualIP != False:
            valid = self.checkIfIP(manualIP)
            if valid:
                self.addRule(manualIP, True)
                clearCache()
        else:
            
            ## Reading logs for offenders
            if testing:
                debug_log("Reading system log for offences.")
            self.readSystemLog()
            if testing:
                debug_log("Reading Apache log for offences.")
            self.readApacheLog()
            
            self.newOffenders.sort()
            
            ## Filter safe hosts
            for entry in range(len(self.newOffenders)-1, -1, -1):
                if self.newOffenders[entry][0] in self.excludeSafeHosts:
                    self.newOffenders.pop(entry)
            if testing:
                for offender in self.newOffenders:
                    debug_log("New offender: " + offender[0] + " has " + str(offender[1]) + " offences.")
            
            ## Filter out already blocked single ips
            for index in range(len(self.newOffenders)-1, -1, -1):
                if self.newOffenders[index][0] in self.alreadyBlockedSingles:
                    self.newOffenders.pop(index)
            
            ## Filter out already blocked single ips by range blocks
            for index in range(len(self.newOffenders)-1, -1, -1):
                for sets in self.alreadyBlockedRanges:
                    if self.newOffenders[index][0].startswith(sets):
                        self.newOffenders.pop(index)
            
            ## Check if the remaining offenders have hit the limit
            for index in range(len(self.newOffenders)-1, -1, -1):
                if self.newOffenders[index][1] < 3:
                    self.newOffenders.pop(index)
                else:
                    self.newOffenders[index] = self.newOffenders[index][0]
            
            ## Check for new range offenders
            self.getRangeOffender()
            if testing:
                debug_log("New range offenders: \n" + '\n'.join(self.newRangeOffenders))
                            
            if len(self.newRangeOffenders) > 0:
                clearCache()
                self.lastSingleRuleNumber = 3000
                self.lastRangeRuleNumber = 4000
                command = ''
                if self.adminPass:
                    command += "echo " + self.adminPass + " | sudo -S -p \"\" "
                command += "ipfw -f flush"
                add = os.popen(command)
                result = add.read()
                sleep(1)
                
                if len(self.alreadyBlockedRanges) > 0:
                    if testing:
                        debug_log("Already Blocked Ranges Length:" + str(len(self.alreadyBlockedRanges)))
                    self.addRangeRule(self.alreadyBlockedRanges, False)
                if len(self.newRangeOffenders) > 0:
                    if testing:
                        debug_log("New Block Ranges Length:" + str(len(self.newRangeOffenders)))
                    self.addRangeRule(self.newRangeOffenders)
                if len(self.alreadyBlockedSingles) > 0:
                    if testing:
                        debug_log("Already Blocked Singles Length:" + str(len(self.alreadyBlockedSingles)))
                    self.addRule(self.alreadyBlockedSingles, False)
                    
            if testing:
                debug_log("After filtering: ")
                for offender in self.newOffenders:
                    debug_log("New offender: " + offender)
            
            if len(self.newOffenders) > 0:
                self.addRule(self.newOffenders)
                clearCache()
            
            if testing:
                #run = False
                debug_log("Finished.")
            return 0

    def getRangeOffender(self):
        if len(self.alreadyBlockedSingles) > 0:
            for entry in range(len(self.alreadyBlockedSingles)-1, -1, -1):
                found = False
                ipStartingSets = self.alreadyBlockedSingles[entry][:self.alreadyBlockedSingles[entry].rfind('.')+1]
                if ipStartingSets not in self.alreadyBlockedRanges:
                    if len(self.newRangeOffenders) > 0:
                        high = len(self.newRangeOffenders)-1
                        low = 0
                        if self.newRangeOffenders[low][0] == ipStartingSets:
                            self.newRangeOffenders[low][1] += 1
                            self.newRangeOffenders[low][2].append(entry)
                            found = True
                        elif self.newRangeOffenders[high][0] == ipStartingSets:
                            self.newRangeOffenders[high][1] += 1
                            self.newRangeOffenders[high][2].append(entry)
                            found = True
                        if not found:
                            mid = high / 2
                            while low <= high:
                                if self.newRangeOffenders[mid][0] == ipStartingSets:
                                    self.newRangeOffenders[mid][1] += 1
                                    self.newRangeOffenders[mid][2].append(entry)
                                    found = True
                                    break
                                if ipStartingSets > self.newRangeOffenders[mid][0]:
                                    low = mid + 1
                                elif ipStartingSets < self.newRangeOffenders[mid][0]:
                                    high = mid - 1
                                elif low == high:
                                    break
                                mid = (low + high) / 2
                else:
                    found = True
                if not found:
                    self.newRangeOffenders.append([ ipStartingSets, 1, [entry], [] ])
                self.newRangeOffenders.sort()
                
        if len(self.newOffenders) > 0:
            if testing:
                debug_log("newOffenders: " + str(self.newOffenders))
            for entry in range(len(self.newOffenders)-1, -1, -1):
                if testing:
                    debug_log("Testing for range for: " + str(self.newOffenders[entry]))
                found = False
                ipStartingSets = self.newOffenders[entry][:self.newOffenders[entry].rfind('.')+1]
                if ipStartingSets not in self.alreadyBlockedRanges:
                    if len(self.newRangeOffenders) > 0:
                        high = len(self.newRangeOffenders)-1
                        low = 0
                        if self.newRangeOffenders[low][0] == ipStartingSets:
                            self.newRangeOffenders[low][1] += 1
                            self.newRangeOffenders[low][3].append(entry)
                            found = True
                        elif self.newRangeOffenders[high][0] == ipStartingSets:
                            self.newRangeOffenders[high][1] += 1
                            self.newRangeOffenders[high][3].append(entry)
                            found = True
                        if not found:
                            mid = high / 2
                            while low <= high:
                                if self.newRangeOffenders[mid][0] == ipStartingSets:
                                    self.newRangeOffenders[mid][1] += 1
                                    self.newRangeOffenders[mid][3].append(entry)
                                    found = True
                                    break
                                if ipStartingSets > self.newRangeOffenders[mid][0]:
                                    low = mid + 1
                                elif ipStartingSets < self.newRangeOffenders[mid][0]:
                                    high = mid - 1
                                elif low == high:
                                    break
                                mid = (low + high) / 2
                else:
                    found = True
                if not found:
                    self.newRangeOffenders.append([ ipStartingSets, 1, [], [ entry ] ])
                self.newRangeOffenders.sort()
                
        if len(self.newRangeOffenders) > 0:
            for entry in range(len(self.newRangeOffenders)-1, -1, -1):
                if self.newRangeOffenders[entry][1] < 3:
                    self.newRangeOffenders.pop(entry)
                else:
                    if len(self.newRangeOffenders[entry][2]) > 0:
                        for index in self.newRangeOffenders[entry][2]:
                            if testing:
                                debug_log("Removing " + self.alreadyBlockedSingles[index] + " per new range rule.")
                            self.alreadyBlockedSingles.pop(index)
                    if len(self.newRangeOffenders[entry][3]) > 0:
                        for index in self.newRangeOffenders[entry][3]:
                            if testing:
                                debug_log("Removing " + self.newOffenders[index] + " per new range rule.")
                            self.newOffenders.pop(index)
                    self.newRangeOffenders[entry] = self.newRangeOffenders[entry][0]
        if len(self.newRangeOffenders) > 0:
            debug_log("New range offenders: " + str(self.newRangeOffenders))
    
    def addRangeRule(self, ipRange, log=True):
        if testing:
            debug_log("Ranges to add: " + str(ipRange))
        if type(ipRange) is list:
            command = ''
            if self.adminPass:
                command += "echo " + self.adminPass + " | sudo -S -p \"\" "
            for sequence in ipRange:
                if len(sequence) > 1:
                    self.lastRangeRuleNumber += 1
                    command += "ipfw add " + str(self.lastRangeRuleNumber) + " deny ip from " + sequence + "0/24 to me | "
                    if log:
                        log = "Adding: " + str(self.lastRangeRuleNumber) + " -> " + sequence + "0/24"
                        history_log(log)
                        if testing:
                            debug_log(log)
                    if self.adminPass:
                        command += "sudo "
            command = command[:command.rfind('|')-1]
            add = os.popen(command)
        else:
            self.lastRangeRuleNumber += 1
            command = ''
            if self.adminPass:
                command += "echo " + self.adminPass + " | sudo -S -p \"\" "
            command += "ipfw add " + str(self.lastRangeRuleNumber) + " deny ip from " + ipRange + "0/24 to me"
            add = os.popen(command)
            if log:
                log = "Adding: " + str(self.lastRangeRuleNumber) + " -> " + ipRange + "0/24"
                history_log(log)
                if testing:
                    debug_log(log)
    
    def getCurRules(self):
        command = ''
        if self.adminPass:
            command += "echo " + self.adminPass + " | sudo -S -p \"\" "
        command += "ipfw list"
        curRules = os.popen(command)
        self.rules = curRules.read()
        
        self.rules = self.rules.split("\n")
        for entry1 in range(0, len(self.rules)):
            self.rules[entry1] = self.rules[entry1].split(" ")
        self.rules.pop(-1)
        
        ## Remove rules outside the range, may need to modify these in the future if going outside the range of 1000 entries...
        for entry2 in range(len(self.rules)-1, -1, -1):
            curRuleNum = int(self.rules[entry2][0])
            if curRuleNum < 3000 or curRuleNum >= 5000:
                self.otherRules.append(self.rules[entry2])
                self.rules.pop(entry2)
                
        for entry6 in range(len(self.otherRules)-1, -1, -1):
            if self.otherRules[entry6] == ['65535', 'allow', 'ip', 'from', 'any', 'to', 'any']:
                self.otherRules.pop(entry6)
                break
            
        ## ['04000', 'deny', 'ip', 'from', '198.48.92.0/24', 'to', 'me']
        for entry3 in range(len(self.rules)-1, -1, -1):
            curRuleNum = int(self.rules[entry3][0])
            if curRuleNum >= 4000 and curRuleNum < 5000 and self.rules[entry3][1:4] == [ 'deny', 'ip', 'from' ] and self.rules[entry3][5:7] == [ 'to', 'me' ]:
                if int(self.rules[entry3][0]) > self.lastRangeRuleNumber:
                    self.lastRangeRuleNumber = int(self.rules[entry3][0])
                self.alreadyBlockedRanges.append(self.rules[entry3][4][:self.rules[entry3][4].rfind('.')+1])
                self.alreadyBlockedRanges.sort()
                self.rules.pop(entry3)
            
        ## ['03000', 'deny', 'ip', 'from', '198.48.92.104', 'to', 'me']
        for entry4 in range(len(self.rules)-1, -1, -1):
            curRuleNum = int(self.rules[entry4][0])
            if self.rules[entry4][1:4] == [ 'deny', 'ip', 'from' ] and self.rules[entry4][5:7] == [ 'to', 'me' ]:
                if int(self.rules[entry4][0]) > self.lastSingleRuleNumber:
                    self.lastSingleRuleNumber = int(self.rules[entry4][0])
                self.alreadyBlockedSingles.append(self.rules[entry4][4])
                self.alreadyBlockedSingles.sort()
    
    def addOffence(self, ip):
        if ip in self.alreadyBlockedSingles:
            return False
        for ipRange in self.alreadyBlockedRanges:
            if ip.startswith(ipRange):
                return False
        found = False
        if len(self.newOffenders) > 0:
            high = len(self.newOffenders)-1
            low = 0
            if self.newOffenders[low][0] == ip:
                self.newOffenders[low][1] += 1
                found = True
            elif self.newOffenders[high][0] == ip:
                self.newOffenders[high][1] += 1
                found = True
            if not found:
                mid = high / 2
                while low <= high:
                    if self.newOffenders[mid][0] == ip:
                        self.newOffenders[mid][1] += 1
                        found = True
                        break
                    if ip > self.newOffenders[mid][0]:
                        low = mid + 1
                    elif ip < self.newOffenders[mid][0]:
                        high = mid - 1
                    elif low == high:
                        break
                    mid = (low + high) / 2
        if not found:
            self.newOffenders.append([ ip, 1 ])
        self.newOffenders.sort()

    def addRule(self, offender, log = True):
        if testing:
            debug_log("Single IP Rule:" + str(offender))
        if type(offender) is list:
            command = ''
            if self.adminPass:
                command += "echo " + self.adminPass + " | sudo -S -p \"\" "
            for sequence in offender:
                self.lastSingleRuleNumber += 1
                command += "ipfw add " + str(self.lastSingleRuleNumber) + " deny ip from " + sequence + " to me | "
                if log:
                    log = "Adding: " + str(self.lastSingleRuleNumber) + " -> " + sequence + " from " + countryLookup(sequence) + '.'
                    history_log(log)
                    if testing:
                        debug_log(log)
                if self.adminPass:
                    command += "sudo "
            command = command[:command.rfind('|')-1]
            add = os.popen(command)
        else:
            self.lastSingleRuleNumber += 1
            command = ''
            if self.adminPass:
                command += "echo " + self.adminPass + " | sudo -S -p \"\" "
            command += "ipfw add " + str(self.lastSingleRuleNumber) + " deny ip from " + offender + " to me"
            add = os.popen(command)
            result = add.read()
            result = result.replace('\n', '')
            if log:
                log = "Adding: " + str(self.lastSingleRuleNumber) + " -> " + offender + " from " + countryLookup(offender) + '.'
                history_log(log)
                
    def checkIfIP(self, offender):
        if testing:
            debug_log("Testing if ip address: " + offender)
        valid = True
        tempOffender = offender.split('.')
        if len(tempOffender) == 4:
            for sets in tempOffender:
                if not sets.isdigit():
                    valid = False
        else:
            valid = False
            
        if not valid:
            try:
                valid = socket.gethostbyname(offender)
            except:
                error_log("Failed to decode offender " + offender + " to an ip address!")
                valid = False
        else:
            valid = offender
        if testing:
            debug_log("Offender ip => " + valid )
        return valid
    
    def readSystemLog(self):
        if os.path.isfile(self.systemLog):
            global cachedSystemLogTimeStamp
            lastChanged = os.stat(self.systemLog).st_mtime
            if testing:
                debug_log("System Log File Cached Stamp: " + str(cachedSystemLogTimeStamp))
                debug_log("System Log File Time Stamp: " + str(lastChanged))
            if cachedSystemLogTimeStamp != lastChanged:
                cachedSystemLogTimeStamp = lastChanged
                try:
                    systemLog = open(self.systemLog, "r")
                
                    rawLines = systemLog.read()
                    rawLines = rawLines.split("\n")
                    
                    systemLog.close()
                except:
                    error_log("Could not find system.log, possibly from the system starting a new one, if repeats please check your config.")
                    return False
                
                lines = []
                for line in range(0, len(rawLines)):
                    if "ssh" in rawLines[line] and rawLines[line+1] == "--- last message repeated 2 times ---":
                        lines.append(rawLines[line])
                        lines.append(rawLines[line])
                    elif "ssh" in rawLines[line]:
                        lines.append(rawLines[line])
                
                for line in range(0, len(lines)):
                    lines[line] = lines[line].split(" ")
                    try:
                        start = lines[line].index("Invalid")
                        end = start + 2
                        ## ['Apr', '21', '11:28:08', 'MacServer.local', 'sshd[77485]:', 'Invalid', 'user', 'recruit', 'from', '222.236.44.115']
                        if lines[line][start : end] == [ 'Invalid', 'user' ]:
                            ip = self.checkIfIP(lines[line][-1])
                            if ip != False:
                                self.addOffence(ip)
                    except:
                        pass
                    
                    try:
                        start = lines[line].index("error:")
                        end = start + 4
                        ## ['Apr', '21', '00:32:29', 'MacServer.local', 'sshd[69026]:', 'error:', 'PAM:', 'authentication', 'error', 'for', 'root', 'from', '43.255.191.145', 'via', '192.168.7.11']
                        if lines[line][start : end] == [ 'error:', 'PAM:', 'authentication', 'error' ]:
                            if testing:
                                debug_log(str(lines[line][start : end]) + lines[line][-3])
                            ip = self.checkIfIP(lines[line][-3])
                            if ip != False:
                                self.addOffence(ip)
                    except:
                        pass
            elif testing:
                debug_log("System log has not been modified, skipping.")
        else:
            error_log("Error finding " + self.systemLog + ", please check your configuration.")
    
    def readApacheLog(self):
        if os.path.isfile(self.apacheLog):
            global cachedApacheLogTimeStamp
            lastChanged = os.stat(self.apacheLog).st_mtime
            if testing:
                debug_log("Apache File Cached Stamp: " + str(cachedApacheLogTimeStamp))
                debug_log("Apache File Time Stamp: " + str(lastChanged))
            if cachedApacheLogTimeStamp != lastChanged:
                cachedApacheLogTimeStamp = lastChanged
                try:
                    systemLog = open(self.apacheLog, "r")
                
                    rawLines = systemLog.read()
                    rawLines = rawLines.split("\n")
                    
                    systemLog.close()
                except:
                    error_log("Could not find apache_error.log, possibly from the system starting a new one, if repeats please check your config.")
                    return False
                    
                lines = []
                for line in range(0, len(rawLines)):
                    if "[error]" in rawLines[line]:
                        lines.append(rawLines[line])
                
                for line in range(0, len(lines)):
                    lines[line] = lines[line].replace('[','')
                    lines[line] = lines[line].replace(']','')
                    lines[line] = lines[line].split(" ")
                    ## ['Thu', 'Apr', '02', '17:18:51', '2015', 'error', 'client', '59.125.230.30', 'File', 'does', 'not', 'exist:', '/Applications/MAMP/htdocs/phph']
                    start = lines[line].index('error')
                    if lines[line][start:start+2] == [ 'error', 'client' ]:
                        ip = self.checkIfIP(lines[line][start+2])
                        if ip != False:
                                self.addOffence(ip)
            elif testing:
                debug_log("Apache log has not been modified, skipping.")
        else:
            error_log("Error finding " + self.apacheLog + ", please check your configuration.")

    def __init__(self, adminPass=False, manualIP = False):
        try:
            myself = socket.gethostbyname('h711.webhop.me')
        except:
            myself = '76.95.128.199'
            
        self.systemLog = "/private/var/log/system.log"
        self.apacheLog = "/Applications/MAMP/logs/apache_error.log"
        self.adminPass = adminPass
        self.rules = []
        self.newOffenders = []
        self.alreadyBlockedSingles = []
        self.excludeSafeHosts = ['127.0.0.1', myself ]
        self.alreadyBlockedRanges = []
        self.newRangeOffenders = []
        self.blockOn = 5
        self.lastSingleRuleNumber = 3000
        self.lastRangeRuleNumber = 4000
        self.otherRules = []
        
        self.doIt(manualIP)
        
def firewall(adminPass=False):
    while run:
        root = IPFW_Watcher(adminPass)
        sleep(1)
        
def cleanForTest(adminPass):
    if flush:
        command = ''
        if adminPass:
            command += "echo " + adminPass + " | sudo -S -p \"\" "
        command += "ipfw -f flush"
        add = os.popen(command)
    
    try:
        os.remove(debug_LogLocation)
    except:
        pass
    try:
        os.remove(history_LogLocation)
    except:
        pass
    try:
        os.remove(error_LogLocation)
    except:
        pass
        
if __name__ == '__main__':
    
    testing = False
    flush = False
    
    global cachedSystemLogTimeStamp
    cachedSystemLogTimeStamp = 0
    
    global cachedApacheLogTimeStamp
    cachedApacheLogTimeStamp = 0
    
    global cachedOtherRules
    cachedOtherRules = []

    global cachedSingleRules
    cachedSingleRules = []
    
    global cachedRangeRules
    cachedRangeRules = []
    
    global cachedRangeRulesNumber
    cachedRangeRulesNumber = 4000
    global cachedSingleRulesNumber
    cachedSingleRulesNumber = 3000
    
    global run
    run = True
    
    readCountryDatabase()
    
    adminPass = ''
    if getpass.getuser() != 'root':
        adminPass = getpass.getpass()
    else:
        adminPass = False
    if testing:
        cleanForTest(adminPass)
    firewallHandler = threading.Thread(target = firewall, args=(adminPass,))
    firewallHandler.start()
    print "Firewall running..."
    while run:
        print "1 - Clear cache"
        print "2 - Manually add IP"
        try:
            choice = raw_input("Choice: ")
        except KeyboardInterrupt:
            run = False
            sleep(3)
        except:
            pass
            choice = 'z'
        if choice.isdigit():
            choice = int(choice)
            if choice == 1:
                clearCache()
            elif choice == 2:
                ip = raw_input("Enter in IP: ")
                IPFW_Watcher(adminPass, ip)
            else:
                print "Invalid choice, try again."
        