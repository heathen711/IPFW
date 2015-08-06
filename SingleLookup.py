import urllib2
import socket

def readCountryDatabase():
    global database
    database = []
    dataFile = open('GeoIPCountryWhois.csv', 'r')
    data = dataFile.read()
    lines = data.split('\r')
    for ranges in lines:
        database.append(ranges.split(','))
    dataFile.close()
    
def countryLookup(ip):
    global database

    ##Binary search through static database
    if True:
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
    
    
readCountryDatabase()
while True:
    userInput = raw_input("Enter in ip address: ")
    if userInput.count('.') == 3:
        print countryLookup(userInput) + '\n'