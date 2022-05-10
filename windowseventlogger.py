import win32evtlog
import pandas as pd
import subprocess
import os
#* We use bootstrap css to make our table layout better:
header = '''<head>
  <meta charset="utf-8">
  <title>Windows Event Log Viewer</title>
  <!--bootstrap-->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.1/dist/css/bootstrap.min.css" integrity="sha384-zCbKRCUGaJDkqS1kPbPd7TveP5iyJE0EjAuZQTgFLD2ylzuqKfdKlfG/eSrtxUkn" crossorigin="anonymous">
  <!--Fonts-->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link rel="stylesheet" href="/static/css/styles.css">

  <style>
    table { padding: 300px; }
</style>
</head>
<body>
  <h1>Windows Event Log Viewer</h1>
'''
header1 = '''<head>
  <meta charset="utf-8">
  <title>Windows Event Log Viewer</title>
  <!--bootstrap-->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.1/dist/css/bootstrap.min.css" integrity="sha384-zCbKRCUGaJDkqS1kPbPd7TveP5iyJE0EjAuZQTgFLD2ylzuqKfdKlfG/eSrtxUkn" crossorigin="anonymous">
  <!--Fonts-->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link rel="stylesheet" href="/static/css/styles.css">

  <style>
    table { padding: 300px; }
</style>
</head>
<body>
  <h1>System Event Log Viewer</h1>
'''
header2 = '''<head>
  <meta charset="utf-8">
  <title>Windows Event Log Viewer</title>
  <!--bootstrap-->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.1/dist/css/bootstrap.min.css" integrity="sha384-zCbKRCUGaJDkqS1kPbPd7TveP5iyJE0EjAuZQTgFLD2ylzuqKfdKlfG/eSrtxUkn" crossorigin="anonymous">
  <!--Fonts-->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link rel="stylesheet" href="/static/css/styles.css">

  <style>
    table { padding: 300px; }
</style>
</head>
<body>
  <h1>Application Event Log Viewer</h1>
'''
header3 = '''<head>
  <meta charset="utf-8">
  <title>Windows Event Log Viewer</title>
  <!--bootstrap-->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.1/dist/css/bootstrap.min.css" integrity="sha384-zCbKRCUGaJDkqS1kPbPd7TveP5iyJE0EjAuZQTgFLD2ylzuqKfdKlfG/eSrtxUkn" crossorigin="anonymous">
  <!--Fonts-->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link rel="stylesheet" href="/static/css/styles.css">

  <style>
    table { padding: 300px; }
</style>
</head>
<body>
  <h1>Security Event Log Viewer</h1>
'''


#* Func is concerned with making a dataframe of the data that we have collected with the help of win32evtlog
def makeDataFrames(events):
    eventslst = []
        
    for i in range(len(events)):
        eventslst.append([])
        eventslst[i].append(str(events[i].EventCategory))
        eventslst[i].append(str(events[i].TimeGenerated))
        eventslst[i].append(str(events[i].SourceName))
        eventslst[i].append(str(events[i].EventID))
        eventslst[i].append(str(events[i].EventType))
        data = events[i].StringInserts
        if data:
            msgData = ""
            for msg in data:
                msgData+=msg
            eventslst[i].append(msgData)
            
    
    column_names = ["Event Category:","Time Generated:","Source Name:","Event ID:","Event Type:","Event Data:"]
    df = pd.DataFrame(eventslst,columns = column_names)  
    return df

#* Func to return the event log file data as a list of strings
def initWindowsEVT(n):
    #* 'Localhost' is the name of the target computer
    server = 'localhost' 
    logtypesy = 'System' 
    logtypea = 'Application'
    logtypese = 'Security'

    #* This is a reading flag and shows that we want to read the data in either backwards order or sequential order.
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ

    #* Here, this is the handle that opens the event log. The return handle will reference whatever log type we wish to see, and that
    #* is put as a paremeter. It accesses data from the registry.
    handSystem = win32evtlog.OpenEventLog(server,logtypesy)
    handApplication = win32evtlog.OpenEventLog(server,logtypea)
    handSecurity = win32evtlog.OpenEventLog(server,logtypese)

    #* This reads the event log that we opened in the previous lines of code. 0 is just the output buffer size.
    eventsSystem = win32evtlog.ReadEventLog(handSystem, flags,0)
    eventsApplication = win32evtlog.ReadEventLog(handApplication, flags,0)
    eventsSecurity = win32evtlog.ReadEventLog(handSecurity, flags,0)
    if n == 1:
        return eventsSystem
    elif n == 2:
        return eventsApplication
    else:
        return eventsSecurity

#* Func to display all windows event log files in 3 seperate HTML Files
def initWindowsEVTALL():
    server = 'localhost' 
    logtypesy = 'System' 
    logtypea = 'Application'
    logtypese = 'Security'

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ

    handSystem = win32evtlog.OpenEventLog(server,logtypesy)
    handApplication = win32evtlog.OpenEventLog(server,logtypea)
    handSecurity = win32evtlog.OpenEventLog(server,logtypese)

    eventsSystem = win32evtlog.ReadEventLog(handSystem, flags,0)
    eventsApplication = win32evtlog.ReadEventLog(handApplication, flags,0)
    eventsSecurity = win32evtlog.ReadEventLog(handSecurity, flags,0)

    dfs = []

    systemdf = makeDataFrames(eventsSystem)
    applicationdf = makeDataFrames(eventsApplication)
    securitydf = makeDataFrames(eventsSecurity)
    dfs.append(systemdf)
    dfs.append(applicationdf)
    dfs.append(securitydf)
    
    return dfs
    

#* Our main driver program
def driverProgram():
    
    print("")
    print("--------------------------------------------------------")
    print("Welcome to Windows Event Viewer implemented using Python")
    print("--------------------------------------------------------")
    print("\n\tDone by:")
    print("\t\tAkaash Nidhiss 2K19/IT/008")
    print("\t\tAnasuya Mithra 2K19/IT/018\n")

    n = int(input("Please enter your choice on what type of event log you wish to see: Type in (1) for System Log, (2) for Application Log, (3) for Security Log and (4) for all the EVT Log Files:"))
    
    if n == 4:
        dfs = []
        dfs = initWindowsEVTALL()
        htmls = []

        for df in dfs:
            htmls.append(df.to_html())
        
        #* Making System HTML File
        text_file = open("index1.html", "w")
        text_file.write(header1)
        system = htmls[0]
        text_file.write(system)
        text_file.close()
        #* Making Application HTML File
        text_file = open("index2.html", "w")
        text_file.write(header2)
        application = htmls[1]
        text_file.write(application)
        text_file.close()
        #* Making Security HTML File
        text_file = open("index3.html", "w")
        text_file.write(header3)
        security = htmls[2]
        text_file.write(security)
        text_file.close()

        #* Here we call a subprocess to run our .bat file which opens our index.html files on the default browser
        subprocess.call([r'D:\UniversityProjectFolders\ThirdYearCFProject2\finalcfproject\openALLHTML.bat'])
        
    else:
        events = initWindowsEVT(n)
        df = makeDataFrames(events)
        #* Here we render the dataframe as html
        html = df.to_html()

        #* And then write html to file
        text_file = open("index.html", "w")
        text_file.write(header)
        text_file.write(html)
        text_file.close()

        #* Here we call a subprocess to run our .bat file which opens our index.html file on the default browser
        subprocess.call([r'D:\UniversityProjectFolders\ThirdYearCFProject2\finalcfproject\openHTML.bat'])
    

    



driverProgram()


