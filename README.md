# EventViewerPythonImplementation
The rapid speed by which technology has grown has also increased the spate of cybercrimes. Windows operating system is the most widely used OS, resulting in its users being on the receiving end of these cybercrimes. Such crimes brought about the need for cyber forensics. 

Evidence collection is a major part of the field of cyber forensics. Because the log files link certain occurrences to a specific point in time, the Windows event log is the most essential source of evidence during a digital forensic investigation of a Windows system. An investigator can use Windows Event Log analysis to create a timeline based on the logging data and found artifacts. The data that must be logged is determined by the audit features that are enabled, which implies that event logs can be disabled with administrative access. The Event Logs catch a lot of data from a forensic standpoint.

![image](https://user-images.githubusercontent.com/60477228/167592773-135ade6a-b175-48f2-97af-c442de006c76.png)

### PROGRAMMING LANGUAGE AND LIBRARIES USED:
Python Programming language was used to implement this project. The libraries used are as follows:
- Win32evtlog
- Pandas
- Os

### FUNCTIONALITIES:
- Allows the user to select whether they wish to see the application log, system log or security log or all three
- Displays the Logs as an html file
- The following data is shown in a tabular format:
  - Event Category
  - Time Generated
  - Source Name
  - Event ID
  - Event Type
  - Event Data

