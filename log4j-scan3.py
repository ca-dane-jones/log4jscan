from __future__ import print_function
"""
[summary]
"""
import argparse
import hashlib
import datetime
import os
import datetime
import time
import subprocess
import stat
import zipfile
import shutil
import csv
import socket
import json
from zipfile import ZipFile
from datetime import date

version="3.1.1"
parser = argparse.ArgumentParser(description='Scans for and identifies the version of any JndiLookup.class files on attached filesystems.')
starttime=time.time()
scandate=str(date.today().year) + "-" + str(date.today().month) + "-" + str(date.today().day)
hostname=socket.getfqdn()
outputdir=""
extractdir=""
hnfdir=""
hnfpackagename=""
logfile=""
resultscsvfile=""
excludes=[]
args=[]
drives=[]
filecount=0
jarcount=0
jndiclasscount=0
csvrowcount=0
hnfcount=0

# Dictionary of known JndiLookup.class hashes to version values
# NOTE: Log4j JndiLookup.class did not appear in the log4j-core jars until 2.0 Beta 9
# 		and later.
versionmd5s = dict(
    {
        "662118846c452c4973eca1057859ad61": "2.0 Beta 9 - 2.0 RC1",
        "1daf21d95a208cfce994704824f46fae": "2.0 RC2",
        "62c82ad7c1ec273a683de928c93abbe9": "2.0.0",
        "2365c12b4a7c5fa5d7903dd90ca9e463": "2.0.1",
        "5c727238e74ffac28315c36df27ef7cc": "2.0.2",
        "8ededbb1646c1a4dd6cdb93d9a01f43c": "2.1.0 - 2.3.0",
        "8d28b7bdf91ee2f18224ca0c17ee9442": "2.3.1",
        "381eff450ecfff94026b92b0ddf05d31": "2.3.2",
        "da195a29e34e02e9e4c6663ce0b8f243": "2.4.0 - 2.5.0",
        "766bf6b755adee673838fdf968c15079": "2.6.0 - 2.6.2",
        "4618c4bea52a4e2e2693b7d91b019c71": "2.7.0",
        "fe963defc63d2df86d3d4e2f160939ab": "2.8.0 - 2.8.1",
        "641fd7ae76e95b35f02c55ffbf430e6b": "2.8.2",
        "88568653545359ace753f19a72b18208": "2.9.0 - 2.11.2",
        "4cb3a0271f77c02fd2de3144a729ab70": "2.12.0 - 2.12.1 ",
        "ddf868bc458a7732ec3e63673a331d04": "2.12.2",
        "f54d88847ebcf0e2b7c7bfe03b91b69a": "2.12.3 - 2.12.4",
        "7b2cf8f2e9d85014884add490878a600": "2.13.0 - 2.14.0",
        "737b430fac6caef7c485c9c47f0f9104": "2.14.1 - 2.16.0",
        "719b34335646f58d0ca2a9b5cc7712a3": "2.17.0 - 2.17.1"
    })

def initArgParser():
    """
    Initializes the command line argument parser
    """
    parser.add_argument('--loglevel','-l',
                        choices=[0,1,2],
                        type=int,
                        default=1,
                        help='integer value from 0-2.  Default is 1.  [0] Disable logging, [1] Standard Logging, [2] Debug Logging')
    parser.add_argument('--silent','-s', 
                        action='store_true',
                        help='if true, status messages will not be displayed on screen.  Default is false.')
    parser.add_argument('--outputdir','-o',
                        type=str,
                        default="",
                        help='specifies the output directory for logs, reporting, and temporary working files.  This directory will be created if it does not exist.  Default is dependent on detected file system.  /tmp/log4jscan for Posix filesystems or c:\windows\\temp\log4jscan for NT file systems.')
    parser.add_argument('--version','-v',
                        action='store_true',
                        help='displays version information')
    #TODO: Move type definitions for -o to custom FileDirType type based on argparse.FileType
    
def log(lvl, message):
    global args
    global logfile
    ct = str(datetime.datetime.now())
    if args.loglevel >= lvl:
        if not args.silent:
            print(ct + " :: " + message)
        print(message, file=open(logfile, 'a+'))

def loginfo(message):
    global args
    if args.loglevel >= 1:
        message="[INFO] " + message
        log(1, message)
    
def logdebug(message):
    global args
    if args.loglevel >= 2:
        message="[DEBUG] " + message
        log(2,message)
    
def logerror(message):
    message="[ERROR] " + message
    log(0,message)

def setOutputDir(path):
    global extractdir
    global logfile
    global resultscsvfile
    global hnfdir
    global hostname
    global hnfpackagename
    
    #TODO: Move file cleanup to seperate functions and wrap in a cleanup function
    #TODO: Move to inidividual file / directory creation functions
    
    if path.endswith('/') or path.endswith('\\'):                                           
        path = path[:-1]
    path = path.strip() + "/log4jscan"
    extractdir = path + "/extract"
    logfile = path + "/" + hostname + "-scan" + ".log"
    hnfdir = path + "/hnf"
    resultscsvfile = path + "/" + hostname + "-scanresults.csv"
    hnfpackagename = path + "/" + hostname + "-hnfpackage.zip"
    
    if os.path.isfile(path):
        raise ValueError('Invalid directory specified as output directory [{0}].  The path supplied is a file'.format(path))
    # Set / create output directory
    if not os.path.isdir(path):
        logdebug("Output directory [{0}] does not exist.  Creating it.".format(path))
        os.mkdir(path)
        os.chmod(path,stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)

    # Set / create extract directory
    if not os.path.isdir(extractdir):
        logdebug("Extract directory [{0}] does not exist.  Creating it.".format(extractdir))
        os.mkdir(extractdir)
        os.chmod(extractdir,stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    else:
        # clear existing files
        logdebug("Extract directory [{0}] exists.  Removing any existing files.")
        for f in os.listdir(extractdir):
            if os.path.isfile(os.path.join(f,extractdir)):
                os.remove(os.path.join(extractdir, f))
            else:
                shutil.rmtree(os.path.join(extractdir,f))

    # Set / create / clear hash not found directory
    if not os.path.isdir(hnfdir):
        logdebug("Hash not found package directory [{0}] does not exist.  Creating it.".format(hnfdir))
        os.mkdir(hnfdir)
        os.chmod(extractdir,stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    else:
        # clear existing files
        logdebug("Hash not found package directory [{0}] exists.  Removing any existing files.")
        for f in os.listdir(hnfdir):
            if os.path.isfile(os.path.join(hnfdir, f)):
                os.remove(os.path.join(hnfdir, f))
            else:
                shutil.rmtree(os.path.join(hnfdir,f))
    
    # Delete existing HNF package
    if os.path.exists(hnfpackagename):
        os.remove(hnfpackagename)
        logdebug("Deleting HNF package: [{0}]".format(hnfpackagename))
    
    # Delete existing log file
    if os.path.exists(logfile):
        os.remove(logfile)
        logdebug("Deleting existing logfile: [{0}]".format(logfile))
    
    # Delete existing results file
    if os.path.exists(resultscsvfile):
        os.remove(resultscsvfile)
        logdebug("Deleting existing results file: [{0}]".format(resultscsvfile))

    logdebug("Output directory set: [{0}]".format(path))
    logdebug("Extract directory set: [{0}]".format(extractdir))
    logdebug("Hash not found package directory set: [{0}]".format(hnfdir))
    logdebug("Log file set: [{0}]".format(logfile))
    logdebug("Results file set: [{0}]".format(resultscsvfile))

def initOutputDir():
    global args
    if args.outputdir == "":
        # Determine file system and set the output directory
        logdebug("No output directory specified in arguments.  Determining default..")
        if os.name=="nt":
            logdebug("File system type: [nt]")
            setOutputDir("C:\\Windows\\temp")
        elif os.name=="posix":
            logdebug("File system type: [posix]")
            setOutputDir("/tmp")
    else:
        setOutputDir(args.outputdir)

def addCsvResultRow(jarpath, classpath, versionresult,finalize=False):
    """Adds a result row to the results CSV file
    Args:
        jarpath (str): 
        classpath (str): 
        versionresult (str):
    """
    global csvrowcount
    global resultscsvfile

    with open(resultscsvfile, 'a') as csvfile:
        # create the csv writer object
        resultscsvwriter = csv.writer(csvfile)
    
        # if there are no csv results in the list, write the header row   
        if csvrowcount == 0:
            resultscsvwriter.writerow(['ScanDate','FQDN','JarPath','ClassPath','ClassVersion'])
            csvrowcount +=1
            
        if csvrowcount > 0 and finalize is False:
            #write the row
            resultscsvwriter.writerow([scandate,hostname,jarpath,classpath,versionresult])
            csvrowcount +=1

        if csvrowcount == 1 and finalize is True:
            resultscsvwriter.writerow([scandate,hostname,'NO RESULTS','',''])

def getStopwatchTime():
    global starttime
    sec = time.time() - starttime
    mins = sec // 60
    sec = sec % 60
    hours = mins // 60
    mins = mins % 60
    return("{0}:{1}:{2}".format(int(hours),int(mins),sec))

def printBanner():
    loginfo("===================================================================")
    loginfo("  log4jscan")
    loginfo("  Version: {0}".format(version))
    loginfo("===================================================================")

def getjndilookupver(filepath):
    """
    Returns a string containing the jndiLookup.class version based on an MD5 hash 
    calculation performed on the file found at the supplied filepath.  This function
    will buffer the input file while hashing to prevent excessive memory consumption
    """
    # BUF_SIZE is used to set the file chunking size for hashing.  This prevents potential
    #          issues with BIG files being passed
    # versionmd5s is a dictionary of md5 hash to JndiLookup.class versions
    BUF_SIZE = 65536
    
    md5 = hashlib.md5()
    
    # Genrate the MD5
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
    
    # Lookup the MD5 in the versionmd5 dictionary.  If found, return the version string
    for hash in versionmd5s:
        if md5.hexdigest().strip() == hash.strip():
            return versionmd5s[hash]
    
    # No match for the MD5, return version not found
    return "VERSION NOT FOUND - HASH: {0}".format(md5.hexdigest())
 
def initntdrives():
    global drives
    logdebug("Entered getntdrives()")
    drive_cmd = subprocess.Popen(['wmic',
                                  'logicaldisk',
                                  'where',
                                  'drivetype=3',
                                  'get',
                                  'deviceid'], 
                                 stdout=subprocess.PIPE)
    _ = drive_cmd.stdout.read().decode("utf-8").strip().split()
    for i in _:
        if ":" in i:
            drives.append(str(i).strip() + '\\\\')
    logdebug("getntdrives() setting drives to [{0}]".format(drives))
    logdebug("Exiting getntdrives()")

def initposixdrives():
    global drives
    logdebug("Entered initposixdrives()")
    drives.append("/")
    # Need to exclude unformated drives
    unformatedexec = subprocess.Popen(['mount','-t','nfs'],
                                         stdout=subprocess.PIPE)
    unformateddrives = unformatedexec.stdout.read()
    for drive in unformateddrives.splitlines():
        excludes.append(str(drive).split(' ')[2])
    if len(excludes) > 0:
        logdebug("Excluding unformated posix mounts: [{0}]".format(excludes))
    logdebug("getposixdrives() setting drives to [{0}]".format(drives))
    logdebug("Exiting initposixdrives()")

def buildhashnotfoundpackage(jarfilepath, classfilepath, versionmsg, filenum):
    global hostname
    global scandate
    global hnfcount
    
    hnfcount +=1
    
    logdebug('Building hash not found package for [{0}] in [{1}]'.format(classfilepath,jarfilepath))
    
    # build package file names
    vhash = versionmsg.split(': ')[1]
    pkgname = hnfdir + "/" + hostname + "-" + vhash + "-" + str(filenum)
    jsonname = hnfdir + "/" + vhash + ".json"
    archivepath = pkgname + ".zip"
    
    # build report json
    hnf = dict(
        {
        "FQDN:" : hostname,
        "ScanDate:" : scandate,
        "JarFilePath:" : jarfilepath,
        "ClassFile:" : classfilepath,
        "VersionResult:" : versionmsg,
        "FileHash:" : vhash,
        "ScannerVersion:" : version
        })
    
    # serialize the json object and write it to a file
    s = json.dumps(hnf, indent = 4)  
    with open(jsonname, "w") as outfile:
        outfile.write(s)
    
    # build archive zip package
    zipObj = ZipFile(archivepath, 'w')
    zipObj.write(jsonname)
    zipObj.write(classfilepath)
    zipObj.close()
    logdebug("Created hash not found package [{0}]".format(archivepath))
    
    # delete working files
    logdebug("Deleting json working file [{0}]".format(jsonname))
    os.remove(jsonname)

def finalizehnfpackages():
    global hnfpackagename
    
    if hnfcount == 0:
        return
    
    # build HNF package zip
    zipObj = ZipFile(hnfpackagename, 'w')
    for f in os.listdir(hnfdir):
        zipObj.write(os.path.join(hnfdir,f))
    zipObj.close()
    
    # cleanup HNF packages
    for f in os.listdir(hnfdir):
        os.remove(os.path.join(hnfdir,f))

def scanjar(path,jarlevel=1,jarlevelpath=""):
    global jarcount
    global jndiclasscount
    global scandate
    
    jarcount += 1
    if jarlevelpath == "":
        jarlevelpath = path
    loginfo("Inspecting jar: [{0}]".format(jarlevelpath))
    jararchive = zipfile.ZipFile(path)
    jararchivefiles = jararchive.namelist()
    for archivefile in jararchivefiles:
        logdebug("---> [{0}]".format(archivefile))
        if "JndiLookup.class" in archivefile:
            jndiclasscount += 1
            logdebug("Processing JndiLookup.class file")
            extractjardir = extractdir + "/" + file
            classfilepath = extractjardir + "/" + archivefile
            jararchive.extract(archivefile,
                               extractjardir)
            v = getjndilookupver(classfilepath)
            loginfo("---> found JndiLookup.class version: [{0}]".format(v))
            if "VERSION NOT FOUND" in v:
                buildhashnotfoundpackage(jarlevelpath,archivefile,v,filecount)
            addCsvResultRow(jarlevelpath,archivefile,v)    
            logdebug("Removing extract directory [{0}]".format(extractjardir))
            shutil.rmtree(extractjardir)
        elif archivefile.endswith(".jar"):
            # recursion for embedded jar...
            logdebug("Processing jar-in-jar...")
            jarlevelpath = jarlevelpath + " --> " + archivefile
            jarlevel +=1
            extractjardir = extractdir + "/" + archivefile + "_" + str(jarlevel)
            jarfilepath = extractjardir + "/" + archivefile
            jararchive.extract(archivefile,
                               extractjardir)
            scanjar(jarfilepath,jarlevel,jarlevelpath)
            shutil.rmtree(extractjardir)

def cleanup():
    if os.path.isdir(extractdir):
        shutil.rmtree(extractdir)
    if os.path.isdir(hnfdir):
        shutil.rmtree(hnfdir)

# Initialize
initArgParser()
args=parser.parse_args()

# Check to see if we should just print version info from arg switch
if args.version is True:
    print('Version: ' + str(version))
    exit()

initOutputDir()
printBanner()

if os.name == "nt":
    initntdrives()
elif os.name == "posix":
    initposixdrives()

# Start the OS walk
for drive in drives:
    for root, dirs, files in os.walk(drive, topdown=True):
        if any(exclude in root for exclude in excludes):
            continue
        for file in files:
            filecount += 1
            logdebug("Scanning file: [{}]".format(os.path.join(root,file)))
            if file.endswith(".jar"):
                jarpath = os.path.join(root,file)
                scanjar(jarpath)
            elif file.endswith(".class"):
                if "JndiLookup.class" in file:
                    jndiclasscount += 1
                    classpath = os.path.join(root,file)
                    v = getjndilookupver(classpath)
                    if "VERSION NOT FOUND" in v:
                        buildhashnotfoundpackage('',classpath,v,filecount)
                    loginfo("---> found JndiLookup.class version: [{0}]".format(v))
                    addCsvResultRow(classpath,'',v)  

# Finalize
addCsvResultRow('','','',True)
finalizehnfpackages()
cleanup()

loginfo("Processing completed:")
loginfo("     Results file: [{0}]".format(resultscsvfile))
if hnfcount > 0:
    loginfo("     Hash Miss Package: [{0}]".format(hnfpackagename))
loginfo("     Run time: [{0}]".format(getStopwatchTime()))
loginfo("     File count: [{0}]".format(str(filecount)))
loginfo("     JAR count: [{0}]".format(str(jarcount)))
loginfo("     JndiLookup.class count: [{0}]".format(str(jndiclasscount)))
loginfo("     Version Hash Misses: [{0}]".format(str(hnfcount)))
