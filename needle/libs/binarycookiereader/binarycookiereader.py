#*******************************************************************************#
# BinaryCookieReader: Written By Satishb3 (http://www.securitylearn.net)        #
#                                                                               #
# For any bug fixes contact me: satishb3@securitylearn.net                      #
#                                                                               #
# Usage: Python BinaryCookieReader.py Cookie.Binarycookies-FilePath             #
#                                                                               #
# Safari browser and iOS applications store the persistent cookies in a binary  #
# file names Cookies.binarycookies.BinaryCookieReader is used to dump all the   #
# cookies from the binary Cookies.binarycookies file.                           #
#                                                                               #
#*******************************************************************************#

import sys
from struct import unpack
from StringIO import StringIO
from time import strftime, gmtime

if len(sys.argv)!=2:
    print "\nUsage: Python BinaryCookieReader.py [Full path to Cookies.binarycookies file] \n"
    print "Example: Python BinaryCookieReader.py C:\Cookies.binarycookies"
    sys.exit(0)

FilePath=sys.argv[1]
try:
    binary_file=open(FilePath,'rb')
except IOError as e:
    print 'File Not Found :'+ FilePath
    sys.exit(0)
   
file_header=binary_file.read(4)                             #File Magic String:cook
if str(file_header)!='cook':
    print "Not a Cookies.binarycookie file"
    sys.exit(0)

num_pages=unpack('>i',binary_file.read(4))[0]               #Number of pages in the binary file: 4 bytes
page_sizes=[]
for np in range(num_pages):
    page_sizes.append(unpack('>i',binary_file.read(4))[0])  #Each page size: 4 bytes*number of pages

pages=[]
for ps in page_sizes:
    pages.append(binary_file.read(ps))                      #Grab individual pages and each page will contain >= one cookie

print "#*************************************************************************#"
print "# BinaryCookieReader: developed by Satishb3: http://www.securitylearn.net #"
print "#*************************************************************************#"
for page in pages:
    page=StringIO(page)                                     #Converts the string to a file. So that we can use read/write operations easily.
    page.read(4)                                            #page header: 4 bytes: Always 00000100
    num_cookies=unpack('<i',page.read(4))[0]                #Number of cookies in each page, first 4 bytes after the page header in every page.
    cookie_offsets=[]
    for nc in range(num_cookies):
        cookie_offsets.append(unpack('<i',page.read(4))[0]) #Every page contains >= one cookie. Fetch cookie starting point from page starting byte
    page.read(4)                                            #end of page header: Always 00000000
    cookie=''
    for offset in cookie_offsets:
        page.seek(offset)                                   #Move the page pointer to the cookie starting point
        cookiesize=unpack('<i',page.read(4))[0]             #fetch cookie size
        cookie=StringIO(page.read(cookiesize))              #read the complete cookie
        cookie.read(4)                                      #unknown
        flags=unpack('<i',cookie.read(4))[0]                #Cookie flags:  1=secure, 4=httponly, 5=secure+httponly
        cookie_flags=''
        if flags==0:
            cookie_flags=''
        elif flags==1:
            cookie_flags='Secure'
        elif flags==4:
            cookie_flags='HttpOnly'
        elif flags==5:
            cookie_flags='Secure; HttpOnly'
        else:
            cookie_flags='Unknown'

        cookie.read(4)                                      #unknown
        urloffset=unpack('<i',cookie.read(4))[0]            #cookie domain offset from cookie starting point
        nameoffset=unpack('<i',cookie.read(4))[0]           #cookie name offset from cookie starting point
        pathoffset=unpack('<i',cookie.read(4))[0]           #cookie path offset from cookie starting point
        valueoffset=unpack('<i',cookie.read(4))[0]          #cookie value offset from cookie starting point
        endofcookie=cookie.read(8)                          #end of cookie
        expiry_date_epoch= unpack('<d',cookie.read(8))[0]+978307200          #Expiry date is in Mac epoch format: Starts from 1/Jan/2001
        expiry_date=strftime("%a, %d %b %Y ",gmtime(expiry_date_epoch))[:-1] #978307200 is unix epoch of  1/Jan/2001 //[:-1] strips the last space
        create_date_epoch=unpack('<d',cookie.read(8))[0]+978307200           #Cookies creation time
        create_date=strftime("%a, %d %b %Y ",gmtime(create_date_epoch))[:-1]
		
        cookie.seek(urloffset-4)                            #fetch domaain value from url offset
        url=''
        u=cookie.read(1)
        while unpack('<b',u)[0]!=0:
            url=url+str(u)
            u=cookie.read(1)

        cookie.seek(nameoffset-4)                           #fetch cookie name from name offset
        name=''
        n=cookie.read(1)
        while unpack('<b',n)[0]!=0:
            name=name+str(n)
            n=cookie.read(1)

        cookie.seek(pathoffset-4)                          #fetch cookie path from path offset
        path=''
        pa=cookie.read(1)
        while unpack('<b',pa)[0]!=0:
            path=path+str(pa)
            pa=cookie.read(1)

        cookie.seek(valueoffset-4)                         #fetch cookie value from value offset
        value=''
        va=cookie.read(1)
        while unpack('<b',va)[0]!=0:
            value=value+str(va)
            va=cookie.read(1)

        print 'Cookie : '+name+'='+value+'; domain='+url+'; path='+path+'; '+'expires='+expiry_date+'; '+cookie_flags
binary_file.close()