"""
taks2: recursively get all .js files
"""
import asyncio
import pdb
from curl_cffi.requests import AsyncSession 
import random
import time
# from linkfinder import myLinkFinder
from jslinkfinder import myLinkFinder
import aiosqlite
import re
import os
#from pdb import set_trace as trace

if os.path.exists("db_amilliontargets.db"):
    os.remove("db_amilliontargets.db")

with open('scan_targets.txt') as f:
    #x = [f.write(url) for url in urls]
    urls = f.readlines()
    urls = [line.strip() for line in urls]

url = "http://localhost:3000/"
# trace()

#urls = random.choices(urls, k=2)
#urls = ["jitheshkuyyalil.com"]

from dataclasses import dataclass, field
from typing import Optional

@dataclass
class ReconResult:
    url: str
    text: Optional[str] = None
    status_code: Optional[int] = None
    jslit: list[str] = field(default_factory=list)
    
rcnResult =  ReconResult(url=url)

async def getUrl(s: AsyncSession, result: ReconResult, db: aiosqlite.Connection) -> ReconResult: 
    # async with session:
    print("fetching: ", result.url)
    output = await s.get(result.url, impersonate='chrome110', headers={'X-Bug-Bounty  ':'BugCrowd-jitheshkuyyalil'})
    # results = await asyncio.gather(*tasks)
    result.text = output.text
    result.status_code = output.status_code
    # print("fetched: ", result.url, result.status_code, result.text[:100])
    return result

async def getHTML(s: AsyncSession, result: ReconResult, db: aiosqlite.Connection) -> ReconResult:
    output = await getUrl(s, result, db)
    print("fetched: ", output.url, output.status_code, output.text[:100])
    return output

async def analyzeHTML(s: AsyncSession, result: ReconResult, db: aiosqlite.Connection) -> list[str]:
    #foundPattern = myLinkFinder('text ' + result.text, 'cli', '(?i)(admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
    pattern = re.compile(r'(?i)(admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
    matches = pattern.findall(result.text)
    #print(matches)
    matches = list(set(matches))
    if matches:
        #with open('results_amilliontarget.txt', 'a') as f:
            #f.write(result.url + '\n')
        print(matches)
        await db.execute("INSERT INTO scan_results (url, status_code, matches) VALUES (?, ?, ?)", (result.url, result.status_code, ', '.join(matches)))
        await db.commit()
        return matches

async def getJS(s: AsyncSession, result: ReconResult, db: aiosqlite.Connection) -> list[str]:
    print('*' * 15)
    jslist = myLinkFinder(result.text)
    #print(patternFound)
    jslistupdate = []
    # change relative url to full url
    for jslink in jslist:
        if not jslink.startswith('http'):
            from urllib.parse import urljoin
            base_url = result.url  
            relative_url = jslink
            fullurl = urljoin(base_url, relative_url)
            jslistupdate.append(fullurl)
        else:
            jslistupdate.append(jslink)

    return jslistupdate

async def analyzeJS(s: AsyncSession, jslist: list[str], db: aiosqlite.Connection) -> None:
    #for (domain, jslinkslist) in zip(results, jslist):
    for jslink in jslist:
        jsresult = await s.get(jslink)
        # print(jsresult.text)
        pattern = re.compile(r'(?i)(admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup|api|secret|secretkey)')
        matches = pattern.findall(jsresult.text)
        print("js: " , matches)
        #foundPattern = myLinkFinder('text ' + jsresult.text, 'cli', '(?i)(API|secret|admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
        matches = list(set(matches))
        if matches:
            with open('scanresults.txt', 'a') as f:
                f.write(jsresult.url + '\n')
                async with aiosqlite.connect("db_amilliontargets.db") as db:
                    await db.execute("INSERT INTO scan_results (url, status_code, matches) VALUES (?, ?, ?)", (jsresult.url, jsresult.status_code, ', '.join(matches)))
                    await db.commit()
        print(matches)


async def main():
    start = time.perf_counter()
    async with AsyncSession() as s:    
        async with aiosqlite.connect("db_amilliontargets.db") as db:
            await db.execute("CREATE TABLE IF NOT EXISTS scan_results (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, status_code INTEGER, matches TEXT)")   
            #tasks = [s.get(url, impersonate='chrome110', headers={'X-Bug-Bounty':'BugCrowd-jitheshkuyyalil'}) for url in urls]
            
            global rcnResult
            rcnResult = await getHTML(s, rcnResult, db)

            #result = await s.get(url, impersonate='chrome110', headers={'X-Bug-Bounty':'BugCrowd-jitheshkuyyalil'})

            #results = await asyncio.gather(*tasks)

            #results = await getUrls(urls)

            print(rcnResult.url, rcnResult.status_code, rcnResult.text[:100])
            # import pdb; pdb.set_trace()

            #for result in results:
            #    print(result.url, result.status_code)
            #    print(result.text, file=open('test' + '.html', 'w'))

            #print(results)

            midtime = time.perf_counter()

            # async def analyzeHTML(result):
            #     #foundPattern = myLinkFinder('text ' + result.text, 'cli', '(?i)(admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
            #     pattern = re.compile(r'(?i)(admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
            #     matches = pattern.findall(result.text)
            #     #print(matches)
            #     matches = list(set(matches))
            #     if matches:
            #         #with open('results_amilliontarget.txt', 'a') as f:
            #             #f.write(result.url + '\n')
            #         print(matches)
            #         await db.execute("INSERT INTO scan_results (url, status_code, matches) VALUES (?, ?, ?)", (result.url, result.status_code, ', '.join(matches)))
            #         await db.commit()
            #         return matches

            matches = await analyzeHTML(s, rcnResult, db)    
            print(matches)
            # import pdb; pdb.set_trace()

            #tasks = [analyzeHTML(result) for result in results]

            #htmlResults = await asyncio.gather(*tasks) 

            # async def getJS(s: AsyncSession, result: ReconResult, db: aiosqlite.Connection) -> list[str]:
            #     print('*' * 15)
            #     jslist = myLinkFinder(result.text)
            #     #print(patternFound)
            #     jslistupdate = []
            #     # change relative url to full url
            #     for jslink in jslist:
            #         if not jslink.startswith('http'):
            #             from urllib.parse import urljoin
            #             base_url = result.url  
            #             relative_url = jslink
            #             fullurl = urljoin(base_url, relative_url)
            #             jslistupdate.append(fullurl)
            #         else:
            #             jslistupdate.append(jslink)

            #     return jslistupdate
            
            jslist = await getJS(s, rcnResult, db)
            print(jslist)
            # import pdb; pdb.set_trace()

            # tasks = [getJS(result) for result in results]
            ## jslistAll is a 2D list -> [[jslinks-domain1],...]
            # jslistAll = await asyncio.gather(*tasks)
            # type(jslistAll)

            # async def analyzeJS(s: AsyncSession, jslist: list[str], db: aiosqlite.Connection) -> None:
            #     #for (domain, jslinkslist) in zip(results, jslist):
            #     for jslink in jslist:
            #         jsresult = await s.get(jslink)
            #         # print(jsresult.text)
            #         pattern = re.compile(r'(?i)(admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup|api|secret|secretkey)')
            #         matches = pattern.findall(jsresult.text)
            #         print("js: " , matches)
            #         #foundPattern = myLinkFinder('text ' + jsresult.text, 'cli', '(?i)(API|secret|admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
            #         matches = list(set(matches))
            #         if matches:
            #             with open('scanresults.txt', 'a') as f:
            #                 f.write(jsresult.url + '\n')
            #                 async with aiosqlite.connect("db_amilliontargets.db") as db:
            #                     await db.execute("INSERT INTO scan_results (url, status_code, matches) VALUES (?, ?, ?)", (jsresult.url, jsresult.status_code, ', '.join(matches)))
            #                     await db.commit()
            #         print(matches)

            await analyzeJS(s, jslist, db)

            # import pdb; pdb.set_trace() 

            # tasks = [analyzeJS(jslinkslist) for (jslinkslist) in (jslistAll)]

            # output = await asyncio.gather(*tasks)
            # del output

    end = time.perf_counter()
    print('time taken: %.2f, %.2f' % ((midtime - start), (end - midtime)))

    print("scan results from database: ")
    async with aiosqlite.connect("db_amilliontargets.db") as db:
        async with db.execute("SELECT * FROM scan_results") as cursor:
            async for row in cursor:
                print(row)

asyncio.run(main())
