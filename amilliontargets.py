"""
taks2: recursively get all .js files
"""
import asyncio
import pdb
from curl_cffi.requests import AsyncSession 
import random
import time
from linkfinder import myLinkFinder
import aiosqlite
import re
#from pdb import set_trace as trace

with open('scan_targets.txt') as f:
    #x = [f.write(url) for url in urls]
    urls = f.readlines()
    urls = [line.strip() for line in urls]

url = "http://localhost:3000/"
# trace()

#urls = random.choices(urls, k=2)
#urls = ["jitheshkuyyalil.com"]

async def getUrls(urls: list) -> list: 
    async with AsyncSession() as s:
        tasks = [s.get(url, impersonate='chrome110', headers={'X-Bug-Bounty  ':'BugCrowd-jitheshkuyyalil'}) for url in urls]
        results = await asyncio.gather(*tasks)
        return results

async def main():
    start = time.perf_counter()
    async with AsyncSession() as s:    
        async with aiosqlite.connect("db_amilliontargets.db") as db:
            await db.execute("CREATE TABLE IF NOT EXISTS scan_results (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, status_code INTEGER, matches TEXT)")   
            #tasks = [s.get(url, impersonate='chrome110', headers={'X-Bug-Bounty':'BugCrowd-jitheshkuyyalil'}) for url in urls]

            result = await s.get(url, impersonate='chrome110', headers={'X-Bug-Bounty':'BugCrowd-jitheshkuyyalil'})

            #results = await asyncio.gather(*tasks)

            #results = await getUrls(urls)

            print(result.url, result.status_code, result.text[:100])
            #import pdb; pdb.set_trace()

            #for result in results:
            #    print(result.url, result.status_code)
            #    print(result.text, file=open('test' + '.html', 'w'))

            #print(results)

            midtime = time.perf_counter()

            async def analyzeHTML(result):
                #foundPattern = myLinkFinder('text ' + result.text, 'cli', '(?i)(admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
                pattern = re.compile(r'(?i)(admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
                matches = pattern.findall(result.text)
                #print(matches)
                if matches:
                    #with open('results_amilliontarget.txt', 'a') as f:
                        #f.write(result.url + '\n')
                    print(matches)
                    await db.execute("INSERT INTO scan_results (url, status_code, matches) VALUES (?, ?, ?)", (result.url, result.status_code, ', '.join(matches)))
                    await db.commit()
                    return matches

            matches = await analyzeHTML(result)    

            #tasks = [analyzeHTML(result) for result in results]

            #htmlResults = await asyncio.gather(*tasks) 
            print(matches)
            import pdb; pdb.set_trace() 

            async def getJS(result):
                print('*' * 15)
                jslist = myLinkFinder('text ' + result.text, 'cli', '.js')
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

            tasks = [getJS(result) for result in results]
            ## jslistAll is a 2D list -> [[jslinks-domain1],...]
            jslistAll = await asyncio.gather(*tasks)
            type(jslistAll)

            async def analyzeJS(jslist):

                #for (domain, jslinkslist) in zip(results, jslist):
                for jslink in jslist:
                    jsresult = await s.get(jslink)
                    foundPattern = myLinkFinder('text ' + jsresult.text, 'cli', '(?i)(API|secret|admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
                    if foundPattern:
                        with open('scanresults.txt', 'a') as f:
                            f.write(jsresult.url + '\n')
                            async with aiosqlite.connect("db_amilliontargets.db") as db:
                                await db.execute("INSERT INTO scan_results (url, status_code) VALUES (?, ?)", (jsresult.url, jsresult.status_code))
                                await db.commit()
                    print(foundPattern)

            tasks = [analyzeJS(jslinkslist) for (jslinkslist) in (jslistAll)]

            output = await asyncio.gather(*tasks)
            del output

    end = time.perf_counter()
    print('time taken: %.2f, %.2f' % ((midtime - start), (end - midtime)))

    print("scan results from database: ")
    async with aiosqlite.connect("db_amilliontargets.db") as db:
        async with db.execute("SELECT * FROM scan_results") as cursor:
            async for row in cursor:
                print(row)

asyncio.run(main())
