"""
taks2: recursively get all .js files
"""
import asyncio
from curl_cffi.requests import AsyncSession 
import random
import time
from linkfinder import myLinkFinder
from pdb import set_trace as trace

with open('scan_targets.txt') as f:
    #x = [f.write(url) for url in urls]
    urls = f.readlines()
    urls = [line.strip() for line in urls]

# trace()

urls = random.choices(urls, k=2)

async def getUrls(urls: list) -> list: 
    async with AsyncSession() as s:
        tasks = [s.get(url, impersonate='chrome110', headers={'X-Bug-Bounty  ':'BugCrowd-jitheshkuyyalil'}) for url in urls]
        results = await asyncio.gather(*tasks)
        return results


async def main():
    start = time.perf_counter()
    async with AsyncSession() as s:    
        tasks = [s.get(url, impersonate='chrome110', headers={'X-Bug-Bounty':'BugCrowd-jitheshkuyyalil'}) for url in urls]

        results = await asyncio.gather(*tasks)

        #results = await getUrls(urls)

        for result in results:
            print(result.url, result.status_code)
        #    print(result.text, file=open('test' + '.html', 'w'))

        print(results)

        midtime = time.perf_counter()

        async def analyzeHTML(result):
            foundPattern = myLinkFinder('text ' + result.text, 'cli', '(?i)(admin)')
            if foundPattern:
                with open('results_amilliontarget.txt', 'a') as f:
                    f.write(result.url + '\n')

        tasks = [analyzeHTML(result) for result in results]

        await asyncio.gather(*tasks) 
                    

        async def analyzeJS(result):
            foundPattern = myLinkFinder('text ' + result.text, 'cli', '(?i)(API|secret|admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
            print('*' * 15)
            print(foundPattern)
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

        #tasks = [analyzeHTML(result) for result in results]
        ## jslist is a 2D list -> [[jslinks-domain1],...]
        #jslist = await asyncio.gather(*tasks)

        #async def analyzeJS(results, jslist):

        #    #for (domain, jslinkslist) in zip(results, jslist):
        #    for jslink in jslinkslist:
        #        jsresult = s.get(jslink)
        #        foundPattern = myLinkFinder('text ' + jsresult.text, 'cli', '(?i)(API|secret|admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
        #        if foundPattern:
        #            with open('scanresults.txt', 'w') as f:
        #                f.write(jsresult.url, foundPattern)
        #        print(foundPattern)

        #tasks = [analyzeJS(results, jslist) for (domain, jslinkslist) in zip(result,jslist)]

        #output = await asyncio.gather(*tasks)
        #del output

        #print('- -' * 15)
        ##jslist = jslist[0]
        #for domain in jslist:
        #    [print(item) for item in domain]

        #async def contentWrite(result):
        #    fName = result.url.split('/')[2] + '.html'
        #    with open(fName, 'w') as f:
        #        f.write(result.text)

        #tasks = [contentWrite(result) for result in results]

        #results = await asyncio.gather(*tasks)
    end = time.perf_counter()
    print('time taken: %.2f, %.2f' % ((midtime - start), (end - midtime)))

asyncio.run(main())
