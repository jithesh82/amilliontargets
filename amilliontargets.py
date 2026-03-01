"""
task1: parse html file for .js files
taks2: recursively get all .js files
"""
import asyncio
from curl_cffi.requests import AsyncSession 
import random
import time
#from pdb import set_trace as trace

with open('scan_targets.txt') as f:
    #x = [f.write(url) for url in urls]
    urls = f.readlines()
    urls = [line.strip() for line in urls]

# trace()

urls = random.choices(urls, k=1)

async def main():
    start = time.perf_counter()
    async with AsyncSession() as s:    
        tasks = [s.get(url, impersonate='chrome110', headers={'X-Bug-Bounty':'BugCrowd-jitheshkuyyalil'}) for url in urls]

        results = await asyncio.gather(*tasks)

        for result in results:
            print(result.url, result.status_code, result.headers)
            print(result.text, file=open('test' + '.html', 'w'))

        print(results)

        midtime = time.perf_counter()

        async def contentWrite(result):
            fName = result.url.split('/')[2] + '.html'
            with open(fName, 'w') as f:
                f.write(result.text)

        tasks = [contentWrite(result) for result in results]

        results = await asyncio.gather(*tasks)
    end = time.perf_counter()
    print('time taken: %.2f, %.2f' % ((midtime - start), (end - midtime)))


asyncio.run(main())
