"""
Task1: save the html file to disk
Task2: add tqdm 
"""
import asyncio
from curl_cffi.requests import AsyncSession 
import random
import time

urls =['www.tesla.com', 'www.war.gov', 'www.clio.com', 'www.criteo.com', 'account.t-mobile.com']
urls = random.choices(urls, k=5)

async def main():
    start = time.perf_counter()
    async with AsyncSession() as s:
        tasks = [s.get(url, impersonate='chrome110') for url in urls]

        results = await asyncio.gather(*tasks)

        for result in results:
            print(result.url, result.status_code)
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
