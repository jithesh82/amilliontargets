"""
Task1: save the html file to disk
Task2: add tqdm 
"""
import asyncio
from curl_cffi.requests import AsyncSession 

urls =['www.tesla.com', 'www.war.gov', 'www.clio.com']


async def main():
    async with AsyncSession() as s:
        tasks = [s.get(url, impersonate='chrome110') for url in urls]

        results = await asyncio.gather(*tasks)

        for result in results:
            print(result.url, result.status_code)

asyncio.run(main())
