import asyncio
from curl_cffi.requests import get, AsyncSession 

async def get1():
    get('www.tesla.com', impersonate='chrome110')

async def get2():
    get('www.war.gov', impersonate='chrome110')


async def main():
    async with AsyncSession() as s:
        task1 = asyncio.create_task(s.get('www.tesla.com', impersonate='chrome110'))
        task2 = asyncio.create_task(s.get('www.tesla.com', impersonate='chrome110'))
        await task1
        await task2

asyncio.run(main())
