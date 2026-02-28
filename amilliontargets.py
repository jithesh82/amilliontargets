import asyncio
from curl_cffi.requests import get

async def get1():
    get('www.tesla.com', impersonate='chrome110')

async def get2():
    get('www.war.gov', impersonate='chrome110')


async def main():
    task1 = asyncio.create_task(get1())
    task2 = asyncio.create_task(get2())
    await task1
    await task2

asyncio.run(main())
