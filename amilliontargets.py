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
from abc import ABC, abstractmethod
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
    jslist: list[str] = field(default_factory=list)
    htmlMatches: list[str] = field(default_factory=list)
    jsMatches: list[str] = field(default_factory=list)

rcnResult =  ReconResult(url=url)


class reconPipeline:
    def __init__(self, pipeline: list, s: AsyncSession, result: ReconResult,  db: aiosqlite.Connection) -> ReconResult:
        self.pipeline = pipeline
        self.result = result
        self.s = s
        self.db = db
        self.run()
    async def run(self) -> ReconResult:
        for func in self.pipeline:
            self.result = await func(self.s, self.result, self.db)
        return self.result

class VulnRecon(ABC):
    def __init__(self, s: AsyncSession, result: ReconResult, db: aiosqlite.Connection) -> ReconResult:
        self.s = s
        self.result = result
        self.db = db
    @abstractmethod
    async def run(self) -> ReconResult:
        pass       
    async def getUrl(self) -> ReconResult: 
        # async with session:
        print("fetching: ", self.result.url)
        output = await self.s.get(self.result.url, impersonate='chrome110', headers={'X-Bug-Bounty  ':'BugCrowd-jitheshkuyyalil'})
        # results = await asyncio.gather(*tasks)
        self.result.text = output.text
        self.result.status_code = output.status_code
        # print("fetched: ", self.result.url, self.result.status_code, self.result.text[:100])
        return self.result

class GetHTML(VulnRecon):
    def __init__(self, s: AsyncSession, result: ReconResult, db: aiosqlite.Connection) -> ReconResult:
        super().__init__(s, result, db)
    async def run(self) -> ReconResult:
        output = await self.getUrl()
        self.result.text = output.text
        self.result.status_code = output.status_code
        print("fetched: ", output.url, output.status_code, output.text[:100])
        return self.result

class AnalyzeHTML(VulnRecon):
    def __init__(self, s: AsyncSession, result: ReconResult, db: aiosqlite.Connection) -> ReconResult:
        super().__init__(s, result, db)
    async def run(self) -> ReconResult:
        pattern = re.compile(r'(?i)(admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup)')
        matches = pattern.findall(self.result.text)
        matches = list(set(matches))
        if matches:
            print(matches)
            await self.db.execute("INSERT INTO scan_results (url, status_code, matches) VALUES (?, ?, ?)", (self.result.url, self.result.status_code, ', '.join(matches)))
            await self.db.commit()
        for match in matches:
            self.result.htmlMatches.append(match)
        return self.result

class GetJS(VulnRecon):
    def __init__(self, s: AsyncSession, result: ReconResult, db: aiosqlite.Connection) -> ReconResult:
        super().__init__(s, result, db)
    async def run(self) -> ReconResult:
        print('*' * 15)
        jslist_ = myLinkFinder(self.result.text)
        jslist = []
        for jslink in jslist_:
            if not jslink.startswith('http'):
                from urllib.parse import urljoin
                base_url = self.result.url  
                relative_url = jslink
                fullurl = urljoin(base_url, relative_url)
                jslist.append(fullurl)
            else:
                jslist.append(jslink)
        for jslink in jslist:
            self.result.jslist.append(jslink)
        return self.result

class AnalyzeJS(VulnRecon):
    def __init__(self, s: AsyncSession, result: ReconResult, db: aiosqlite.Connection) -> ReconResult:
        super().__init__(s, result, db)
    async def run(self) -> ReconResult:
        for jslink in self.result.jslist:
            jsresult = await self.s.get(jslink)
            pattern = re.compile(r'(?i)(admin|administrator|internal|old|bak|backup|key|env|.env|back|bkup|api|secret|secretkey)')
            matches = pattern.findall(jsresult.text)
            matches = list(set(matches))
            if matches:
                with open('scanresults.txt', 'a') as f:
                    f.write(jsresult.url + '\n')
                    async with aiosqlite.connect("db_amilliontargets.db") as db:
                        await db.execute("INSERT INTO scan_results (url, status_code, matches) VALUES (?, ?, ?)", (jsresult.url, jsresult.status_code, ', '.join(matches)))
                        await db.commit()
            print(matches)
        for match in matches:
            self.result.jsMatches.append(match)
        return self.result

class reconPipelineClass:
    def __init__(self, pipeline: list, s: AsyncSession, result: ReconResult,  db: aiosqlite.Connection) -> ReconResult:
        self.pipeline = pipeline
        self.result = result
        self.s = s
        self.db = db
        self.run()
    async def run(self) -> ReconResult:
        for reconclass in self.pipeline:
            self.result = await reconclass(self.s, self.result, self.db).run()
        return self.result

async def main():
    start = time.perf_counter()
    async with AsyncSession() as s:    
        async with aiosqlite.connect("db_amilliontargets.db") as db:
            await db.execute("CREATE TABLE IF NOT EXISTS scan_results (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, status_code INTEGER, matches TEXT)")   
            
            global rcnResult

            midtime = time.perf_counter()

            # pipeline test with class as input
            print("\n" + "*" * 15 + "class pipeline test" + "*" * 15)
            url = 'http://localhost:3000/'
            mypipe = reconPipelineClass(pipeline=[GetHTML, AnalyzeHTML, GetJS, AnalyzeJS],  s=s, result=ReconResult(url=url), db=db)
            mypipeResult = await mypipe.run()
            print(mypipeResult.url, mypipeResult.status_code, mypipeResult.htmlMatches, mypipeResult.jsMatches)


    end = time.perf_counter()
    print('time taken: %.2f, %.2f' % ((midtime - start), (end - midtime)))

    print("scan results from database: ")
    async with aiosqlite.connect("db_amilliontargets.db") as db:
        async with db.execute("SELECT * FROM scan_results") as cursor:
            async for row in cursor:
                print(row)

asyncio.run(main())