from ComponentClass import Component
from ConfigClass import Config
# from BOMClass import BOM
# import global_values
# import logging
# import requests
import aiohttp
import asyncio

class ComponentList:
    def __init__(self):
        self.components = []

    def add(self, comp: Component):
        self.components.append(comp)

    def count(self):
        return len(self.components)

    def count_ignored(self):
        count = 0
        for comp in self.components:
            if comp.is_ignored():
                count += 1
        return count

    def get_vulns(self):
        for comp in self.components:
            comp.get_vulns()

    def check_kernel(self):
        for comp in self.components:
            if comp.is_kernel():
                return True

        return False

    def get_copyrights(self, conf: Config, bom):
        for comp in self.components:
            if comp.is_ignored():
                continue
            count = comp.get_copyrights(conf, bom)
            conf.logger.info(f"Component '{comp.name}/{comp.version}': {count} copyrights")

    async def async_get_copyright_counts(self, conf :Config, bd):
        token = bd.session.auth.bearer_token

        async with aiohttp.ClientSession(trust_env=True) as session:
            copyright_tasks = []
            for comp in self.components:
                if comp.is_ignored():
                    continue

                copyright_task = asyncio.ensure_future(comp.async_get_copyright_count(bd, conf, session, token))
                copyright_tasks.append(copyright_task)

            copyright_data = dict(await asyncio.gather(*copyright_tasks))
            await asyncio.sleep(0.250)

        return copyright_data

    async def async_get_file_copyrights(self, conf: Config, bd, zero_count_ids):
        token = bd.session.auth.bearer_token

        async with aiohttp.ClientSession(trust_env=True) as session:
            tasks = []
            for comp in self.components:
                if comp.is_ignored() or comp.id not in zero_count_ids:
                    continue
                task = asyncio.ensure_future(
                    comp.async_get_file_copyrights(bd, conf, session, token)
                )
                tasks.append(task)

            if not tasks:
                return {}

            result = dict(await asyncio.gather(*tasks))
            await asyncio.sleep(0.250)
            conf.logger.info('-')

        return result
