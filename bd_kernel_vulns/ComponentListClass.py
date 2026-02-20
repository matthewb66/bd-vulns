from ComponentClass import Component
from ConfigClass import Config
# from BOMClass import BOM
# import global_values
# import logging
# import requests

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
            if comp.get_copyrights(conf, bom) == 0:
                conf.logger.info(f"Component '{comp.name}/{comp.version}': missing copyrights")
            else:
                conf.logger.info(f"Component '{comp.name}/{comp.version}': OK")
