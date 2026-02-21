# import global_values
import re
# import global_values
# import logging
# from thefuzz import fuzz
from VulnListClass import VulnList
from ConfigClass import Config
# from BOMClass import BOM


class Component:
    def __init__(self, name, version, data):
        self.name = name
        self.version = version
        self.vulnlist = VulnList()
        self.data = data
        self.id = self.get_compid()

    # def get_matchtypes(self):
    #     try:
    #         return self.data['matchTypes']
    #     except KeyError:
    #         return []
    #
    # def is_dependency(self):
    #     dep_types = ['FILE_DEPENDENCY_DIRECT', 'FILE_DEPENDENCY_TRANSITIVE']
    #     match_types = self.get_matchtypes()
    #     for m in dep_types:
    #         if m in match_types:
    #             return True
    #     return False
    #
    # def is_signature(self):
    #     sig_types = ['FILE_EXACT', 'FILE_SOME_FILES_MODIFIED', 'FILE_FILES_ADDED_DELETED_AND_MODIFIED',
    #                  'FILE_EXACT_FILE_MATCH']
    #     match_types = self.get_matchtypes()
    #     for m in sig_types:
    #         if m in match_types:
    #             return True
    #     return False

    def is_ignored(self):
        try:
            return self.data['ignored']
        except KeyError:
            return False

    # def process_signatures(self):
    #     all_paths_ignoreable = True
    #     unmatched = False
    #     reason = ''
    #     for sigentry in self.sigentry_arr:
    #         ignore, reason = sigentry.filter_folders()
    #         if not ignore:
    #             all_paths_ignoreable = False
    #         else:
    #             self.sigentry_arr.remove(sigentry)
    #
    #     if all_paths_ignoreable:
    #         # Ignore
    #         reason = f"Mark IGNORED - {reason}"
    #         self.reason = reason
    #         logging.debug(f"- Component {self.filter_name}/{self.version}: {reason}")
    #         self.set_ignore()
    #     else:
    #     #     print(f"NOT Ignoring {self.name}/{self.version}")
    #         self.sig_match_result = 0
    #         set_reviewed = False
    #         ignore = True
    #         unmatched = True
    #         reason = f"No Action - component name '{self.oriname_arr}' not found in signature paths"
    #         for sigentry in self.sigentry_arr:
    #             # compname_found, compver_found,\
    #             #     new_match_result = sigentry.search_component(self.filter_name, self.filter_version)
    #             compname_found, compver_found,\
    #                 new_match_result = sigentry.search_component(self.oriname_arr, self.filter_version)
    #             logging.debug(f"Compname in path {compname_found}, Version in path {compver_found}, "
    #                           f"Match result {new_match_result}, Path '{sigentry.path}'")
    #
    #             if compver_found:
    #                 self.compver_found = True
    #                 ignore = False
    #                 unmatched = False
    #             if compname_found:
    #                 self.compname_found = True
    #             if global_values.version_match_reqd:
    #                 if compver_found:
    #                     set_reviewed = True
    #                     ignore = False
    #                     unmatched = False
    #                 else:
    #                     reason = f"No Action - component version {self.filter_version} not found
    #                     (and required because --version_match_reqd set)"
    #             elif compname_found:
    #                 set_reviewed = True
    #                 ignore = False
    #                 unmatched = False
    #             if new_match_result > self.sig_match_result:
    #                 self.sig_match_result = new_match_result
    #                 self.best_sigpath = sigentry.path
    #             # print(self.name, self.version, src['commentPath'])
    #         if set_reviewed:
    #             if self.compver_found:
    #                 reason = f"Mark REVIEWED - Compname & version in path '{self.best_sigpath}'
    #                 (Match result {self.sig_match_result})"
    #             elif self.compname_found:
    #                 reason = f"Mark REVIEWED - Compname {self.oriname_arr} in path '{self.best_sigpath}'
    #                 (Match result {self.sig_match_result})"
    #
    #             logging.debug(f"- Component {self.name}/{self.version}: {reason}")
    #             self.set_reviewed()
    #             unmatched = False
    #     if ignore and global_values.ignore_no_path_matches:
    #         self.set_ignore()
    #         reason = f"Mark IGNORED - compname or version not found in paths & --ignore_no_path_matches set"
    #
    #     self.reason = reason
    #     self.unmatched = unmatched

    # @staticmethod
    # def filter_name_string(name, logger):
    #     # Remove common words
    #     # - for, with, in, on,
    #     # Remove strings in brackets
    #     # Replace / with space
    #     ret_name = re.sub(r"\(.*\)", r"", name)
    #     for rep in [r" for ", r" with ", r" in ", r" on ", r" a ", r" the ", r" by ",
    #                 r" and ", r"^apache | apache | apache$", r" bundle ", r" only | only$", r" from ",
    #                 r" to ", r" - "]:
    #         ret_name = re.sub(rep, " ", ret_name, flags=re.IGNORECASE)
    #     ret_name = re.sub(r"[/@#:]", " ", ret_name)
    #     ret_name = re.sub(r" \w$| \w |^\w ", r" ", ret_name)
    #     ret_name = ret_name.replace("::", " ")
    #     ret_name = re.sub(r" +", r" ", ret_name)
    #     ret_name = re.sub(r"^ ", r"", ret_name)
    #     ret_name = re.sub(r" $", r"", ret_name)
    #
    #     debug(f"filter_name_string(): Compname '{name}' replaced with '{ret_name}'")
    #     return ret_name.lower()

    @staticmethod
    def filter_version_string(version):
        # Remove +git*
        # Remove -snapshot*
        # Replace / with space
        ret_version = re.sub(r"\+git.*", r"", version, flags=re.IGNORECASE)
        ret_version = re.sub(r"-snapshot.*", r"", ret_version, flags=re.IGNORECASE)
        ret_version = re.sub(r"/", r" ", ret_version)
        ret_version = re.sub(r"^v", r"", ret_version, flags=re.IGNORECASE)
        ret_version = re.sub(r"\+*", r"", ret_version, flags=re.IGNORECASE)

        return ret_version.lower()

    def get_compid(self):
        try:
            compurl = self.data['componentVersion']
            # return compurl.split('/')[-1]
            return compurl
        except KeyError:
            return ''

    # def print_origins(self):
    #     try:
    #         for ori in self.data['origins']:
    #             print(f"Comp '{self.name}/{self.version}' Origin '{ori['externalId']}' Name '{ori['name']}'")
    #     except KeyError:
    #         print(f"Comp '{self.name}/{self.version}' No Origin")
    #
    # def get_origin_compnames(self):
    #     compnames_arr = []
    #     try:
    #         for ori_entry in self.data['origins']:
    #             ori = ori_entry['externalId']
    #             ori_ver = ori_entry['name']
    #             ori_string = ori.replace(f"{ori_ver}", '')
    #             arr = re.split(r"[:/#]", ori_string)
    #             new_name = arr[-2].lower()
    #             if new_name not in compnames_arr:
    #                 logging.debug(
    #                     f"Comp '{self.name}/{self.version}' Compname calculate from origin '{new_name}' -
    #                     origin='{ori}'")
    #                 compnames_arr.append(new_name)
    #         if self.filter_name.find(' ') == -1:
    #             # Single word component name
    #             if self.filter_name not in compnames_arr:
    #                 compnames_arr.append(self.filter_name.lower())
    #     except (KeyError, IndexError):
    #         logging.debug(f"Comp '{self.name}/{self.version}' Compname calculate from compname only '{self.name}'")
    #         compnames_arr.append(self.filter_name.lower())
    #     return compnames_arr
    #
    # def get_sigpaths(self):
    #     data = ''
    #     count = 0
    #     for sigentry in self.sigentry_arr:
    #         data += f"{sigentry.get_sigpath()}\n"
    #         count += 1
    #     return data

    def check_kernel(self):
        if self.name == 'Linux Kernel':
            return True
        return False

    def get_href(self, href_string, conf):
        try:
            for link in self.data['_meta']['links']:
                if link['rel'] == href_string:
                    return link['href']
        except Exception as e:
            conf.logger.error(f"Unable to process href links for component {self.name} - {e}")
        return ''

    def get_copyrights(self, conf: Config, bom):
        try:
            # origin_url = self.get_href('origins', conf)
            #
            # # copyright_url = origin_url + "/copyrights"
            # data = conf.get_data(bom.bd, origin_url, "application/vnd.blackducksoftware.component-detail-4+json")
            # for origin in data['items']:
            #     fcopyright_url = self.get_href(origin, 'file-copyrights')
            #     print(fcopyright_url)
            count_copyrights = 0
            for origin in self.data['origins']:
                copyright_url = origin['origin'] + "/copyrights"
                data = conf.get_data(bom.bd, copyright_url, "application/vnd.blackducksoftware.copyright-4+json")
                count_copyrights += data['totalCount']
            return count_copyrights

        except Exception as e:
            conf.logger.error(e)
        return 0

    async def async_get_copyright_count(self, bd, conf, session, token):
        if conf.bd_trustcert:
            ssl = False
        else:
            ssl = None

        headers = {
            'Accept': "application/vnd.blackducksoftware.copyright-4+json",
            'Authorization': f'Bearer {token}',
        }

        comp_id = self.id
        try:
            count = 0
            for origin in self.data['origins']:
                copyright_url = origin['origin'] + "/copyrights"
                async with session.get(copyright_url, headers=headers, ssl=ssl) as resp:
                    data = await resp.json()
                count += data.get('totalCount', 0)
            return comp_id, count
        except Exception as e:
            conf.logger.error(e)

        return comp_id, 0

    async def async_get_file_copyrights(self, bd, conf, session, token):
        if conf.bd_trustcert:
            ssl = False
        else:
            ssl = None

        headers_origins = {
            'Accept': "application/vnd.blackducksoftware.component-detail-4+json",
            'Authorization': f'Bearer {token}',
        }
        headers_copyrights = {
            'Accept': "application/vnd.blackducksoftware.copyright-4+json",
            'Authorization': f'Bearer {token}',
        }

        all_copyrights = []
        try:
            for selected_origin in self.data.get('origins', []):
                # Strip last path segment (origin ID) to get component version origins list, fetch first 20
                origin_url = selected_origin['origin'].rstrip('/')
                origins_list_url = origin_url.rsplit('/', 1)[0] + '?limit=100'

                async with session.get(origins_list_url, headers=headers_origins, ssl=ssl) as resp:
                    origins_data = await resp.json()

                for origin_item in origins_data.get('items', []):
                    origin_item_href = origin_item.get('_meta', {}).get('href', '')
                    if not origin_item_href:
                        continue
                    copyright_url = origin_item_href.rstrip('/') + '/copyrights'

                    async with session.get(copyright_url, headers=headers_copyrights, ssl=ssl) as resp:
                        copyright_data = await resp.json()

                    for item in copyright_data.get('items', []):
                        copyright_text = item.get('updatedCopyright', item.get('originalCopyright', ''))
                        if copyright_text and copyright_text not in all_copyrights:
                            all_copyrights.append(copyright_text)

        except Exception as e:
            conf.logger.error(f"Error fetching file copyrights for {self.name}/{self.version}: {e}")

        return self.id, all_copyrights

