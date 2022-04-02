import unittest

from .cve_matcher import CVEMatcher, is_version_any, get_main_version
import pandas as pd
def get_sorted_keys(report):
    return sorted(report.keys())


class DictTester(unittest.TestCase):

    def assertEqualKeys(self, dict1, dict2):
        keys_dict1 = get_sorted_keys(dict1)
        keys_dict2 = get_sorted_keys(dict2)
        self.assertEqual(keys_dict1, keys_dict2)

    def assertEqualValues(self, dict1, dict2):
        for key, value_dict1 in dict1.items():
            self.assertEqual(value_dict1, dict2[key], "key: " + key + " values not equal " + str(value_dict1) + " != " + str(dict2[key]))

CVE_1 = {'id': 'CVE-2007-4774',
         'summary': 'The Linux kernel before 2.4.36-rc1 has a race condition. It was possible to bypass systrace policies by flooding the ptraced process with SIGCONT signals, which can can wake up a PTRACED process.',
         'reference_data': "['http://taviso.decsystem.org/research.html', 'https://osdn.net/projects/linux-kernel-docs/scm/git/linux-2.4.36/listCommit?skip=60','https://security.netapp.com/advisory/ntap-20200204-0002/']",
         'cpes': ['cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*'],
         'vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N',
         'attack_complexity': 'HIGH',
         'confidentiality_impact': 'NONE',
         'integrity_impact': 'HIGH',
         'availability_impact': 'NONE',
         'privileges_required': 'NONE',
         'base_score': '5.9',
         'base_severity': 'MEDIUM',
         'exploitability_score': '2.2',
         'impact_score': '3.6',
         'cpes_logic': "[{'operator': 'OR', 'cpe_match': [{'vulnerable': True, 'cpe23Uri': 'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*', 'versionEndIncluding': '2.4.35'}]}]"
         }
CVE_2 = {
    'id': 'CVE-2017-11124',
    'summary': 'libxar.so in xar 1.6.1 has a NULL pointer dereference in the xar_unserialize function in archive.c.',
    'reference_data': "['https://blogs.gentoo.org/ago/2017/06/28/xar-null-pointer-dereference-in-xar_unserialize-archive-c/','https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2S2KRIILUKBJHXDNYJQQX74TFUQRG5ND/','https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YV6RF6VWM7AFYFTTS7VY5TNH26QUEEFC/']",
    'cpes': ['cpe:2.3:a:xar_project:xar:1.6.1:*:*:*:*:*:*:*'],
    'vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'attack_complexity': 'LOW',
    'confidentiality_impact': 'HIGH',
    'integrity_impact': 'HIGH',
    'availability_impact': 'NONE',
    'privileges_required': 'NONE',
    'base_score': '9.8',
    'base_severity': 'CRITICAL',
    'exploitability_score': '3.9',
    'impact_score': '5.9',
    'cpes_logic': "[{'operator': 'OR', 'cpe_match': [{'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:xar_project:xar:1.6.1:*:*:*:*:*:*:*'}]}]"
}

CVE_3 = {
    'id': 'CVE-2018-13041',
    'summary': 'The mint function of a smart contract implementation for Link Platform (LNK), an Ethereum ERC20 token, has an integer overflow that allows the owner of the contract to set the balance of an arbitrary user to any value.',
    'reference_data': "['https://github.com/dwfault/AirTokens/blob/master/Link_Platform__LNK_/mint%20integer%20overflow.md']",
    'cpes': ['cpe:2.3:a:linktoken_project:linktoken:-:*:*:*:*:*:*:*'],
    'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
    'attack_complexity': 'LOW',
    'confidentiality_impact': 'NONE',
    'integrity_impact': 'HIGH',
    'availability_impact': 'NONE',
    'privileges_required': 'NONE',
    'base_score': '3.9',
    'base_severity': 'CRITICAL',
    'exploitability_score': '3.9',
    'impact_score': '',
    'cpes_logic': "[{'operator': 'OR', 'cpe_match': [{'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:linktoken_project:linktoken:-:*:*:*:*:*:*:*'}]}]"
}
# encode summary
CVE_4 = {
    'id': 'CVE-2020-5230',
    'summary': 'Opencast before 8.1 and 7.6 allows almost arbitrary identifiers for media packages and elements to be used. This can be problematic for operation and security since such identifiers are sometimes used for file system operations which may lead to an attacker being able to escape working directories and write files to other locations. In addition, Opencast\'s Id.toString(?) vs Id.compact(?) behavior, the latter trying to mitigate some of the file system problems , can cause errors due to identifier mismatch since an identifier may unintentionally change. This issue is fixed in Opencast 7.6 and 8.1.',
    'reference_data': "['https://github.com/opencast/opencast/commit/bbb473f34ab95497d6c432c81285efb0c739f317','https://github.com/opencast/opencast/security/advisories/GHSA-w29m-fjp4-qhmq']",
    'cpes': ['cpe:2.3:a:apereo:opencast:*:*:*:*:*:*:*:*', 'cpe:2.3:a:apereo:opencast:8.0:*:*:*:*:*:*:*'],
    'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
    'attack_complexity': 'LOW',
    'confidentiality_impact': 'NONE',
    'integrity_impact': 'HIGH',
    'availability_impact': 'NONE',
    'privileges_required': 'NONE',
    'base_score': '7.5',
    'base_severity': 'HIGH',
    'exploitability_score': '3.6',
    'impact_score': '3.6',
    'cpes_logic': "[{'operator': 'OR', 'cpe_match': [{'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:apereo:opencast:*:*:*:*:*:*:*:*', 'versionEndExcluding': '7.6'}, {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:apereo:opencast:8.0:*:*:*:*:*:*:*'}]}]"
}

CVE_5 = {
    'id': 'CVE-2019-1353',
    'summary': 'An issue was found in Git before v2.24.1, v2.23.1, v2.22.2, v2.21.1, v2.20.2, v2.19.3, v2.18.2, v2.17.3, v2.16.6, v2.15.4, and v2.14.6. When running Git in the Windows Subsystem for Linux (also known as ""WSL"") while accessing a working directory on a regular Windows drive, none of the NTFS protections were active.',
    'reference_data': "['http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00056.html','https://lore.kernel.org/git/xmqqr21cqcn9.fsf@gitster-ct.c.googlers.com/T/#u','https://public-inbox.org/git/xmqqr21cqcn9.fsf@gitster-ct.c.googlers.com/']",
    'cpes': ['cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*','cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*','cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*','cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'cpe:2.3:o:opensuse:leap:15.1:*:*:*:*:*:*:*'],
    'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'attack_complexity': 'LOW',
    'confidentiality_impact': 'HIGH',
    'integrity_impact': 'HIGH',
    'availability_impact': 'HIGH',
    'privileges_required': 'NONE',
    'base_score': '9.8',
    'base_severity': 'CRITICAL',
    'exploitability_score': '3.9',
    'impact_score': '5.9',
    'cpes_logic': "[{'operator': 'OR', 'cpe_match': [{'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'versionStartIncluding': '2.14.0', 'versionEndExcluding': '2.14.6'}, {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'versionStartIncluding': '2.15.0', 'versionEndExcluding': '2.15.4'}, {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'versionStartIncluding': '2.16.0', 'versionEndExcluding': '2.16.6'}, {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'versionStartIncluding': '2.17.0', 'versionEndExcluding': '2.17.3'}, {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'versionStartIncluding': '2.18.0', 'versionEndExcluding': '2.18.2'}, {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'versionStartIncluding': '2.19.0', 'versionEndExcluding': '2.19.3'}, {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'versionStartIncluding': '2.20.0', 'versionEndExcluding': '2.20.2'}, {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'versionStartIncluding': '2.21.0', 'versionEndExcluding': '2.21.1'}, {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'versionStartIncluding': '2.22.0', 'versionEndExcluding': '2.22.2'}, {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'versionStartIncluding': '2.23.0', 'versionEndExcluding': '2.23.1'}, {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*', 'versionStartIncluding': '2.24.0', 'versionEndExcluding': '2.24.1'}]}, {'operator': 'OR', 'cpe_match': [{'vulnerable': True, 'cpe23Uri': 'cpe:2.3:o:opensuse:leap:15.1:*:*:*:*:*:*:*'}]}]"
}

Asset1 = {'product': 'Workspace ONE Intelligent Hub Installer',
          'vendor': 'VMware, Inc.',
          'version': '19.12.2.0',
          'number_of_assets': 4,
          'cpes': "[{'uri': 'cpe:/a:vmware:workspace_one:2.5.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '2.5.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:2.5.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:2.6::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '2.6', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:2.6:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:3.0::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '3.0', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:3.0:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:3.0.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '3.0.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:3.0.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:3.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '3.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:3.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:3.1.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '3.1.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:3.1.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:3.10::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '3.10', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:3.10:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:3.10.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '3.10.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:3.10.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:3.12::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '3.12', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:3.12:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:3.12.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '3.12.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:3.12.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.3::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.3', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.3:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.3.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.3.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.3.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.6::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.6', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.6:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.9::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.9', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.9:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.9.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.9.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.9.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.9.2::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.9.2', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.9.2:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.9.3::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.9.3', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.9.3:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.12::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.12', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.12:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.13::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.13', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.13:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.13.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.13.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.13.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.13.2::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.13.2', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.13.2:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.13.3::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.13.3', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.13.3:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.14::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.14', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.14:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.15::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.15', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.15:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.16::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.16', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.16:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.16.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.16.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.16.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.17::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.17', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.17:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.17.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.17.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.17.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.18::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.18', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.18:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.18.1::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.18.1', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.18.1:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.19::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.19', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.19:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}, {'uri': 'cpe:/a:vmware:workspace_one:4.19.2::~~~iphone_os~~', 'wfn': ""{'part': 'a', 'vendor': 'vmware', 'product': 'workspace_one', 'version': '4.19.2', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'iphone_os', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:vmware:workspace_one:4.19.2:*:*:*:*:iphone_os:*:*', 'product': 'workspace_one', 'vendor': 'vmware'}]"
          }

Asset2 = {'product': 'Git version 2.24.0',
          'vendor': 'The Git Development Community',
          'version': '2.24.0',
          'number_of_assets': 3,
          'cpes': "[{'uri': 'cpe:/a:git:git:2.24.0', 'wfn': ""{'part': 'a', 'vendor': 'git', 'product': 'git', 'version': '2.24.0', 'update': 'ANY', 'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'ANY', 'target_hw': 'ANY', 'other': 'ANY'}"", 'formatted_string': 'cpe:2.3:a:git:git:2.24.0:*:*:*:*:*:*:*', 'product': 'git', 'vendor': 'git'}]"
          }

wfn1 = {'part': 'a', 'vendor': 'The Git Development Community', 'product': 'Git version 2.24.0', 'version': '2.24.0',
        'update': None, 'edition': None, 'language': None, 'sw_edition': None, 'target_sw': None, 'target_hw': None,
        'other': None}


class TestCVEMatcher(unittest.TestCase):

    def setUp(self):
        self.dict_tester = DictTester()
        test_cve_collection = pd.DataFrame([CVE_1, CVE_2, CVE_3, CVE_4, CVE_5])
        print(test_cve_collection)
        test_assets = pd.DataFrame([Asset1, Asset2])
        self.cve_matcher = CVEMatcher(test_assets, test_cve_collection)

    def test_cve_for_wfn(self):
        wfn = {'part': 'a', 'vendor': 'git', 'product': 'git', 'version': '2.24.0',
               'update': 'ANY', 'edition': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'ANY', 'target_hw': 'ANY',
               'other': 'ANY', 'language': 'ANY'}
        match = self.cve_matcher.search_cves_for_wfn(wfn)
        self.assertListEqual(match, ['CVE-2019-1353'])

    def test_create_wfn_from_software_attributes(self):
        wfn_git = self.cve_matcher.create_wfn_from_software_attributes(Asset2)
        self.assertDictEqual(wfn1, wfn_git)

    def test_get_main_version(self):
        version = '2.3.5'
        main_version = get_main_version(version)
        self.assertEqual('2', main_version)

    def test_is_version_any(self):
        ver_any1 = is_version_any('*')
        ver_any2 = is_version_any('ANY')
        ver3 = is_version_any('2.3')
        self.assertTrue(ver_any1)
        self.assertTrue(ver_any2)
        self.assertFalse(ver3)

    def test_get_product_vendor_list(self):
        uri_list = ['cpe:2.3:a:fortinet:fortimanager:*:*:*:*:*:*:*:*', 'cpe:2.3:a:git:git:*:*:*:*:*:*:*:*']
        product_vendor_list = self.cve_matcher.get_product_vendor_list(uri_list)
        self.assertListEqual([('fortimanager', 'fortinet'), ('git', 'git')], product_vendor_list)

    def test_serach_cves_by_product_and_vendor(self):
        wfn_doc = {'part': 'a', 'vendor': 'git', 'product': 'git', 'version': 'ANY', 'update': 'ANY',
                   'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'ANY',
                   'target_hw': 'ANY', 'other': 'ANY'}

        df_result_expected_cve = pd.DataFrame([CVE_5])
        expected_result_list = df_result_expected_cve['id'].tolist()
        df_result_cve = self.cve_matcher.search_cves_by_product_vendor_version(wfn_doc)
        result_list = df_result_cve['id'].tolist()
        self.assertListEqual(result_list, expected_result_list)

        wfn_doc = {'part': 'a', 'vendor': 'apereo', 'product': 'opencast', 'version': '8.0', 'update': 'ANY',
                   'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'ANY',
                   'target_hw': 'ANY', 'other': 'ANY'}
        expected_result_list = ['CVE-2020-5230']
        df_result_cve = self.cve_matcher.search_cves_by_product_vendor_version(wfn_doc)
        result_list = df_result_cve['id'].tolist()
        self.assertListEqual(result_list, expected_result_list)

    def test_search_cves_with_summary(self):
        wfn_doc = {'part': 'a', 'vendor': 'git', 'product': 'git', 'version': 'ANY', 'update': 'ANY',
                   'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'ANY',
                   'target_hw': 'ANY', 'other': 'ANY'}

        expected_result_list = ['CVE-2019-1353']
        df_result = self.cve_matcher.search_cves_with_summary(wfn_doc)
        result_list = df_result['id'].to_list()
        self.assertListEqual(result_list, expected_result_list)
        wfn_doc = {'part': 'a', 'vendor': 'apereo', 'product': 'opencast', 'version': '8.0', 'update': 'ANY',
                   'edition': 'ANY', 'language': 'ANY', 'sw_edition': 'ANY', 'target_sw': 'ANY',
                   'target_hw': 'ANY', 'other': 'ANY'}
        df_result_cve = self.cve_matcher.search_cves_with_summary(wfn_doc)
        self.assertTrue(df_result_cve.empty)


if __name__ == '__main__':
    unittest.main()
