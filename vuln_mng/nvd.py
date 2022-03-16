"""Process, parse, persist NVD vendor and software data.

Purpose
=======

The nvd module ingests the following NIST NVD data:
    * CPE dictionary of vendor and software data.
    * CVE vulnerability data including CVSS data.

The data is parsed and placed in pandas dataframes.

The public classes are container objects used to input, persist, parse, and
process NVD data.

Public classes
==============

NvdCpe          NVD CPE vendor / software dictionary data

                The NVD CPE data base lists standardized vendor names /
                software names & versions. These are referenced by the CVE
                data which lists the actual vulnerabilities.


NvdCve          NVD CVE vulnerability data

"""
import datetime
import json
import os
import re
import sys
import time
import io
import pandas as pd
import requests
import xmltodict as xd
import gbls
import utils
import numpy as np
# Public classes
__all__ = (
    'NvdCpe',
    'NvdCve'
)


class NvdCpe(object):
    """Input, parse, persist NIST NVD vendor/software data.

    The NIST NVD Official Common Platform Enumeration (CPE) Dictionary is a
    structure dataset containing software products published by each vendor.

    From https://nvd.nist.gov/cpe.cfm:

        CPE is a structured naming scheme for information technology systems,
        software, and packages. Based upon the generic syntax for Uniform
        Resource Identifiers (URI), CPE includes a formal name format, a
        method for checking names against a system, and a description format
        for binding text and tests to a name.

    Following is a typical entry from the CPE XML flat file:

    ::

        <cpe-item name="cpe:/a:oracle:jdk:1.7.0:update_60">

            <title xml:lang="en-US">Oracle JDK 1.7.0 Update 60</title>

            <references>
                <reference
                    href="http://www.oracle.com/technetwork/topics/security
                        /cpujul2014-1972956.html">
                    Oracle July 2014 CPU
                </reference>
            </references>

            <cpe-23:cpe23-item
                    name="cpe:2.3:a:oracle:jdk:1.7.0:update_60:*:*:*:*:*:*"/>

        </cpe-item>

    **TL;DR: The CPE dictionary is an XML flat file which gives standardized
    vendor and software names. It also lists the software published by each
    vendor.**

    The I/P data is extracted from the XML flat file and placed in a pandas
    dataframe.

    Methods
    -------
    __init__    Class constructor to configure logging, initialize empty data
                frame

    download_cpe    Download NVD CPE XML dictionary data from the NIST website

    read        Input the NVD CPE dictionary XML file. Clean data and
                remove columns. Extract the nested XML data to form a
                simple pandas dataframe.

    load        Load CPE dataframe from the serialized pickled file.
    save        Save the CPE dataframe to the corresponding pickled file.
    get         Return a *copy* of the CPE dataframe.

    """

    def __init__(self):
        """Initialize class by configuring logging,  initializing dataframe.

        This is the class constructor. It initializes logging and allocates
        an empty dataframe to contain sccm hosts data.

        I/P Parameters
        --------------
        """


        self.df_cpe4 = pd.DataFrame({
            #   Fields in NVD software record
            '@name': [],
            'check': [],
            'cpe-23:cpe23-item': [],
            'notes': [],
            'references': [],
            'title': [],
            'cpe23-item-name': [],

            #   Fields added during processing
            'title_X': [],
            'vendor_X': [],
            'software_X': [],
            'release_X': []
        })

    def download_cpe(self):
        """Download NIST CPE XML dictionary data.

        The CPE dictionary lists known vendors / products in a normalized
        format.

        The NVD CVE ("Common Vulnerabilities and Exposures") XML flat files
        use this dictionary to reference vendors / software data.

        Actions
        -------

            Determine current time. Allocate download directory if it does not
            exist.

            if the file currently exists and is too old, then download / unzip
            a new copy.

        Exceptions
        ----------
        RequestException:   The requests module, used for https access, has
                            several exception conditions.

        Returns
        -------
        None

        """


        # Determine current time
        now = time.time()

        my_cpe = gbls.nvddir + gbls.cpe_filename


        # If CPE dictionary file has already been downloaded

        if os.path.isfile(my_cpe):
            # If CPE file is too old, then download a new copy
            cpe_timestamp = os.path.getmtime(my_cpe)
            cpe_age = (now - cpe_timestamp) / (60 * 60 * 24)

            do_download = cpe_age > gbls.cpe_max_age

        else:
            do_download = True

        if do_download:


            (cpe_filename, cpe_file_contents) = utils.get_zip(gbls.url_cpe)
            if cpe_filename:
                output_cpe = open(my_cpe, 'wb')
                output_cpe.write(cpe_file_contents)
                output_cpe.close()

        return None

    def read(self, my_cpe=None):
        """Read the CPE XML file, parse, and store in pandas dataframe.

        Actions
        -------

        The NVD CPE XML flat file is read. This file documents vendors and
        corresponding published software in a formal, standardized format.

        * The XML file is parsed into a python dictionary. This in turn is
          loaded into a pandas dataframe.

        * The data is cleaned by removing deprecated entries along with
        accompanying columns.

        * The nested "name" data (in the form of an embedded python
          dictionary) is extracted and converted to a pandas dataframe. This
          new dataframe is concatenated to the original dataframe.

        * Entries pertaining to "OS" and "Hardware" are removed.

        * The nested software title information (in the form of an embedded
          python dictionary) is next accessed. Vendor, software name, and
          release data are extracted using pattern matching. The data is added
          to new columns in the pandas dataframe. If the software is released
          in multiple languages, only the en-US version is kept. All of this
          data is added to the dataframe in new columns.

        Exceptions
        ----------
        IOError:    Log an error message and ignore

        Returns
        -------
        None

        """

        if my_cpe is None:
            my_cpe = gbls.nvdcpe



        # read in the uncompressed NVD XML data

        with io.open(my_cpe, 'r', encoding='utf8') as fd:
            data = fd.read()
            dict_cpe = xd.parse(data)#, encoding='utf-8', xml_attribs=True, item_depth=2)
        # convert the python dictionary to a pandas dataframe
        df_cpe = pd.DataFrame.from_dict(
            dict_cpe['cpe-list']['cpe-item']
        )



        # Do an initial cleaning of the data
        # remove deprecated entries
        df_cpe1 = df_cpe[~(df_cpe['@deprecated'] == 'true')]


        # drop the corresponding columns
        df_cpe1.drop(
            ['@deprecated', '@deprecation_date'],
            axis=1,
            inplace=True
        )

        # Extract the embedded 'name' data
        # extract embedded dictionary that has cpe 2.3 name data
        s_cpe_name_dict = df_cpe1['cpe-23:cpe23-item']

        # and convert this to a dataframe
        df_cpe_name = pd.DataFrame(s_cpe_name_dict.tolist())

        # rename column
        df_cpe_name = df_cpe_name.rename(
            columns={'@name': 'cpe23-item-name'}
        )

        # concatenate the two dframes by columns
        df_cpe2 = pd.concat(
            [df_cpe1.reset_index(drop=True), df_cpe_name],
            axis=1,
            join='outer')
        #

        # Remove entries pertaining to 'OS' and 'Hardware'
        # look at applications only. Eliminate 'h' (hardware), 'o' OS
        pattern = re.compile('cpe:2.3:[oh]:', re.IGNORECASE | re.UNICODE)

        df_cpe3 = df_cpe2[
            ~(df_cpe2['cpe23-item-name'].str.contains(pattern))
        ]


        # Extract embedded software title text
        # extract title text (which is also an embedded dictionary in an ... )
        s_cpe_title_dict = df_cpe3['title']

        def myfn4(row):

            # handle case of software with name in multiple languages

            if isinstance(row, list):
                for elt in row:
                    if elt['@xml:lang'] == 'en-US':
                        return elt['#text']
            else:
                return row['#text']

        df_cpe3.loc[:, 'title_X'] = s_cpe_title_dict.apply(myfn4)
        # Extract vendor, software, release information

        pattern = re.compile(
            'cpe:2.3:a:'
            '(?P<vendor_X>[^:]*):'
            '(?P<software_X>[^:]*):'
            '?(?P<release_X>[^:]*):',
            re.IGNORECASE | re.UNICODE)

        df_tmp = df_cpe3['cpe23-item-name'].str.extract(
            pattern,
            expand=False)

        # add the new columns to the main dataframe
        self.df_cpe4 = pd.concat([df_cpe3, df_tmp], axis=1, join='outer')



        return None

    def load(self, my_pck=None):
        """Load CPE dataframe that was previously saved."""

        if my_pck is None:
            my_pck = gbls.df_cpe4_pck

        self.df_cpe4 = pd.read_pickle(my_pck)
        return None

    def save(self):
        """Save CPE dataframe in serialized pickle format."""
        self.df_cpe4.to_pickle(gbls.nvddir+gbls.df_cpe4_pck)
        self.df_cpe4.to_csv(gbls.nvddir+gbls.df_cpe4_csv)

        return None

    def get(self):
        """Return a *copy* of the dataframe."""
        df_tmp = self.df_cpe4.copy()
        return df_tmp


class NvdCve(object):
    """Input, parse, persist NIST CVE vulnerability data.

    The NIST National Vulnerability Database ("NVD") is:

        "the U.S. government repository of standards based vulnerability
        management data."

    From https://nvd.nist.gov/download.cfm:

        XML Vulnerability Feeds - security related software flaws contained
        within XML documents. Each vulnerability in the file includes a
        description and associated reference links from the CVE dictionary
        feed, as well as a CVSS base score, vulnerable product configuration,
        and weakness categorization.

    "CVE" == "Common Vulnerabilities and Exposures". Each CVE entry describes
    "a known vulnerability. Included in the CVE entry are the CVSS scores.

    "CVSS" == "Common Vulnerability Scoring System". This is a set of metrics
    "to assess the severity / impact of a security vulnerability.

    Following is a typical NVD CVE entry from the XML flat file:

    ::

        <entry id="CVE-2015-1683">

            <vuln:vulnerable-configuration id="http://www.nist.gov/">

                <cpe-lang:logical-test operator="OR" negate="false">
                  <cpe-lang:fact-ref name="cpe:/a:microsoft:office:2007:sp3"/>
                </cpe-lang:logical-test>

            </vuln:vulnerable-configuration>

            <vuln:vulnerable-software-list>

                <vuln:product>
                    cpe:/a:microsoft:office:2007:sp3
                </vuln:product>

            </vuln:vulnerable-software-list>

            <vuln:cve-id>CVE-2015-1683</vuln:cve-id>

            <vuln:published-datetime>
                2015-05-13T06:59:14.880-04:00
            </vuln:published-datetime>

            <vuln:last-modified-datetime>
                2015-05-13T11:57:28.013-04:00
            </vuln:last-modified-datetime>

            <vuln:cvss>
              <cvss:base_metrics>

                <cvss:score>9.3</cvss:score>
                <cvss:access-vector>NETWORK</cvss:access-vector>
                <cvss:access-complexity>MEDIUM</cvss:access-complexity>
                <cvss:authentication>NONE</cvss:authentication>

                <cvss:confidentiality-impact>
                    COMPLETE
                </cvss:confidentiality-impact>

                <cvss:integrity-impact>COMPLETE</cvss:integrity-impact>
                <cvss:availability-impact>COMPLETE</cvss:availability-impact>
                <cvss:source>http://nvd.nist.gov</cvss:source>

                <cvss:generated-on-datetime>
                    2015-05-13T11:55:11.580-04:00
                </cvss:generated-on-datetime>

              </cvss:base_metrics>
            </vuln:cvss>

            <vuln:cwe id="CWE-119"/>
            <vuln:references xml:lang="en" reference_type="VENDOR_ADVISORY">
              <vuln:source>MS</vuln:source>

              <vuln:reference
                href="http://technet.microsoft.com/security/bulletin/MS15-046"
                xml:lang="en">

                MS15-046

              </vuln:reference>

            </vuln:references>

            <vuln:summary>
              Microsoft Office 2007 SP3 allows remote attackers to
              execute arbitrary code via a crafted document, aka "Microsoft
              Office Memory Corruption Vulnerability."
            </vuln:summary>

        </entry>

    **TL;DR: The NIST NVD is an standards-based repository of vulnerabilities.
    The vendor and software names can be found in the NIST CPE dictionary.**

    The I/P XML data is parsed, relevant data is extracted and then placed in
    a pandas dataframe.

    Methods
    -------
    __init__    Class constructor to configure logging, initialize empty data
                frame

    download_cve    Download NVD CVE XML feed data from the NIST website

    read        Input the NVD CVE data from the raw XML file. Clean data and
                remove columns. Extract the nested XML data to form a
                simple pandas dataframe.

    load        Load CVE dataframe from the serialized pickled file.
    save        Save the CVE dataframe to the corresponding pickled file and csv file
    get         Return a *copy* of the CVE dataframe.

    """

    def __init__(self, my_logger=None):
        """Initialize class by configuring logging,  initializing dataframe.

        This is the class constructor. It initializes logging and allocates
        an empty dataframe to contain sccm hosts data.

        I/P Parameters
        --------------

        :param my_logger:    logging object. If None, then a new object is initialized.
        """
        # Configure logging

        self.df_cve = pd.DataFrame({
            'id': [],  # 'cve.CVE_data_meta.ID':[],
            'summary': [],  # 'cve.description.description_data':[],  # [{'lang':'','value':''}]
            'reference_data': [],  # cve.references.reference_data:[{'url'}]
            'cpes': [],  # configurations.nodes':[], #[{"operator" : "OR","cpe_match" :
            # [ { "vulnerable" : true,"cpe23Uri" : "cpe:2.3:o:google:android:8.0:*:*:*:*:*:*:*"}]}]
            'vector': [],  # impact.baseMetricV3.cvssV3.vectorString
            'attack_complexity': [],  # 'impact.baseMetricV3.cvssV3.attackComplexity':[],
            'confidentiality_impact': [],  # 'impact.baseMetricV3.cvssV3.confidentialityImpact':[],
            'integrity_impact': [],  # 'impact.baseMetricV3.cvssV3.integrityImpact':[],
            'availability_impact': [],  # 'impact.baseMetricV3.cvssV3.availabilityImpact ':[],
            'privileges_required': [],  # 'impact.baseMetricV3.cvssV3.privilegesRequired ':[],
            'base_score': [],  # 'impact.baseMetricV3.cvssV3.baseScore':[],
            'base_severity': [],  # 'impact.baseMetricV3.cvssV3.baseSeverity':[],
            'exploitability_score': [],  # 'impact.baseMetricV3.exploitabilityScore':[],
            'impact_score': [],  # 'impact.baseMetricV3.impactScore':[],
            'cpes_logic': []
        })

    def download_cve(self):
        """Download NIST CVE XML feed data and store in local directory.

        The NVD CVE ("Common Vulnerabilities and Exposures") XML flat files
        are downloaded. These files list known vulnerabilities.

        The data is supplied as a series of files - one file for each
        year. As vulnerability information is updated, files from previous
        years can be updated depending on when the vulnerability was
        discovered.

        For each year, there is also a small file with "meta" data
        describing the main XML file: Time of last update, file size, hash
        of file contents. NIST's intention is apparently twofold: a) limit
        B/W requirements by avoiding downloads of files that have not
        changed, b) protect integrity of downloaded data.

        Actions
        -------

            Determine current year. Allocate download directory if it does not
            exist.

            For each year to be processed:

                Download that year's meta file.

                Compare meta file contents with previous meta file (if it
                exists)

                If meta file contents have changed, then download the updated
                XML Feed file.

                The XML file is unzipped and stored in the download directory.

        Exceptions
        ----------
        RequestException:   The requests module, used for https access, has
                            several exception conditions.

        Returns
        -------
        None

        """

        # Determine current year
        now = datetime.datetime.now()
        my_yr = now.year

        # Process cve files for last "n" years

        for index in range(gbls.num_nvd_files):
            yr_processed = my_yr - index

            # get the meta file for the year being processed
            url_meta = (
                    gbls.url_meta_base
                    + str(yr_processed)
                    + gbls.url_meta_end
            )
            try:
                resp = requests.get(url_meta)

            except requests.exceptions.RequestException as e:
                continue

            meta_filename = (
                    gbls.nvddir
                    + gbls.nvd_meta_filename
                    + str(yr_processed)
            )

            # if file already exists then read the contents

            if os.path.isfile(meta_filename):
                meta_filecontents = open(meta_filename, 'r', encoding="utf-8").read()

                # read updated xml feed file since corresponding meta file
                # contents have changed.

                if meta_filecontents == resp.text:

                    continue
                else:
                    print('file read from nvd')
            else:
                print('\nMeta file does not exist:{0}'.format( meta_filename) )


            # save new / updated meta file to disk

            output_meta = open(meta_filename, 'w')
            output_meta.write(resp.text)
            output_meta.close()

            # Read the new json feed file
            if gbls.url_json_middle == '':
                url_json = (
                        gbls.url_json_base
                        + str(yr_processed)
                        + gbls.url_json_end
                )
            else:
                url_json = (
                        gbls.url_json_base
                        + gbls.url_json_middle
                        + gbls.url_json_end
                ) ### need to change

            (json_filename, json_filecontents) = utils.get_zip(url_json)

            # write this new / updated json feed file to disk as well

            if json_filename:
                # hardcode the filenames to avoid problems if NIST changes
                # names

                my_cve_filename = (
                        gbls.nvdcve
                        + str(yr_processed)
                        + '.json'
                )

                print(
                    '\nSaving Json file I/P {0} as {1}\n\n'.format(
                        json_filename,
                        my_cve_filename
                    )
                )

                output_json = open(my_cve_filename, 'wb')
                output_json.write(json_filecontents)
                output_json.close()
        return None

    def read(self, my_dir=None):
        """Read the CVE Json file, parse, and store in pandas dataframe.

        Actions
        -------

        The NVD CVE ("Common Vulnerabilities and Exposures") Json flat file is
        read. This file contains a list of known vulnerabilities. The vendor
        and software names can be found in the NIST CPE dictionary.

        * The data is supplied in a series of files. There is one file for
          each year. As vulnerability information is updated, files from
          previous years can be updated depending on when the vulnerability
          was discovered.

          Each files is read, parsed into a python dictionary, then converted
          to a pandas dataframe.

          All of these individual data frames are appended to form one
          dataframe.

        * The data is cleaned by eliminating null entries.

        * The nested Json data is painstakingly extracted. The data from the
          corresponding python dictionaries and lists is used to populate new
          columns in the main pandas dataframe.   loaded into a pandas
          dataframe.

        *  The data is cleaned further by removing "OS" and "Hardware"
           entries. Extraneous columns are also dropped.

        *  The CVSS ("Common Vulnerability Scoring System" data in the CVE
           entry is extracted and used to populate additional columns in the
           dataframe.

        Exceptions
        ----------
        IOError:    Log an error message and ignore

        Returns
        -------
        None

        """
        print('\n\nEntering NvdCve.read\n\n')

        # Read in the uncompressed NVD XML data
        try:
            if my_dir is None:
                my_dir = gbls.nvddir

            # List directory contents

            f = []

            for (dir_path, dir_names, file_names) in os.walk(my_dir):
                f.extend(file_names)
                break

            # Iterate through the cve files

            for my_file in f:

                # skip the cpe dictionary if it is there

                if not my_file.startswith(gbls.cve_filename):
                    continue

                my_file1 = my_dir + my_file

                print(
                    '\nReading {0}\n\n'.format(
                        my_file1
                    )
                )

                with open(my_file1, encoding="utf8") as fd:
                    cve_dict = json.loads(fd.read())

                df_cve_items = pd.json_normalize(cve_dict['CVE_Items'])

                #save csv for pass 1 days
                yesterday = datetime.date.today() + datetime.timedelta(days=-1)
                df_cve_items_7_days= df_cve_items.copy()
                df_cve_items_7_days['Date'] = df_cve_items_7_days['lastModifiedDate'].map(lambda x: datetime.datetime.strptime(x, '%Y-%m-%dT%H:%MZ').date())

                df_cve_items_7_days = df_cve_items_7_days[
                    df_cve_items_7_days['Date'] >= yesterday]
                today = datetime.date.today()
                df_cve_items_7_days.to_csv("C:/nvd/df_cve_all_modified_1day_" + today.strftime("%Y-%m-%d") + ".csv")

                # get cves for yesterday
                yesterday = datetime.date.today() + datetime.timedelta(days=-1)
                df_cve_items = df_cve_items[
                    df_cve_items['lastModifiedDate'].str[:10] == yesterday.strftime("%Y-%m-%d")]


                self.df_cve[['id', 'vector', 'attack_complexity', 'confidentiality_impact', 'integrity_impact',
                             'availability_impact', 'privileges_required', 'base_score', 'base_severity',
                             'exploitability_score', 'impact_score', 'cpes_logic']] = \
                    df_cve_items[['cve.CVE_data_meta.ID', 'impact.baseMetricV3.cvssV3.vectorString',
                                  'impact.baseMetricV3.cvssV3.attackComplexity',
                                  'impact.baseMetricV3.cvssV3.confidentialityImpact',
                                  'impact.baseMetricV3.cvssV3.integrityImpact',
                                  'impact.baseMetricV3.cvssV3.availabilityImpact',
                                  'impact.baseMetricV3.cvssV3.privilegesRequired',
                                  'impact.baseMetricV3.cvssV3.baseScore',
                                  'impact.baseMetricV3.cvssV3.baseSeverity',
                                  'impact.baseMetricV3.exploitabilityScore', 'impact.baseMetricV3.impactScore',
                                  'configurations.nodes']]
                self.df_cve['summary'] = df_cve_items.apply(
                    lambda x: pd.DataFrame(x['cve.description.description_data'])[
                        'value'].to_list() if not pd.DataFrame(x['cve.description.description_data']).empty else [],
                    axis=1)

                self.df_cve['reference_data'] = df_cve_items.apply(
                    lambda x: pd.DataFrame(x['cve.references.reference_data'])['url'].to_list() if not pd.DataFrame(
                        x['cve.references.reference_data']).empty else [], axis=1)

                self.df_cve['cpes'] = df_cve_items['configurations.nodes'].apply(
                    lambda x: re.findall('\'cpe23Uri\': \'(.+?)\'', str(x)))

        except IOError as e:
            print('\n\n***I/O error({0}): {1}\n\n'.format(
                e.errno, e.strerror))
        except:
            print(
                '\n\n***Unexpected error: {0}\n\n'.format(
                    sys.exc_info()[0]))
            raise

        print(
            '\n\nNVD CVE raw data input counts: \n{0}\n{1}\n\n'.format(
                self.df_cve.shape,
                self.df_cve.columns
            )
        )

        return None

    def load(self, my_pck=None):
        """Load NvdCve vulnerability dataframe that was previously saved."""
        print(
            '\n\nLoading saved CVE data into '
            'NvdCve.df_cve dataframe\n\n'
        )
        if my_pck is None:
            my_pck = gbls.df_cve_pck

        self.df_cve = pd.read_pickle(my_pck)
        return None

    def save(self):
        """Save NvdCpe vuln dataframe in serialized pickle format and csv format"""
        yesterday = datetime.date.today() + datetime.timedelta(days=-1)
        print('\n\nSaving NvdCve.df_cve dataframe\n\n')
        self.df_cve.to_pickle(gbls.nvddir + gbls.df_cve+"_modofied_"+yesterday.strftime("%Y-%m-%d")+".pck")
        self.df_cve.to_csv(gbls.nvddir + gbls.df_cve + "_modofied_"+yesterday.strftime("%Y-%m-%d")+".csv")
        return None

    def save_to_csv(self):
        yesterday = datetime.date.today() + datetime.timedelta(days=-1)
        self.df_cve.to_csv(gbls.nvddir + gbls.df_cve + "_modofied_"+yesterday.strftime("%Y-%m-%d")+".csv")

        return None

    def get(self):
        """Return a *copy* of the data."""
        df_tmp = self.df_cve.copy()
        print(
            '\n\nGet NvdCve.df_cve: \n{0}\n{1}\n\n'.format(
                df_tmp.shape,
                df_tmp.columns
            )
        )
        return df_tmp
