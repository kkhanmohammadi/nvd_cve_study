# nvd_cve_study
empirical_study.py contains statistical study over cves downloaded everyday from NVD feeds and also list of cves for 2020.
cve_matching.py contains the approach for finding matched cves to list of products by studing the summary of every cve report provided by NVD. It used NLP libraries to find nouns in a cve summary, do cleaning over the list of nouns and find matched product names in the cve summary.
