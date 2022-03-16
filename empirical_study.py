import os
import platform
import shutil
import re
import gbls
from nvd import NvdCpe, NvdCve
import time
import datetime
import sys
import pandas as pd
import numpy as np
import requests
from ast import literal_eval
import stanza # stanza.download('en','C:/Users/kobrakhanmohammadi/stanza_resources')



def get_summary_statistics(dataset):
    mean = np.round(np.mean(dataset), 2)
    median = np.round(np.median(dataset), 2)
    min_value = np.round(dataset.min(), 2)
    max_value = np.round(dataset.max(), 2)
    quartile_1 = np.round(dataset.quantile(0.25), 2)
    quartile_3 = np.round(dataset.quantile(0.75), 2)
    # Interquartile range
    iqr = np.round(quartile_3 - quartile_1, 2)
    print('Min: %s' % min_value)
    print('Mean: %s' % mean)
    print('Max: %s' % max_value)
    print('25th percentile: %s' % quartile_1)
    print('Median: %s' % median)
    print('75th percentile: %s' % quartile_3)
    print('Interquartile range (IQR): %s' % iqr)
def read_all_files(): #reading all cves downloaded everyday from nvd feeds
    df_all_cves=pd.DataFrame()
    basepath = 'C:/nvd/'
    with os.scandir(basepath) as entries:
        for entry in entries:
            if entry.is_file():
                if entry.name.startswith('df_cve_all_modified_1day'):
                    print(entry.name)
                    df_cves = pd.read_csv("C:/nvd/"+entry.name)
                    df_all_cves = pd.concat([df_all_cves, df_cves])
                    df_all_cves.drop_duplicates(keep="first", inplace=True)
    df_all_cves.to_csv("C:/nvd/df_all_cves.csv")
    return
def find_vendors():
    df_cves = pd.read_csv("C:/nvd/df_all_cves.csv")
    df_cves['vendors'] = df_cves['configurations.nodes'].apply(
        lambda x: list(set(re.findall('\'cpe:2.3:a:(.+?):', str(x)))))
    df_cves_1 = df_cves.drop_duplicates(subset=['cve.CVE_data_meta.ID'], keep="first")
    df_cves_2 = df_cves.drop_duplicates(subset=['cve.CVE_data_meta.ID'], keep="last")
    df_merge = pd.merge(df_cves_1, df_cves_2, how='left', left_on='cve.CVE_data_meta.ID', right_on='cve.CVE_data_meta.ID')
    df_with_initial_cpe=df_merge[df_merge['vendors_x'].apply(len).gt(0)] #7148
    df_with_update_cpe=df_merge[df_merge['vendors_y'].apply(len).gt(0) & df_merge['vendors_x'].apply(len).eq(0)] #2248
    list_vendors_with_initial_cpe = df_with_initial_cpe.vendors_x.sum()#7820
    list_vendors_with_update_cpe = df_with_update_cpe.vendors_y.sum()#2319


    from collections import Counter
    import matplotlib.pyplot as plt
    counts_vendors_with_initial_cpe = Counter(list_vendors_with_initial_cpe)
    counts_vendors_with_update_cpe = Counter(list_vendors_with_update_cpe)
    common = counts_vendors_with_initial_cpe.most_common(20)
    labels = [item[0] for item in common]
    number = [item[1] for item in common]
    nbars = len(common)

    plt.bar(np.arange(nbars), number, tick_label=labels)
    plt.xticks(rotation=90)
    plt.xlabel('Vendors')
    plt.ylabel('Number of Vulnerabilities')
    plt.tight_layout()
    plt.show()

    counts_vendors_with_update_cpe = Counter(list_vendors_with_update_cpe)
    common = counts_vendors_with_update_cpe.most_common(20)
    df_common_vendors_with_initial_cpe = pd.DataFrame.from_dict(common)

    '''
    get_summary_statistics(df_common_vendors_with_initial_cpe[1])
    Min: 38
    Mean: 183.6
    Max: 713
    25th percentile: 61.5
    Median: 105.5
    75th percentile: 318.0
    Interquartile range (IQR): 256.5
        '''
    labels = [item[0] for item in common]
    number = [item[1] for item in common]
    nbars = len(common)

    plt.bar(np.arange(nbars), number, tick_label=labels, color=['blue'])
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

    dict_vendors_with_initial_cpe = dict(counts_vendors_with_initial_cpe)
    dict_vendors_with_update_cpe = dict(counts_vendors_with_update_cpe)
    df_vendors_with_initial_cpe = pd.DataFrame.from_dict(list(dict_vendors_with_initial_cpe.items()))
    df_vendors_with_update_cpe = pd.DataFrame.from_dict(list(dict_vendors_with_update_cpe.items()))
    df_vendors_with_update_cpe.rename(columns={0: 'vendor', 1:'vul_no'}, inplace=True)
    df_vendors_with_initial_cpe.rename(columns={0: 'vendor', 1:'vul_no'}, inplace=True)
    df_vendor_merge = pd.merge(df_vendors_with_initial_cpe, df_vendors_with_update_cpe, how='left', left_on='vendor', right_on='vendor')
    df_vendor_merge = df_vendor_merge.fillna(0)
    df_vendor_merge['average_no_score'] = df_vendor_merge['vul_no_y'] / (
                df_vendor_merge['vul_no_x'] + df_vendor_merge['vul_no_y'])
    df_vendor_merge['average_no_score'] = df_vendor_merge['average_no_score'] * 100
    df_vendor_merge['average_score'] = df_vendor_merge['vul_no_x'] / (
                df_vendor_merge['vul_no_x'] + df_vendor_merge['vul_no_y'])
    df_vendor_merge['average_score'] = df_vendor_merge['average_score'] * 100

    boxplot = df_vendor_merge.boxplot(column='average')
    '''
    get_summary_statistics(df_vendor_merge['average_no_score'])
    Min: 0.0
    Mean: 6.69
    Max: 92.86
    25    th    percentile: 0.0
    Median: 0.0
    75    th    percentile: 0.0
    Interquartile
    range(IQR): 0.0
    get_summary_statistics(df_vendor_merge['average_score'])
    Min: 7.14
    Mean: 93.31
    Max: 100.0
    25    th    percentile: 100.0
    Median: 100.0
    75    th    percentile: 100.0
    Interquartile
    range(IQR): 0.0
    '''
    df_top_no_score=df_vendor_merge.nlargest(20,['average_no_score'])


    common_vendors_with_update_cpe = counts_vendors_with_update_cpe.most_common(20)
    common_vendors_with_initial_cpe = counts_vendors_with_initial_cpe.most_common(20)
    df_common_vendors_with_initial_cpe = pd.DataFrame.from_dict(common_vendors_with_initial_cpe)
    df_common_vendors_with_update_cpe = pd.DataFrame.from_dict(common_vendors_with_update_cpe)
    df_common_vendors_with_initial_cpe.rename(columns={0: 'vendor', 1: 'vul_no'}, inplace=True)
    df_common_vendors_with_update_cpe.rename(columns={0: 'vendor', 1: 'vul_no'}, inplace=True)

    df_merge_common_vendors_with_update_cpe =pd.merge(df_common_vendors_with_update_cpe,df_vendors_with_initial_cpe, how='left', left_on='vendor', right_on='vendor')
    df_merge_common_vendors_with_update_cpe['average'] = df_merge_common_vendors_with_update_cpe['vul_no_y'] / (
                df_merge_common_vendors_with_update_cpe['vul_no_x'] + df_merge_common_vendors_with_update_cpe['vul_no_y'])
    df_merge_common_vendors_with_update_cpe['average']=df_merge_common_vendors_with_update_cpe['average']*100
    df_merge_common_vendors_with_update_cpe = df_merge_common_vendors_with_update_cpe.fillna(0)
    get_summary_statistics(df_merge_common_vendors_with_update_cpe['average'] )
    '''
    Min: 7.14
    Mean: 55.63
    Max: 95.07
    25th percentile: 29.4
    Median: nan
    75th percentile: 81.77
    Interquartile range (IQR): 52.37
    '''
    df_with_initial_cve=df_cves_1[df_cves_1['vendors'].apply(len).gt(0)]
    list_vendors_with_initial_cve = df_with_initial_cve.vendors.sum()
    counts_vendors_with_initial_cve = Counter(list_vendors_with_initial_cve)
    dict_vendors_with_initial_cve = dict(counts_vendors_with_initial_cve)
    df_vendors_with_initial_cve = pd.DataFrame.from_dict(list(dict_vendors_with_initial_cve.items()))
    df_vendors_with_initial_cve.rename(columns={0: 'vendor', 1: 'vul_no'}, inplace=True)

    df_merge_common_vendors_with_initial_cve = pd.merge(df_common_vendors_with_initial_cpe, df_vendors_with_update_cpe,how='left', left_on='vendor', right_on='vendor')

    df_merge_common_vendors_with_initial_cve['average'] = df_merge_common_vendors_with_initial_cve['vul_no_x'] / (
                    df_merge_common_vendors_with_initial_cve['vul_no_x'] + df_merge_common_vendors_with_initial_cve['vul_no_y'])
    df_merge_common_vendors_with_initial_cve['average']=df_merge_common_vendors_with_initial_cve['average']*100
    df_merge_common_vendors_with_initial_cve = df_merge_common_vendors_with_initial_cve.fillna(0)
    get_summary_statistics(df_merge_common_vendors_with_initial_cve['average'] )
    '''
    Min: 0.0
    Mean: 78.73
    Max: 97.7
    25th percentile: 81.61
    Median: 87.74
    75th percentile: 92.43
    Interquartile range (IQR): 10.82
    '''
    df_merge_common_vendors_with_update_cve = pd.merge(df_common_vendors_with_update_cpe, df_vendors_with_update_cpe,how='left', left_on='vendor', right_on='vendor')

    df_merge_all_vendors_withinital_withupdate = pd.merge(df_vendors_with_initial_cpe, df_vendors_with_update_cpe,how='left', left_on='vendor', right_on='vendor')
    df_merge_all_vendors_withinital_withupdate = df_merge_all_vendors_withinital_withupdate.fillna(0)

    df_merge_all_vendors_withinital_withupdate = pd.merge(df_vendors_with_initial_cpe, df_vendors_with_update_cpe,how='left', left_on='vendor', right_on='vendor')
    df_merge_all_vendors_withinital_withupdate = df_merge_all_vendors_withinital_withupdate.fillna(0)
    ...
    df_merge_all_vendors_withinital_withupdate.to_csv('c:/nvd/vendors_cveswithinitialscore_cveswithoutinitialscore.csv')
    df_merge_all_vendors_withinital_withupdate['average'] = df_merge_all_vendors_withinital_withupdate['vul_no_y'] / (
    df_merge_all_vendors_withinital_withupdate['vul_no_x'] + df_merge_all_vendors_withinital_withupdate['vul_no_y'])

    df_merge_all_vendors_withinital_withupdate['average']=df_merge_all_vendors_withinital_withupdate['average']*100

    df_merge_all_vendors_withinital_withupdate = df_merge_all_vendors_withinital_withupdate.fillna(0)

    get_summary_statistics(df_merge_all_vendors_withinital_withupdate['average'] )
    '''
    Min: 0.0
    Mean: 6.69
    Max: 92.86
    25th percentile: 0.0
    Median: 0.0
    75th percentile: 0.0
    Interquartile range (IQR): 0.0
    '''


    #
    # df_without_initial_cve=df_cves_1[df_cves_1['vendors'].apply(len).eq(0)]
    # list_vendors_without_initial_cve = df_without_initial_cve.vendors.sum()
    # counts_vendors_without_initial_cve = Counter(list_vendors_without_initial_cve)
    # dict_vendors_without_initial_cve = dict(counts_vendors_without_initial_cve)
    # df_vendors_without_initial_cve = pd.DataFrame.from_dict(list(dict_vendors_without_initial_cve.items()))
    # df_vendors_without_initial_cve.rename(columns={0: 'vendor', 1: 'vul_no'}, inplace=True)

    df_merge_common_vendors_with_initial_cpe = pd.merge(df_common_vendors_with_initial_cpe, df_vendors_with_initial_cve,how='left', left_on='vendor', right_on='vendor')


    list_all_vendors_first_report = df_cves_1.vendors.sum()
    counts_all_vendors_first_report = Counter(list_all_vendors_first_report)
    dict_vendors_with_initial_cpe = dict(counts_all_vendors_first_report)
    df_all_vendors_first_report = pd.DataFrame.from_dict(list(counts_all_vendors_first_report.items()))
    df_all_vendors_first_report.rename(columns={0: 'vendor', 1: 'vul_no'}, inplace=True)
    df_merge_common_vendors_with_initial_cpe = pd.merge(df_common_vendors_with_initial_cpe, df_all_vendors_first_report,
                                                        how='left', left_on='vendor', right_on='vendor')

    '''
    get_summary_statistics(df_common_vendors_with_initial_cpe['vul_no'] )
    Min: 38
    Mean: 183.6
    Max: 713
    25th percentile: 61.5
    Median: 105.5
    75th percentile: 318.0
    Interquartile range (IQR): 256.5
    
    '''
    my_dict = {'All Vendors': df_vendor_merge['average'], 'Top 20 Vendors': df_merge_common_vendors_with_update_cpe['average']}

    fig, ax = plt.subplots()
    ax.boxplot(my_dict.values(), showfliers =False)
    ax.set_xticklabels(my_dict.keys())
    plt.tight_layout()

    from scipy.stats import mannwhitneyu
    stat, p = mannwhitneyu(df_vendor_merge['average'], df_merge_common_vendors_with_update_cpe['average'])
    print('Statistics=%.3f, p=%.3f' % (stat, p))
    # interpret
    alpha = 0.05
    if p > alpha:
        print('Same distribution (fail to reject H0)')
    else:
        print('Different distribution (reject H0)')
        '''
        p=2.7633177172506037e-22
        Statistics=2828.500, p=0.0000
    Different distribution (reject H0)
        '''

    a=[17,49,30,4]
    b=[13,45,40,2]
    stat, p = mannwhitneyu(a, b)

    count_common_vendor_initial = counts_vendors_with_initial_cpe.most_common(20)
    labels = [item[0] for item in common]
    number = [item[1] for item in common]
    nbars = len(common)



def find_duration_till_geting_cvss():
    df_cves = pd.read_csv("C:/nvd/df_all_cves.csv")
    df_cves_1 = df_cves.drop_duplicates(subset=['cve.CVE_data_meta.ID'], keep="first")
    #                df_cve_items_7_days['Date'] = df_cve_items_7_days['lastModifiedDate'].map(lambda x: datetime.datetime.strptime(x, '%Y-%m-%dT%H:%MZ').date())

    df_cves_2 = df_cves.drop_duplicates(subset=['cve.CVE_data_meta.ID'], keep="last")
    df_merge = pd.merge(df_cves_1, df_cves_2, how='left', left_on='cve.CVE_data_meta.ID', right_on='cve.CVE_data_meta.ID')
    df_merge['Date_X'] = pd.to_datetime(df_merge['Date_x'], format='%Y-%m-%d')
    df_merge['Date_Y'] = pd.to_datetime(df_merge['Date_y'], format='%Y-%m-%d')
    df_merge['Date_p'] = df_merge['publishedDate_x'].map(lambda x: datetime.datetime.strptime(x, '%Y-%m-%dT%H:%MZ').date())
    df_merge['Date_p'] = pd.to_datetime(df_merge['Date_p'], format='%Y-%m-%d')
    df_merge['Date_difference_p'] = (df_merge['Date_X'] - df_merge['Date_p']).dt.days
    '''
    p1 = df_merge[(df_merge['Date_difference_p'] != 0) & (df_merge['impact.baseMetricV3.cvssV3.baseSeverity_x'].isnull())]
    p2 = p1[~p1['impact.baseMetricV2.cvssV2.baseScore_x'].isnull()]
    df_merge = p1[~p1['impact.baseMetricV2.cvssV2.baseScore_x'].isnull()]
    '''
    df_merge=df_merge.drop(df_merge[(df_merge['Date_difference_p'] != 0) & (df_merge['impact.baseMetricV3.cvssV3.baseSeverity_x'].isnull()) & (~df_merge['impact.baseMetricV2.cvssV2.baseScore_x'].isnull())].index)

    df_merge['Date_difference'] = (df_merge['Date_Y'] - df_merge['Date_p']).dt.days
    df_merge1 = df_merge[df_merge['Date_difference'] != 0] #3612
    boxplot = df_merge1.boxplot(column='Date_difference')
    get_summary_statistics(df_merge1['Date_difference'])
    '''
    p1=df_merge[(df_merge['Date_difference_p']!=0) & (df_merge['impact.baseMetricV3.cvssV3.baseSeverity_x'].isnull())]
    p2=p1[p1['impact.baseMetricV2.cvssV2.baseScore_x'].isnull()]
    get_summary_statistics(p2['Date_difference'])
    Min: 0
    Mean: 5.42
    Max: 75
    25th percentile: 0.0
    Median: 1.0
    75th percentile: 8.0
    Interquartile range (IQR): 8.0
    get_summary_statistics(p2['Date_difference_p'])
    Min: 1
    Mean: 2.24
    Max: 148
    25th percentile: 1.0
    Median: 1.0
    75th percentile: 2.0
    Interquartile range (IQR): 1.0
    p3=p1[~p1['impact.baseMetricV2.cvssV2.baseScore_x'].isnull()]
    get_summary_statistics(p3['Date_difference_p'])
    Min: 2008
    Mean: 3954.77
    Max: 8878
    25th percentile: 2247.0
    Median: 3442.0
    75th percentile: 5091.5
    Interquartile range (IQR): 2844.5
    '''
    df_cves_1_nan = df_cves_1[df_cves_1['impact.baseMetricV3.cvssV3.baseSeverity'].isnull()] #5270
    df_merge1_y_nan = df_merge1[df_merge1['impact.baseMetricV3.cvssV3.baseSeverity_y'].isnull()] #453 never updated

    df_cves_1_cpe_nan = df_cves_1[df_cves_1['configurations.nodes'] == '[]']#5128
    df_merge1_cpe_nan = df_merge1[df_merge1['configurations.nodes_y'].isnull()] #270
    df_merge1_cpe = df_merge1[df_merge1['configurations.nodes_y'] != '[]']
    '''
    get_summary_statistics(df_merge1_cpe['Date_difference'])
    Min: 1
    Mean: 14.55
    Max: 113
    25th percentile: 5.0
    Median: 8.0
    75th percentile: 13.0
    Interquartile range (IQR): 8.0
        '''
    '''
    df_merge1_y_nan = df_merge1[df_merge1['impact.baseMetricV3.cvssV3.baseSeverity_y'].isnull()]  # 334
    df_merge1_x_no_y_nan = df_merge1[(df_merge1['impact.baseMetricV3.cvssV3.baseSeverity_x'].isnull())&(~df_merge1['impact.baseMetricV3.cvssV3.baseSeverity_y'].isnull())]  # 453 never updated
    get_summary_statistics(df_merge1_x_no_y_nan['Date_difference'])#2524
    Min: 1
    Mean: 11.62
    Max: 106
    25th percentile: 6.0
    Median: 8.0
    75th percentile: 11.0
    Interquartile range (IQR): 5.0
    '''
    '''
    df_merge['Date_difference_Y_X'] = (df_merge['Date_Y'] - df_merge['Date_X']).dt.days
    df_merge1 = df_merge[df_merge['Date_difference_Y_X'] != 0]
    df_merge1_cpe_xnan_y = df_merge1[(df_merge1['configurations.nodes_y'] == '[]') & (df_merge1['configurations.nodes_y'] != '[]')]
    df_merge1_cpe_xnan_y = df_merge1[(df_merge1['configurations.nodes_x'] == '[]') & (df_merge1['configurations.nodes_y'] != '[]')]
    get_summary_statistics(df_merge1_cpe_xnan_y['Date_difference'])
    Min: 1
    Mean: 11.62
    Max: 106
    25th percentile: 6.0
    Median: 8.0
    75th percentile: 11.0
    Interquartile range (IQR): 5.0
    '''
    '''
    df_merge1_cpe_nan = df_merge1[(df_merge1['configurations.nodes_y']!='[]')&(df_merge1['configurations.nodes_x']=='[]')]
    get_summary_statistics(df_merge1_cpe_nan['Date_difference']) #2653 df_merge1=12507 df_merge2=14493
    Min: 1
    Mean: 11.61
    Max: 106
    25th percentile: 6.0
    Median: 8.0
    75th percentile: 11.0
    Interquartile range (IQR): 5.0
    '''


    '''
    Min: 1
    Mean: 13.58
    Max: 113
    25th percentile: 4.0
    Median: 8.0
    75th percentile: 12.0
    Interquartile range (IQR): 8.0
    '''
    a = df_merge1.groupby(by=['impact.baseMetricV3.cvssV3.baseSeverity_y']).count()
    a = a.reset_index()

    ''' y second update
    CRITICAL     425   13%
    HIGH    1434   45%
    LOW     81   2%
    MEDIUM   1338   40%
    
    3278
        '''
    ''' x: initially reported
    CRITICAL    124 %17
    HIGH        373 %49
    LOW          28  %4
    MEDIUM      232 %30
    
    757
    '''


def cves_no_severity_box_plot():
    df_cves = pd.read_csv("C:/nvd/df_all_cves.csv")  #40813   #df_cve_all_modified_7day_2021-05-27.csv")
    df_cves.head()
    df_cves_no_severity = df_cves[df_cves['impact.baseMetricV3.cvssV3.baseSeverity'].isna()] #11473
    count_date = df_cves_no_severity.groupby(by='Date').count()# cve.CVE_data_meta.ID
    count_date['lastModifiedDate']
    count_date.fillna(0)
    count_date.rename(columns={'lastModifiedDate': 'Last Modified Date'}, inplace=True)
    boxplot = count_date.boxplot(column=['Last Modified Date'], grid=False, showfliers=False)
    # print("median:"+count_date.median()['Last Modified Date'])#15.5
    # print("25th percentage:"+count_date.quantile(0.25)['Last Modified Date'])
    # print("75th percentage:"+count_date.quantile(0.75)['Last Modified Date'])
    # print("min:"+count_date.min()['Last Modified Date'])
    # print("max:" + count_date.max()['Last Modified Date'])
    get_summary_statistics(count_date['Last Modified Date'])
    '''
    Min: 1
    Mean: 139.91
    Max: 802
    25th percentile: 20.5
    Median: 71.5
    75th percentile: 200.0
    Interquartile range (IQR): 179.5
    '''
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(12, 7))
    # Remove top and right border
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    # Remove y-axis tick marks
    ax.yaxis.set_ticks_position('none')
    # Add major gridlines in the y-axis
    ax.grid(color='grey', axis='y', linestyle='-', linewidth=0.25, alpha=0.5)
    # Set plot title
    #ax.set_title('Distribution of petal length by species')
    # Set species names as labels for the boxplot
    # dataset = [setosa_petal_length, versicolor_petal_length, virginica_petal_length]
    # labels = iris_df['species_name'].unique()
    ax.boxplot(count_date['Last Modified Date'])#,labels=['Number of CVEs'])
    plt.show()
    return
def cves_no_cpe_box_plot():
    df_cves = pd.read_csv("C:/nvd/df_cve_all_modified.csv")
    df_cves.head()
    df_cves_no_cpe = df_cves[df_cves['configurations.nodes']=='[]']#10965
    count_date = df_cves_no_cpe.groupby(by='Date').count()
    #count_date['lastModifiedDate']
    count_date.rename(columns={'lastModifiedDate': 'Last Modified Date'}, inplace=True)
    boxplot = count_date.boxplot(column=['Last Modified Date'])
    get_summary_statistics(count_date['Last Modified Date'])
    return

def cves_no_references_box_plot():
    df_cves = pd.read_csv("C:/nvd/df_cve_all_modified_7day_2021-05-27.csv")
    df_cves.head()
    df_cves_no_ref = df_cves[df_cves['cve.references.reference_data']=='[]']
    count_date = df_cves_no_ref.groupby(by='Date').count()
    #count_date['lastModifiedDate']
    count_date.rename(columns={'lastModifiedDate': 'Last Modified Date'}, inplace=True)
    boxplot = count_date.boxplot(column=['Last Modified Date'])
    get_summary_statistics(count_date['Last Modified Date'])
    return

def cves_priority_distribution():
    df_cves = pd.read_csv("C:/nvd/df_cve_all_items_2020.csv")
    df_cves.head()
    #distribution of base_severity per day
    df_cves['Last Modified Date'] = df_cves['lastModifiedDate'].str[:10]
    df_cves = df_cves.fillna('Not Specified')
    df_cves = df_cves[df_cves['lastModifiedDate'].str[:4]=='2020']
    a = df_cves.groupby(by=['Last Modified Date', 'impact.baseMetricV3.cvssV3.baseSeverity']).count()
    a=a.reset_index()
    a = a.rename(columns={'Unnamed: 0': 'count'})
    a=a.rename(columns={'impact.baseMetricV3.cvssV3.baseSeverity':'CVSSV3 Base Score'})
    a.boxplot(by='CVSSV3 Base Score', column=['count'])
    b = a.groupby('Base Severity')
    print(b.groups.keys())# dict_keys(['CRITICAL', 'HIGH', 'LOW', 'MEDIUM', 'Not Specified'])
    get_summary_statistics(b.get_group('CRITICAL')['count'])
    get_summary_statistics(b.get_group('HIGH')['count'])
    get_summary_statistics(b.get_group('MEDIUM')['count'])
    get_summary_statistics(b.get_group('LOW')['count'])
    get_summary_statistics(b.get_group('Not Specified')['count'])

class cve_product_comp:
    def cves_summary_product(self):
        df_cves = pd.read_csv("C:/nvd/df_cve_all_items_2020.csv")
        # df_cves.head()
        # stanza.download('en', 'C:/Users/kobrakhanmohammadi/stanza_resources1')  # added to use stanza package
        # self.nlp = stanza.Pipeline('en', processors='tokenize,pos',
        #                       dir='C:/Users/kobrakhanmohammadi/stanza_resources1')
        # df_cves['summary_list'] = df_cves['cve.description.description_data'].apply(lambda x: literal_eval(x))
        # df_cves['summary'] = df_cves['summary_list'].apply(lambda x: x[0]['value'])
        # df_cves['summary_nouns'] = df_cves['summary'].apply(lambda x: self.extract_stanza_nouns(x))
        #
        # df_cves.to_csv('C:/nvd/feeds/df_cves2020_summary_noun.csv')
        df_cves['cpes'] = df_cves['configurations.nodes'].apply(
            lambda x: re.findall('\'cpe23Uri\': \'(.+?)\'', str(x)))
        df_cves['cpe_products']=df_cves['cpes'].apply(lambda x: self.extract_unique_product_from_cpe_list(x))
        df_cves['cpe_vendors']=df_cves['cpes'].apply(lambda x: self.extract_unique_vendor_from_cpe_list(x))
        df_cves['cpe_product_vendor']=df_cves['cpes'].apply(lambda x: self.extract_unique_product_vendor_from_cpe_list(x))

        df_cves.to_csv('C:/nvd/feeds/df_cves2020_summary_noun_cpe_products_vendors.csv')


        #check if cpe product name is in summary, to validate how common is that the product name is in summary
        #true positive
        #if len greater than 0, it means it found a name of product in the summary
        df_cves['TruePositive_product'] = [len(set(a) & set(b)) for a, b in zip(df_cves['cpe_products'], df_cves['summary_nouns'])]
        df_cves['TruePositive_vendor'] = [len(set(a) & set(b)) for a, b in zip(df_cves['cpe_vendors'], df_cves['summary_nouns'])]

        #check if a noun in summary contains a product name which is not in that cpe_product
        # , to validate how common is that the approach alert a product name based on summary which is not related
        #for example if in the summary it is writen that the vulnerability cause SQL injection, the SQL will be reported
        # as a related product.
        #false positive
        #get list of all products in the dataframe

        all_cpe_products_list = df_cves['cpe_products'].to_list()
        all_cpe_products_list=sum(all_cpe_products_list, [])
        all_cpe_products_list = set(all_cpe_products_list)
        all_cpe_products_list.remove('')
        all_cpe_products_list.difference_update(['java','http','remote','code','access','link','gateway','proxy','disclosure',
                                                'connection','network','backup','path','api','platform','power'
                                                ,'engin','mobile','security','archive','field','applications',
                                                'image','java','php','applications','database','firewall','trafic',
                                                'link','manager','object','path','directory','use','m','tag',
                                                'operations','scripting','time','log','text','reports','entity','advisor',
                                                'endpoint','v','cms','active','fork','office','video','comments','wizard',
                                                'online','dashboard','photo','notes','certificate','workspace',
                                                'macros','process','mall','source','play','interface','word','','release','email','activation','screen','contracts',
                                                'media','failure','workstation','driver','drivers',
                                                 'connector', 'flow', 'reset password', 'systemd', 'workflow', 'panel',
                                                 'wireless',
                                                 'find', 'availability', 'total',
                                                 'connections', 'traffic', 'encryption', 'center', 'vault', 'sounds',
                                                 'engines', 'print', 'engineering',
                                                 'gallery',
                                                 'social', 'helpdesk', 'commons', 'copy', 'utilities', 'streams',
                                                 'on premise',
                                                 'journal', 'genuine', 'knowledge', 'notebook',
                                                 'desk', 'safe',
                                                 'line'
                                                 ])
        #all_cpe_products_list_without_this_product = set(all_cpe_products_list) - set(df_cves['cpe_products'])


        #get list of all vendors in the dataframe
        all_cpe_vendors_list = df_cves['cpe_vendors'].to_list()
        all_cpe_vendors_list=sum(all_cpe_vendors_list, [])
        all_cpe_vendors_list = set(all_cpe_vendors_list)
        all_cpe_vendors_list.remove('')
        all_cpe_vendors_list.difference_update(['java','http','remote','code','access','link','gateway','proxy','disclosure',
                                                'connection','network','backup','path','api','platform','power'
                                                ,'engin','mobile','security','archive','field','applications',
                                                'image','java','php','applications','database','firewall','trafic',
                                                'link','manager','object','path','directory','use','m','tag',
                                                'operations','scripting','time','log','text','reports','entity','advisor',
                                                'endpoint','v','cms','active','fork','office','video','comments','wizard',
                                                'online','dashboard','photo','notes','certificate','workspace',
                                                'macros','process','mall','source','play','interface','word','','release','email','activation','screen','contracts',
                                                'media','failure','workstation','driver','drivers',
                                                'android', 'kernel', 'app', 'bit',  'target', 'cryptography', 'elliptic','contacts',
                                                'bluetooth','protocol','encryption','traffic','robot','save', 'protocol', 'apache', 'student', 'mind', 'owasp', 'eclipse',
          'tiny', 'realtek', 'install', 'signal',
         'socket', 'tasks',  'encode', 'live', 'idea', 'gallery', 'free', 'creative', 'bluetooth',
          'multi',
         'safe', 'health'])

        all_cpe_product_vendor_list=sum(df_cves['cpe_product_vendor'], [])
        # all_cpe_product_vendor_list = set(all_cpe_product_vendor_list)
        # all_cpe_product_vendor_list.remove('')
        product_vendor_u = []
        for item in all_cpe_product_vendor_list:
            if item not in product_vendor_u:
                product_vendor_u.append(item)

        all_cpe_products_list = {item for item in all_cpe_products_list if len(item) > 3}
        all_cpe_vendors_list = {item for item in all_cpe_vendors_list if len(item) > 3}

        # all_falsepositive_products = set.union(*df_cves['FalsePositive_product_list'].to_list())
        # all_falsepositive_vendorss = set.union(*df_cves['FalsePositive_vendor_list'].to_list())


        #if len is greater than 0, it means there is name of products other than the CVEs' cpe product name in the summary
        df_cves['FalsePositive_product'] = [len(set(b) & (all_cpe_products_list - set(a))) for a, b in zip(df_cves['cpe_products'], df_cves['summary_nouns'])]
        df_cves['FalsePositive_product_list'] = [set(b) & (all_cpe_products_list - set(a)) for a, b in zip(df_cves['cpe_products'], df_cves['summary_nouns'])]

        df_cves['FalsePositive_vendor'] = [len(set(b) & (all_cpe_vendors_list - set(a))) for a, b in zip(df_cves['cpe_vendors'], df_cves['summary_nouns'])]
        df_cves['FalsePositive_vendor_list'] = [set(b) & (all_cpe_vendors_list - set(a)) for a, b in zip(df_cves['cpe_vendors'], df_cves['summary_nouns'])]

        df_cves['FalsePositive_product_and_vendor'] = df_cves.apply(lambda x: 1 if (x['FalsePositive_product']>0) & (x['FalsePositive_vendor']>0) else 0, axis=1)
        df_cves['FalsePositive_product_or_vendor'] = df_cves.apply(lambda x: 1 if (x['FalsePositive_product']>0) | (x['FalsePositive_vendor']>0) else 0, axis=1)

        df_cves['check_product_vendor_in_cpe']=df_cves.apply(lambda x: self.check_product_vendor_in_cpe(all_cpe_product_vendor_list, x['FalsePositive_product_list'],x['FalsePositive_vendor_list']),axis=1)

        # df_cves.loc[(df_cves['FalsePositive_product'] > 0) | (
        #             df_cves['FalsePositive_vendor'] > 0), 'FalsePositive_product_or_vendor'] = 1
        # df_cves.loc[((df_cves['FalsePositive_product'] > 0) & (
        #             df_cves['FalsePositive_vendor'] > 0)), 'FalsePositive_product_and_vendor'] = 1
        # df_cves['FalsePositive_product_and_vendor'] = df_cves['FalsePositive_product_and_vendor'].fillna(0)
        # df_cves['FalsePositive_product_or_vendor'] = df_cves['FalsePositive_product_or_vendor'].fillna(0)
        #df_cves['FalsePositive_list'] =df_cves.apply(lambda x: set(x['summary_nouns'])&(all_cpe_products_list_clean-set(x['cpe_products'])),axis=1)
        #df_cves_with_cpe['FalsePositive']=df_cves_with_cpe['FalsePositive_list'].apply(lambda x: len(x))
        df_cves_with_cpe = df_cves[df_cves['cpe_products'].str.len() != 0]

        df_cves_with_cpe[df_cves_with_cpe['FalsePositive_product_and_vendor'] == 1]
        #[1064 rows x 60 columns]

        df_cves_with_cpe[df_cves_with_cpe['FalsePositive_product_or_vendor'] == 1]
        #[6508 rows x 60 columns]

        df_cves_with_cpe[df_cves_with_cpe['FalsePositive_product'] > 0]
        #[6166 rows x 60 columns]
        df_cves_with_cpe[df_cves_with_cpe['FalsePositive_vendor'] > 0]
        #[1406 rows x 60 columns]
        df_cves_with_cpe[df_cves_with_cpe['TruePositive_product'] >= 1]
        #[10189 rows x 60 columns]
        df_cves_with_cpe[df_cves_with_cpe['TruePositive_vendor'] >= 1]
        #[9624 rows x 60 columns]
        df_cves_with_cpe[
            (df_cves_with_cpe['TruePositive_product'] >= 1) | (df_cves_with_cpe['TruePositive_vendor'] >= 1)]
        #[13395 rows x 60 columns]

        df_cves_d = df_cves_with_cpe[
            ['publishedDate', 'lastModifiedDate', 'cve.CVE_data_meta.ID', 'summary_list', 'cpes', 'cpe_products',
             'cpe_vendors', 'TruePositive_product', 'TruePositive_vendor', 'FalsePositive_product',
             'FalsePositive_product_list', 'FalsePositive_vendor', 'FalsePositive_vendor_list',
             'FalsePositive_product_or_vendor', 'FalsePositive_product_and_vendor','check_falsepositive_product_vendor_in_cpe',
             'TruePositive_product_list','TruePositive_vendor_list','check_truepositive_product_vendor_in_cpe']]
        df_cves_d1 = df_cves_d.replace(set(), '')
        df_cves_d1.to_csv('C:/nvd/feeds/cves2020_summary_cpe_false_true_positive.csv', sep='|', index=False)

    def extract_unique_product_from_cpe_list(self, cpe_list):
        #extract products
        product_list=[]
        for cpe in cpe_list:
            p = cpe.split(':')[4]
            p = self.clean_word(p)
            if p not in product_list:
                product_list.append(p)
        return product_list

    def extract_unique_product_vendor_from_cpe_list(self, cpe_list):
        #extract products
        product_vendor_list=[]
        for cpe in cpe_list:
            p = cpe.split(':')[4]
            p = self.clean_word(p)
            v = cpe.split(':')[3]
            v = self.clean_word(v)
            if {p,v} not in product_vendor_list:
                product_vendor_list.append({p,v})
        return product_vendor_list

    def extract_unique_vendor_from_cpe_list(self, cpe_list):
        #extract vendors
        vendor_list=[]
        for cpe in cpe_list:
            p = cpe.split(':')[3]
            p = self.clean_word(p)
            if p not in vendor_list:
                vendor_list.append(p)
        return vendor_list
    def check_product_vendor_in_cpe(self, cpe_list, product_list,vendor_list):
        for p in product_list:
            for v in vendor_list:
                if {p,v} in cpe_list:
                    return True
        return False

    def clean_word(self, word):
        if word is not None and word != '':
            word = re.sub(pattern=r"[0-9][\w.]+", string=word, repl='')  # remove digits
            word = re.sub(pattern=r"([a-zA-Z]+)(\d+)", string=word, repl=r'\1')  # remove digits from end of the words
            word = re.sub(pattern=r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$", string=word,
                          repl='')  # remove email
            word = re.sub(pattern=r"\(.*?\)", string=word, repl='')  # remove ()
            word = re.sub(pattern=r"\[.*?\]", string=word, repl='')  # remove []
            word = re.sub(pattern=r"\<.*?\>", string=word, repl='')  # remove <>
            word = re.sub(pattern=r"\{.*?\}", string=word, repl='')  # remove {}
            word = re.sub(pattern=r"[-_,;|/]", string=word, repl=' ')  # remove special characters #Kobra added
            word = re.sub(pattern=r"[\w]+\.$", string=word, repl=' ')  # remove words abrivated like inc.
            word = re.sub(pattern=r"[ ]+", string=word, repl=' ')  # remove extra spaces
            word = word.strip().lower()
            filtering_words = ['inc', 'system', 'systems', 'software', 'corporate', 'the', 'a', 'an', 'llc', 'team',
                               'foundation',
                               'soft', 'tech', 'technology', 'technologies', 'ltd', 'solutions', 'solution', 'co',
                               'com',
                               'corp',
                               'contributors', 'contributor', 'company', 'lab', 'labs', 'project', 'tool', 'tools',
                               'us',
                               'usa',
                               'service', 'services', 'device', 'devices', 'pty',
                               'edition', 'developer', 'kit', 'resource',
                               'series', 'update', 'core', 'server', 'client', 'runtime', 'package', 'data', 'library',
                               'desktop',
                               'files', 'file', 'maintenance', 'management', 'command', 'error', 'driver',
                               'documentation',
                               'document', 'doc', 'docs', 'agent', 'message', 'ide', 'beta', 'version', 'configuration',
                               'vulnerability'
                , 'protection', 'support', 'application', 'fingerprint', 'storage', 'cloud', 'user', 'compiler', 'help',
                               'host', 'agent', 'framework', 'header', 'headers', 'root', 'windows', 'extension',
                               'deploy', 'deployment', 'web', 'monitoring', 'studio', 'plugin', 'web', 'session',
                               'control',
                               'assistant', 'setup', 'integration', 'ip', 'centre', 'mozilla']

            word = ' '.join([w for w in word.split() if w.lower() not in filtering_words])
            # if it is greater than 3 word return first three word
            words = word.split()
            if len(words) > 3:
                return (' '.join(words[0:3]))
            else:
                return (word)
        else:
            return word

    def extract_stanza_nouns(self, summary):
            summary = ''.join(summary)
            if not summary:
                return []
            else:
                #nlp = stanza.Pipeline('en', processors='tokenize,pos')


                doc = self.nlp(summary)
                nouns = []
                for sentence in doc.sentences:
                    for word in sentence.words:
                        print(word.text, word.lemma, word.pos, word.xpos)
                        if word.xpos in ['NN', 'NNS', 'NNP', 'NNPS']:
                            cword =self.clean_word(word.text.lower())
                            nouns.append(cword)
                return nouns

def find_git_links(references_dict):
    y = []
    for x in references_dict:
        if 'github' in x['url']:
            y.append(x)
    if y:
        return y
    else:
        return []
import json

def read_all_cves():
    #step0: convert json file of the cve feeds to dataframe and csv and save
    my_dir='C:/nvd/feeds/'
    f = []

    for (dir_path, dir_names, file_names) in os.walk(my_dir):
        f.extend(file_names)
        break

    # Iterate through the cve files

    for my_file in f:

        # skip the cpe dictionary if it is there
        if not my_file.startswith('nvdcve-1.1-'):
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

        """Save NvdCpe vuln dataframe in serialized pickle format."""
        print('\n\nSaving NvdCve.df_cve dataframe\n\n')
        df_cve_items.to_pickle('c:/nvd/feeds/df_cve_all_items_'+my_file1[24:28]+'.pck')
        df_cve_items.to_csv('c:/nvd/feeds/df_cve_all_items_'+my_file1[24:28]+'.csv')
    return None

def cves_references_github(year):
    #step 1: find github links on the csvs which has refrences to github
    df_cves = pd.read_csv("C:/nvd/feeds/df_cve_all_items_"+year+".csv")
    df_cves.head()
    df_cves['cve.references.list'] = df_cves['cve.references.reference_data'].apply(lambda x: eval(x)) #change string to array
    df_cves['cve.github.list']=df_cves['cve.references.list'].apply(lambda x: find_git_links(x))
    df_cves_with_github =df_cves[df_cves['cve.github.list'].str.len()!=0]
    df_cves_github_links=pd.DataFrame(columns=['cve_id','github_url','github_tags'])
    for index, row in df_cves_with_github.iterrows():
        for link in row['cve.github.list']:
            df_cves_github_links=df_cves_github_links.append({'cve_id': row['cve.CVE_data_meta.ID'], 'github_url': link['url'], 'github_tags': link['tags']}, ignore_index=True)

    df_cves_github_links.to_csv('C:/nvd/feeds/df_cves'+year+'_github_links.csv')

    df_cves_github_links['patch'] = df_cves_github_links['github_tags'].apply(lambda x: True if 'Patch' in x else False)

    df_cves_github_links_with_Patch = df_cves_github_links[df_cves_github_links['patch']]
    df_cves_github_links_with_Patch.to_csv('C:/nvd/feeds/df_cves'+year+'_github_links_with_Patch.csv')


def change_text(year):
    #step2: add /files to the links ends with /pull
    df=pd.read_csv('C:/nvd/feeds/df_cves'+year+'_github_links_with_Patch.csv')
    df.head()
    df_pulls = df[df['github_url'].str.contains('/pull')]
    df_commits = df[df['github_url'].str.contains('/commits')]
    df_pulls=df_pulls.replace({'github_url': r'\/pull\/([0-9]+)$'}, {'github_url': r'/pull/\1/files'}, regex=True)
    df_files = df_commits.append(df_pulls)
    df_files.drop_duplicates(keep="first", inplace=True)
    df_files.to_csv('c:/nvd/feeds/df_cves'+year+'_github_links_Patch_commit_pull1.csv')

def download_cves():
    # Download CVEs for last seven days ###########################
    cve_database = NvdCve()
    cve_database.download_cve()
    print('Downloaded CVE dictinary for last seven days at {datetime.datetime.now()}')
    cve_database.read()
    print('Read CVEs for the previous day at {datetime.datetime.now()}')
    cve_database.save()
    print('Saved CVEs for the previous day at {datetime.datetime.now()}')
    #cve_database.load()
    # df_cves = cve_database.get()
    #

    #Average number of CVEs mapped to every asset records
    #import re
    # df_assets['cve_no']=df_assets['cves'].apply(lambda x: re.findall('\'(CVE-\d+-\d+)\'',x).__len__())
    # df_assets['cve_no'].mean()
    return

def main():

    cp=cve_product_comp()
    cp.cves_summary_product()


    years = ['1999','2002','2006','2007','2008','2009','2010','2011','2012','2013','2014','2015','2016','2017','2018','2019','2020','2021'] #

    with open('c:/nvd/feeds/nvdcve-1.1-2020.json', encoding="utf8") as fd:
        cve_dict = json.loads(fd.read())
    
    df_cve_items = pd.json_normalize(cve_dict['CVE_Items'])
    
    """Save NvdCpe vuln dataframe in serialized pickle format."""
    print('\n\nSaving NvdCve.df_cve dataframe\n\n')
    df_cve_items.to_pickle('c:/nvd/feeds/df_cve_all_items_2020.pck')
    df_cve_items.to_csv('c:/nvd/feeds/df_cve_all_items_2020.csv')

    find_vendors()
    find_duration_till_geting_cvss()
    read_all_files()
    
    cves_no_severity_box_plot()
    cves_priority_distribution()
    cves_no_cpe_box_plot()
    cves_no_references_box_plot()
    return


if __name__ == '__main__':
    try:
        print('Starting, vulnerability management, finding mached nvd cves.')
        main()
        print('Finished, vulnerability management, finding mached nvd cves.')
    except Exception as e:
        print(e)
    else:
        print()

