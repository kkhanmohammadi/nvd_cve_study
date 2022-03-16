from nvd import NvdCpe


# this is a test file if one need to download cpe only

def main():
    cpe = NvdCpe()
    try:
        cpe.download_cpe()  # download zip file from nvd site every 7 days
        cpe.read(my_cpe=None)  # extract zip file and read xml into a dataframe
        df_cpe = cpe.get()  # get dataframe from df_cpe4
        #print(df_cpe.head())
        cpe.save()  # save df_cpe4 in pkl file
        cpe.load()  # load pkl file to df_cpe4
        my_df_cpe = cpe.get()  # get a copy of df_cpe4
        my_df_cpe1 = my_df_cpe[:5]
        #print(my_df_cpe1)

    except Exception as e:
        #print("error:")
        print(e)


if __name__ == '__main__':
    main()
