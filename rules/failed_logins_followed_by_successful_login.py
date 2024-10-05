'''
https://github.com/lr2t9iz/sigmaRulesHub/blob/main/01-endpoint/windows/failed_logins_followed_by_successful_login.yml

timestamp
SourceIP
UserName
HostName
'''
import pandas as pd

def get_multiples_failed_logon(df, timeframe=10, maxfailedlogins=5):
    '''
    Return users with more 
        failed logins (maxfailedlogins) in a 
        range of time (timeframe) minutes, 
    then search for successful logins of these users.
    '''
    df['timestamp'] = df['timestamp'].dt.floor(f"{timeframe}min")
    df_failed_logins = (
        df.groupby(['timestamp', 'SourceIP', 'UserName', 'HostName'])
          .size()
          .reset_index(name='Attempts')
    )
    df_failed_logins = df_failed_logins[df_failed_logins['Attempts'] > maxfailedlogins]
    df_failed_logins['UntilTimestamp'] = df_failed_logins['timestamp'] + pd.Timedelta(minutes=timeframe+1) # for search success logon
    df_failed_logins = df_failed_logins[['timestamp', 'UntilTimestamp', 'SourceIP', 'UserName', 'HostName', 'Attempts']]
    df_failed_logins['timestamp'] = df_failed_logins['timestamp'].dt.strftime('%Y-%m-%dT%H:%M:%S')
    df_failed_logins['UntilTimestamp'] = df_failed_logins['UntilTimestamp'].dt.strftime('%Y-%m-%dT%H:%M:%S')
    return df_failed_logins.to_dict(orient='records')
