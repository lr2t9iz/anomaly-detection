
def source():
    fields = ["timestamp", "data.win.system.eventID", "data.win.eventdata.ipAddress", 
          "data.win.eventdata.targetUserName", "data.win.eventdata.logonType"] # SELECT
    index_pattern = "wazuh-alerts-*" # FROM
    query_dsl = {  # WHERE
          "bool": {
            "filter": [
                { "range": { "timestamp": { "gt": "now/m-1d" } } }, # batch DATA
                { "terms": { "data.win.system.eventID": ["4625", "4624"] } },
                { "exists": { "field": "data.win.eventdata.ipAddress" } }
            ],
            "must_not": [
                { "terms": { "data.win.eventdata.ipAddress": ["127.0.0.1", "4624"] } },
                { "wildcard": { "user.name": "*$" } }
            ]
        }
    }
    size = 10000 # LIMIT
    sort_docs = [ { "timestamp": { "order": "desc" } } ] # ORDER by

    q = { 
            "_source": { "includes": fields },
            "query": query_dsl,
            "size": size, 
            "sort": sort_docs
        }    
    return index_pattern, q






import pandas as pd
from datetime import timedelta

def rule(data):
    df = pd.json_normalize(data)
    # timetamp, 
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df.rename(columns={"data.win.eventdata.ipAddress": "ipAddress"}, inplace=True)
    df.rename(columns={"data.win.eventdata.targetUserName": "targetUserName"}, inplace=True)
    df.rename(columns={"data.win.eventdata.logonType": "logonType"}, inplace=True)
    df.rename(columns={"data.win.system.eventID": "eventID"}, inplace=True)

    successful_logins = df[df['eventID'] == "4624"]
    failed_logins = df[df['eventID'] == "4625"]

    # rule
    mins=2
    alert_events = []
    alert_df = pd.DataFrame(alert_events)

    for index, success in successful_logins.iterrows():
        time_window_start = success['timestamp'] - timedelta(minutes=mins)
        user_failed_logins = failed_logins[(failed_logins['targetUserName'] == success['targetUserName']) & 
                                        (failed_logins['timestamp'] >= time_window_start) & 
                                        (failed_logins['timestamp'] <= success['timestamp'])]
        succes_result = success
        count_failed = len(user_failed_logins)
        if count_failed >= 4:
            succes_result['count_failed'] = count_failed
            alert_events.append(succes_result)

    if alert_events:
        alert_df['timestamp'] = alert_df['timestamp'].astype(str)
        alert_df['rule_name'] = "possible_bruteforce_with_successful_login"
    return alert_df.to_dict(orient='records')
    