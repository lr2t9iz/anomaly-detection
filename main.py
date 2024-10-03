import os
import importlib
from dotenv import dotenv_values
import requests, json
import urllib3
urllib3.disable_warnings()

app_dir = os.getcwd()
creds = dotenv_values(f"{app_dir}/.env")

wi_url = creds['WI_URL']
wi_user = creds['WI_USER']
wi_pass = creds['WI_PASS']

def extract_data(index_pattern, query):
    docs = requests.get(f"{wi_url}/{index_pattern}/_search",
                        auth=requests.auth.HTTPBasicAuth(wi_user, wi_pass), verify=False,
                        json=query)
    docs = docs.json()['hits']['hits']
    data = []
    if docs:
        data = [doc['_source'] for doc in docs]
    return data

def transform_rules():
    rules = []
    rules_path = os.listdir('rules')
    for filename in rules_path:
        if filename.endswith(".py"):
            module_name = filename[:-3]
            module = importlib.import_module(f"rules.{module_name}")
            rules.append(module)
    return rules

def load_result(results):
    index_pattern = "wazuh-anomaly-detection-10"
    postinfo = {}
    for result in results:
        postinfo = requests.post(f"{wi_url}/{index_pattern}/_doc/",
                            auth=requests.auth.HTTPBasicAuth(wi_user, wi_pass),
                            headers = {'Content-Type': 'application/json'},
                            data=json.dumps(result),
                            verify=False)
    return postinfo.json()

def main():
    rules = transform_rules()
    for rule in rules:
        index_pattern, query = rule.source()
        data = extract_data(index_pattern, query)
        if data:
            results = rule.logic(data)
            if results:
                load_result(results)

if __name__ == "__main__":
    main()
    