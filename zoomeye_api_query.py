#!/usr/bin/python

#Usage: zoomeye_api_query.py <zoomeye_username> <zoomeye_password> <zoomeye_search_query>
#Author: Interference Security

import requests
import sys
import json
import time

def get_access_token(username, password):
    try:
        post_data = '{"username": "%s","password": "%s"}' % (username, password)
        print "[*] Authenticating to ZoomEye API"
        auth_req = requests.post("https://api.zoomeye.org/user/login", data=post_data)
        auth_resp = json.loads(auth_req.text)
        access_token = auth_resp['access_token']
        #print "[-] Access Token: %s" % access_token
        return access_token
    except:
        print "[!] Failed to get access token"
        sys.exit(1)


def get_result_count(query, access_token):
    try:
        headers = {"Authorization": "JWT %s" % access_token}
        query_req = requests.get("https://api.zoomeye.org/host/search?query=%s" % query, headers=headers)
        query_resp = query_req.text
        parsed_json = json.loads(query_resp)
        return int(parsed_json["total"])
    except Exception as e:
        print "[!] Failed to execute query"
        print "\t[-] Exception: %s" % str(e)
    return 0


def execute_query(query, pages, access_token):
    try:
        for page in range(1,pages+1):
            headers = {"Authorization": "JWT %s" % access_token}
            query_req = requests.get("https://api.zoomeye.org/host/search?query=%s&page=%s" % (query,page), headers=headers)
            query_resp = query_req.text
            #print query_resp
            parsed_json = json.loads(query_resp)
            #print json.dumps(parsed_json, indent=4)
            if "matches" in parsed_json.keys():
                for key in range(0, len(parsed_json["matches"])):
                    print parsed_json["matches"][key]["ip"]
                    """print parsed_json["matches"][0]["ip"]
                    print parsed_json["matches"][0]["portinfo"]["hostname"]
                    print parsed_json["matches"][0]["portinfo"]["service"]
                    print parsed_json["matches"][0]["portinfo"]["banner"]
                    print parsed_json["matches"][0]["portinfo"]["app"]
                    print parsed_json["matches"][0]["portinfo"]["extrainfo"]
                    print parsed_json["matches"][0]["portinfo"]["version"]
                    print parsed_json["matches"][0]["portinfo"]["device"]
                    print parsed_json["matches"][0]["portinfo"]["os"]
                    print parsed_json["matches"][0]["portinfo"]["port"]
                    print parsed_json["matches"][0]["rdns"]"""
            else:
                print json.dumps(parsed_json, indent=4)
    except Exception as e:
        print "[!] Failed to execute query"
        print "\t[-] Exception: %s" % str(e)
        sys.exit(1)


def resource_info(access_token):
    try:
        headers = {"Authorization": "JWT %s" % access_token}
        query_req = requests.get("https://api.zoomeye.org/resources-info", headers=headers)
        query_resp = query_req.text
        parsed_json = json.loads(query_resp)
        plan = parsed_json["plan"]
        host_search = parsed_json["resources"]["host-search"]
        web_search = parsed_json["resources"]["web-search"]
        print "[+] Resource Information:"
        print "\t[-] Plan: %s" % plan
        print "\t[-] Host Search: %s" % host_search
        print "\t[-] Web Search: %s" % web_search
        if plan == "developer":
            print "[!] You have a 'developer' plan. Please check: https://www.zoomeye.org/api/doc#limitations"
    except Exception as e:
        print "[!] Failed to execute query"
        print "\t[-] Exception: %s" % str(e)
        sys.exit(1)
        

if __name__ == "__main__":
    if len(sys.argv)<4:
        print "Usage: %s <zoomeye_username> <zoomeye_password> <zoomeye_search_query>" % sys.argv[0]
        sys.exit(1)
    print "[*] Start time: %s" % time.strftime("%d-%m-%Y %H:%M:%S", time.localtime())
    username = sys.argv[1]
    password = sys.argv[2]
    query = sys.argv[3]
    access_token = get_access_token(username, password)
    resource_info(access_token)
    result_count = get_result_count(query, access_token)
    print "[*] Number of results: %s" % result_count
    pages = 0
    if result_count==0:
        pages = 0
    elif result_count >=1 and result_count <= 10:
        pages = 1
    else:
        count_int = int(result_count/10)
        count_float = float(result_count)/10
        if float(count_float) > float(count_int):
            pages = result_count/10 + 1
        else:
            pages = result_count/10
    print "[*] Number of pages: %s" % pages
    raw_input("[*] Press [enter] to continue")
    if pages > 0:
        execute_query(query, pages, access_token)
    else:
        print "[!] No result found"
    print "[*] End time: %s" % time.strftime("%d-%m-%Y %H:%M:%S", time.localtime())
