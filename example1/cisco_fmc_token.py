import requests
from requests.auth import HTTPBasicAuth
from pprint import pprint
from pyvault2.vault.hvault2 import (enable_kv2_engine,
                                    create_update_kv2_secrets,
                                    is_secret_path_exists,
                                    get_kv2_secret)
from ipaddress import ip_address
import sys
from getpass import getpass
from typing import Dict, List
import json


def is_ipv4(ipv4: str) -> bool:
    """
    Check for valid ipv4 address
    :param ipv4:
        test object
    :return:
        if test object is valid ipv4 return True else return False
    """
    try:
        ip_address(ipv4)
        return True
    except ValueError:
        return False


def fmc_gen_token(addr: str = None, username: str = None, password: str = None) -> Dict:
    """
    Generate cisco FMC token
    :param addr:
        address of Cisco FMC
    :param username:
        username of Cisco FMC
    :param password:
        password of Cisco FMC
    :return:
        customized dictionary which contains access token, refresh token and domainUUID
    """
    api_uri = "/api/fmc_platform/v1/auth/generatetoken"
    url = "https://" + addr + api_uri
    response = requests.post(url,
                             verify=False,
                             auth=HTTPBasicAuth(username, password))
    return {
        "X-auth-access-token": response.headers["X-auth-access-token"],
        "X-auth-refresh-token": response.headers["X-auth-refresh-token"],
        "DOMAIN_UUID": response.headers["DOMAIN_UUID"]
    }


def get_version(addr: str = None, token: str = None):
    """
    Call Cisco FMC REST API for getting server version
    :param addr:
        Cisco FMC address
    :param token:
        X-auth-access-token
    :return:
        HTTP response from Cisco FMC
    """
    api_uri = "/api/fmc_platform/v1/info/serverversion"
    url = "https://" + addr + api_uri
    headers = {
        "X-auth-access-token": token
    }
    response = requests.get(url, verify=False, headers=headers)
    return response


def get_policy_assignment(addr: str = None, token: Dict = None, id_only=True):
    """
    Gets the access policy assignment. This policy is assigned to managed devices.
    :param addr:
        Address of Cisco FMC
    :param token:
        dictionary of token response which includes domainUUID, and X-auth-access-token
    :param id_only:
        Default is True, which gives only access_policy_id, else returns all response.
    :return:
    """
    api_uri = f"/api/fmc_config/v1/domain/{token['DOMAIN_UUID']}/policy/accesspolicies"
    url = "https://" + addr + api_uri
    headers = {
        "X-auth-access-token": token["X-auth-access-token"]
    }
    response = requests.get(url, headers=headers, verify=False)
    if id_only:
        return json.loads(response.text)["items"][0]["id"]
    else:
        return json.loads(response.text)


def add_ftd_device(addr: str = None,
                   name: str = None,
                   hostname: str = None,
                   regkey: str = None,
                   license_caps: List = None,
                   domainuuid: str = None,
                   access_policy_id: str = None,
                   description: str = None,
                   token: str = None):
    """
    Add FTD device to Cisco FMC
    :param description:
        Description of the device to be added.
    :param addr:
        Cisco FMC address
    :param name:
        name of the FTD device
    :param hostname:
        IP address of FTD device
    :param regkey:
        regkey configured in FTD
    :param license_caps:
        PROTECT, CONTROL, URLFilter, MALWARE, BASE
    :param domainuuid:
        DomainUUID from Cisco FMC token header
    :param access_policy_id:
        Access Policy ID assign to FTD
    :param token:
        X-auth-access-token
    :return:
        HTTP response from Cisco FMC
    """
    api_uri = f"/api/fmc_config/v1/domain/{domainuuid}/devices/devicerecords"
    url = "https://" + addr + api_uri
    headers = post_request_headers(token)

    payload = {
        "name": name,
        "hostName": hostname,
        "ftdMode": "ROUTED",
        "description": description,
        "regKey": regkey,
        "type": "Device",
        "license_caps": license_caps,
        "accessPolicy": {
            "id": access_policy_id,
            "type": "AccessPolicy"
        }
    }
    print(payload)
    response = requests.post(url, headers=headers, verify=False, data=json.dumps(payload))
    return response


def post_request_headers(x_auth_access_token: str) -> Dict:
    """
    Lazy function to help to generate request headers
    :param x_auth_access_token:
        X-auth-access-token required by Cisco FMC to access REST API.
    :return:
        dictionary of headers
    """
    return {
        "X-auth-access-token": x_auth_access_token,
        "Content-Type": "application/json"
    }


def create_host_object(addr: str = None,
                       token: Dict = None,
                       name: str = None,
                       value: str = None,
                       description: str = None):
    """
    Create host object
    :param addr:
        Cisco FMC address
    :param token:
        Token from fmc_gen_token function
    :param name:
        name of the host object
    :param value:
        IP address of the host object
    :param description:
        Description of the host object
    :return:
        response from Cisco FMC
    """
    api_uri = f"/api/fmc_config/v1/domain/{token['DOMAIN_UUID']}/object/hosts"
    url = "https://" + addr + api_uri
    payload = {
        "name": name,
        "type": "Host",
        "value": value,
        "description": description
    }
    headers = post_request_headers(token["X-auth-access-token"])
    response = requests.post(url, verify=False, headers=headers, data=json.dumps(payload))
    return response.text


def demo():
    """
    Function for demonstration so that __main__ looks neat...
    :return:
    """

    """
    Demonstration code here
    """
    if not is_secret_path_exists(mount_path="cisco_fmc", path="fmc01"):
        """
        Check if vault has FMC's data
        """
        hostname = input("Hostname of FMC: ")
        fmc_ip = input("What is FMC Server ip address: ")
        if not is_ipv4(fmc_ip):
            print("Invalid ip address...bye...")
            sys.exit(1)
        enable_kv2_engine(mount_path="cisco_fmc")
        username = input("Username of fmc01: ")
        password = getpass()
        payload = {
            "username": username,
            "password": password,
            "ip": fmc_ip
        }
        create_update_kv2_secrets(mount_path="cisco_fmc", path=hostname, **payload)

    """
    Codes to get version
    """
    hostname = input("FMC hostname: ")
    data = get_kv2_secret(mount_path="cisco_fmc", path="fmc01", find="data")
    fmc_token = fmc_gen_token(addr=data["ip"],
                              username=data["username"],
                              password=data["password"])
    version = get_version(addr=data["ip"], token=fmc_token["X-auth-access-token"])
    fmc_info = json.loads(version.text)
    print(f"Cisco FMC version:{fmc_info['items'][0]['serverVersion']}")
    print(f"Vulnerable Database version:{fmc_info['items'][0]['vdbVersion']}")
    print(f"Snort rules version:{fmc_info['items'][0]['sruVersion']}")

    # Get Access Policy ID
    policy_id = get_policy_assignment(addr=data["ip"], token=fmc_token)

    """
    Add FTD device to Cisco FMC
    """
    print("*" * 10 + "Add a device to FMC" + "*" * 10)
    device_hostname = input("hostname of FTD: ")
    device_ip_addr = input(f"IP address of {device_hostname}: ")
    regkey = input(f"Registration key configured in {device_hostname}: ")
    description = input(f"Description for this device: ")
    add_device = {
        "addr": data["ip"],
        "name": device_hostname,
        "hostname": device_ip_addr,
        "license_caps": ["MALWARE",
                         "URLFilter",
                         "THREAT",
                         "BASE"],
        "domainuuid": fmc_token["DOMAIN_UUID"],
        "access_policy_id": policy_id,
        "token": fmc_token["X-auth-access-token"],
        "regkey": regkey,
        "description": description
    }
    response = add_ftd_device(**add_device)
    pprint(response.text)


if __name__ == "__main__":
    demo()
