from Evtx.Evtx import Evtx
from lxml import etree


def rdp_security(security_evtx):
    namespace = "http://schemas.microsoft.com/win/2004/08/events/event"
    LOGON_ID = "4624"
    rdp_logon_type = "10"

    with Evtx(security_evtx) as log:
        for record in log.records():
            root = etree.fromstring(record.xml().encode())

            event_id = root.findtext(".//{*}EventID")
            if event_id != LOGON_ID:
                continue

            time_created = root.find(".//{*}TimeCreated").get("SystemTime")
            computer = root.findtext(".//{*}Computer")

            logon_type = "None"
            logon_user = "None"
            logon_ip_address = "None"

            for d in root.findall(".//{*}EventData/{*}Data"):
                if d.get("Name") == "LogonType":
                    logon_type = d.text
                if d.get("Name") == "TargetUserName":
                    logon_user = d.text
                if d.get("Name") == "IpAddress":
                    logon_ip_address = d.text

            if logon_type == "10":
                print(f"[{time_created}] {computer} {event_id} {logon_type} {logon_user} {logon_ip_address}")

def rdp_remote_desktop_services(filepath):
    namespace = "http://schemas.microsoft.com/win/2004/08/events/event"
    TCP_UDP_CONNECTION_ID = "131"

    with Evtx(filepath) as log:
        for record in log.records():
            root = etree.fromstring(record.xml().encode())

            event_id = root.findtext(".//{*}EventID")
            if event_id != TCP_UDP_CONNECTION_ID:
                continue

            time_created = root.find(".//{*}TimeCreated").get("SystemTime")
            remote_ip_address = "None"

            for d in root.findall(".//{*}EventData/{*}Data"):
                if d.get("Name") == "ClientIP":
                    remote_ip_address = d.text

            print(f"[{time_created}] Client ip address: {remote_ip_address}")

def rdp_remote_desktop_connection_manager(filepath):
    namespace = "http://schemas.microsoft.com/win/2004/08/events/event"
    USER_LOGIN_ID = "1149"

    with Evtx(filepath) as log:
        for record in log.records():
            root = etree.fromstring(record.xml().encode())

            event_id = root.findtext(".//{*}EventID")
            if event_id != USER_LOGIN_ID:
                continue

            time_created = root.find(".//{*}TimeCreated").get("SystemTime")
            username = root.find(".//{*}Param1").text
            remote_host = root.find(".//{*}Param2").text
            remote_ip = root.find(".//{*}Param3").text

            print(f"[{time_created}] {username} from {remote_host} - {remote_ip}")


def main():
    rdp_security("security.evtx")  # This might take a while
    rdp_remote_desktop_services("microsoft-windows-remotedesktopservices-rdpcorets%4operational.evtx")
    rdp_remote_desktop_connection_manager("microsoft-windows-terminalservices-remoteconnectionmanager4operational.evtx")

if __name__ == "__main__":
    main()

 
