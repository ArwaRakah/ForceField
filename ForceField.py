import os
import re
import csv
import sys
import json
import time
import bcrypt
import socket
import smtplib
import urllib3
import requests
import logging
import shutil
import warnings
import tempfile
import threading
import subprocess
import configparser
from tqdm import tqdm
import mysql.connector
import scapy.all as scapy
from getpass import getpass
from datetime import datetime
from bs4 import BeautifulSoup
from colorama import Fore, init
from mysql.connector import Error
from scapy.utils import PcapWriter
import xml.etree.ElementTree as ET
from email.mime.text import MIMEText
from sklearn.preprocessing import MinMaxScaler
from email.mime.multipart import MIMEMultipart
from urllib3.exceptions import InsecureRequestWarning
#prediction
from preprocessing_and_prediction import load_model, load_scaler, preprocess_data, make_predictions

# Disable the warning
urllib3.disable_warnings(InsecureRequestWarning)
# Configure logging
logging.basicConfig(
    filename='sniffing.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(
    filename='sniffing.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
def suppress_logging():
    logging.getLogger().setLevel(logging.CRITICAL)


def execute_command(command):
    #suppress_logging()
    if command in ['help', 'h']:
        print(Fore.LIGHTBLUE_EX + "\nAvailable commands:" + Fore.RESET)
        print("  - report (r): Generate a report of real-time sniffing")
        print("  - upload (u): Upload new data and make predictions ")
        print("  - history (i): Display report history")
        print("  - register (g): Register a new Admin")
        print("  - cti (c): Display CTI reports")
        print("  - sniff (s): Start Sniffing")
        print("  - logout (l): Log out \n") #prediction

    elif command in ['register', 'g']:
        print(Fore.LIGHTBLUE_EX + "\n\tRegistering a new Admin...\n")
        try:
            username = input("Enter username: ")
            password = input("Enter password: ")
            provided_key = getpass("Enter registration key: ")
            register_user(username, password, provided_key)
        except KeyboardInterrupt:
            print(Fore.YELLOW+"\nRegistration process interrupted by user, exiting...")
            logout_message()
        except Exception as e:
            print(Fore.RED + f"An exception occurred: {e}\n")
    elif command in ['report', 'r']:
        try:
            report_content = perform_splunk_search()
            save_report_to_downloads(report_content)
        except ET.ParseError as e:
            print(Fore.RED + f"XML Parse Error: {e}" + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"An error occurred: {e}" + Fore.RESET)

    elif command in ['history', 'i']:
        find_reports_in_downloads()

    elif command in ['cti', 'c']:
        # Handle cti command
        print(Fore.MAGENTA + "\nDisplaying CTI reports...")
        # Call the function to display CTI reports
        Mitre_CTI_Group_Extract()

    elif command in ['sniff', 's']:
        print(Fore.LIGHTBLUE_EX + "\nStarting to sniff network traffic 24/7...\n" + Fore.RESET)
        sniff_thread = threading.Thread(target=sniff_continuously, daemon=True)
        sniff_thread.start()
        subject = "Monitoring Result"
        body = "Please login to check the report for more details about the sniffing result."
        # choose an email to send any alerts // change the email
        receiver = "fatimajarri@gmail.com"
        send_email(subject, body, receiver)

    elif command in ['logout', 'l']:
        logout_message()
        sys.exit()

    elif command in ['upload', 'u']: #prediction
        try:
            filepaths = [filepath.strip() for filepath in input(
                Fore.LIGHTBLUE_EX + "Enter the file paths of the new datasets, separated by commas: " + Fore.RESET).split(
                ',')]
            model = load_model("RandomForest_model_best.joblib")  #the model
            scaler = load_scaler("scaler.joblib") #the Scaler
            df_new = preprocess_data(filepaths)
            predictions = make_predictions(model, scaler, df_new)
            print(Fore.GREEN+"Predictions:")
            subject = "APT detection prediction result"
            body = "Please login to check the report for more details about the prediction result."
            # choose an email to send any alerts // change the email
            receiver = "fatimajarri@gmail.com"
            save_report_prediction(str(predictions),"ReportAPT.txt",subject,body,receiver)

        except Exception as e:
            logging.error(f"An error occurred: {e}")

    else:
        print(Fore.RED + "Invalid command. Type 'help' for available commands.\n")


def sniff_continuously():
    scapy.sniff(prn=sniff_it, store=0)

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def check_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def logout_message():
    print(Fore.LIGHTMAGENTA_EX + "\nLogging off...Goodbye" + Fore.RESET)

def interface():
    print(
        """\033[1;34m 

  ███████╗░█████╗░██████╗░░█████╗░███████╗███████╗██╗███████╗██╗░░░░░██████╗░
  ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝██║░░░░░██╔══██╗
  █████╗░░██║░░██║██████╔╝██║░░╚═╝█████╗░░█████╗░░██║█████╗░░██║░░░░░██║░░██║
  ██╔══╝░░██║░░██║██╔══██╗██║░░██╗██╔══╝░░██╔══╝░░██║██╔══╝░░██║░░░░░██║░░██║
  ██║░░░░░╚█████╔╝██║░░██║╚█████╔╝███████╗██║░░░░░██║███████╗███████╗██████╔╝
  ╚═╝░░░░░░╚════╝░╚═╝░░╚═╝░╚════╝░╚══════╝╚═╝░░░░░╚═╝╚══════╝╚══════╝╚═════╝░
        """
    )
    # Initialize colorama
    init(autoreset=True)
    # Define the pattern to print
    pattern = """
                                .:++::::::::-
                           .::.              ..  .-.
                        ++                 :.  :      -
                     -:                 .-  .-     ..  . .
                     +                :-  -.     -   -    .
                     :              +   :      -   -
                     :           -:  --     --  -.        .
                     :         :-  :-     :   -      -   .
                     :      .+  .:     .:  .:     -.  ..  .
                     :    -:  -:     :-  -.     -   -     .
                     :  :.  +.     +   :     .-   -       .
                     =+  .+     -:  -:     --  -.         .
                       -:     :.  :.     +   :
                      -     +   +     .:  .:             .
                      :  -:  --     :-  :.
                      .+.  +.     +   +                 .
                        .:     --  --                  .
                        :    +.  :.                   -
                         :.:  .:                     .
                            :-                      -
                            :                     -
                              +                 ..
                                :-            -
                                   -:     -:
                                       .                      """

    for char in pattern:
        if char == '.':
            print(Fore.MAGENTA + char, end='')
        elif char in ':+-':
            print(Fore.BLUE + char, end='')
        else:
            print(char, end='')
    print(Fore.MAGENTA +
          "\n[+]AUTHORS:\n[+]Fatema Al Jarri\n[+]Arwa Alrakah\n[+]Rawan Al shayib\n[+]Layan Al Ali\n[+]Sara Al Shaieb"
          )
    print(Fore.LIGHTMAGENTA_EX +
          "\nThis tool should detect APT presence using network traffic in real time manner.\n"
          )


def authenticate():
    print(Fore.MAGENTA + """
██╗░░░░░░█████╗░░██████╗░██╗███╗░░██╗
██║░░░░░██╔══██╗██╔════╝░██║████╗░██║
██║░░░░░██║░░██║██║░░██╗░██║██╔██╗██║
██║░░░░░██║░░██║██║░░╚██╗██║██║╚████║
███████╗╚█████╔╝╚██████╔╝██║██║░╚███║
╚══════╝░╚════╝░░╚═════╝░╚═╝╚═╝░░╚══╝  """)

    try:
        username = input(Fore.BLUE + "\nEnter Username: " + Fore.RESET)
        password = getpass(Fore.BLUE + "Enter Password: " + Fore.RESET)  # getpass hides the input on the console
        #passing_args(username)
        user_credentials = get_user_credentials(username)
        if user_credentials:
            stored_hashed_password = user_credentials[1]
            if check_password(stored_hashed_password, password):
                print(Fore.GREEN + "Authentication Successful.\n" + Fore.RESET)
                return True
            else:
                print(Fore.RED + "Authentication Failed. Incorrect Password or Username.\n" + Fore.RESET)
        else:
            print(Fore.RED + "Authentication Failed. Incorrect Password or Username.\n" + Fore.RESET)
        return False

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nAuthentication interrupted by user, exiting...")
        logout_message()
        return False
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}\n" + Fore.RESET)
        return False

def get_config(filename, section):
    config = configparser.ConfigParser()
    if not config.read(filename):
        raise FileNotFoundError(Fore.RED + f"The configuration file was not found." + Fore.RESET)
    if section not in config:
        raise KeyError(f"Make sure you named the configured file correctly.")
    return config[section]

def get_user_credentials(username):
    try:
        # change the path
        db_config = get_config('C:\Shared with Kali\db.ini','database')
        connection_config_dict = {
            'user': db_config['user'],
            'password': db_config['password'],
            'host': db_config['host'],
            'database': db_config['database'],
            'raise_on_warnings': True
        }

        with mysql.connector.connect(**connection_config_dict) as conn:
            with conn.cursor(buffered=True) as cursor:
                query = "SELECT username, passwords FROM users WHERE username = %s"
                cursor.execute(query, (username,))
                result = cursor.fetchone()
                if result:
                    username, hashed_password = result
                    # Ensure hashed_password is in bytes
                    if isinstance(hashed_password, str):
                        hashed_password = hashed_password.encode('utf-8')
                    return username, hashed_password
                else:
                    return None
    except Error as e:
        print(f"Error: {e}"+ Fore.RESET)
        return None


def is_valid_username(username):
    return re.match(r'^\w{4,25}$', username) is not None

def is_valid_password(password):
    return len(password) >= 8

def is_valid_key(key):
    return len(key) == 4 and key.isdigit()

def register_user(username, password, provided_key):
    expected_key = '1212'
    # validate the key
    if not is_valid_key(provided_key) and provided_key != expected_key:
        print(Fore.RED + "Registration failed: Incorrect registration key.\n" + Fore.RESET)
        return False
    # validate the username
    if not is_valid_username(username):
        print(Fore.RED + "Registration failed: Invalid username. Only underscore is allowed as a special character "
                         "and should be more than 4 characters\n" + Fore.RESET)
        return False
    # validate the pass
    if not is_valid_password(password):
        print(Fore.RED + "Registration failed: Password has to be 8 characters or more.\n" + Fore.RESET)
        return False
    hashed_password = hash_password(password)
    try:
        db_config = get_config('db.ini', 'database')
        connection_config_dict = {
            'user': db_config['user'],
            'password': db_config['password'],
            'host': db_config['host'],
            'database': db_config['database'],
            'raise_on_warnings': True
        }

        with mysql.connector.connect(**connection_config_dict) as conn:
            with conn.cursor() as cursor:
                query = "INSERT INTO users (username, passwords) VALUES (%s, %s)"
                cursor.execute(query, (username, hashed_password))
                conn.commit()
                print(Fore.GREEN + "User registered successfully.\n")
                return True
    except Error:
        print(Fore.RED + f"Error found. Username or Password doesn't meet the requirements.\n")
        return False
    except Exception as e:
        print(Fore.RED + f"Registration failed: Exception found {e}\n")
        return False

def perform_splunk_search():
    #change the path
    config_file = 'C:\Shared with Kali\splunk.ini'
    config = get_config(config_file, 'splunk')

    splunk_host = config.get('splunk_host')
    splunk_port = config.get('splunk_port')
    username = config.get('username')
    password = config.get('password')

    search_query = 'search index=forcef'
    search_url = f'{splunk_host}:{splunk_port}/services/search/jobs'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {'search': search_query, 'output_mode': 'xml'}

    response = requests.post(search_url, headers=headers, data=data, auth=(username, password), verify=False)
    if response.status_code != 201:
        print(f"Failed to initiate search: {response.status_code}, {response.text}")
        exit()

    root = ET.fromstring(response.content)
    sid = root.find('.//sid').text

    time.sleep(10)

    results_url = f'{splunk_host}:{splunk_port}/services/search/jobs/{sid}/results?output_mode=csv'
    results_response = requests.get(results_url, headers=headers, auth=(username, password), verify=False)
    if results_response.status_code != 200:
        print(f"Failed to fetch search results: {results_response.status_code}, {results_response.text}")
        exit()
    return results_response.text

def prepare_file_path(report_name):
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    timestamp_label = f"Created at {timestamp}\n"
    name, extension = os.path.splitext(report_name)
    report_name_with_timestamp = f"{name}_{timestamp}{extension}"

    if os.name == 'nt':
        downloads_path = os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')
        # Ensure Downloads directory exists
        if not os.path.exists(downloads_path):
            os.makedirs(downloads_path)
    else:
        downloads_path = os.path.join(os.environ.get('HOME', ''), 'Downloads')
        if not os.path.exists(downloads_path):
            os.makedirs(downloads_path)

    file_path = os.path.join(downloads_path, report_name_with_timestamp)

    if not os.path.exists(downloads_path):
        os.makedirs(downloads_path)

    return file_path, timestamp_label

def save_report_to_downloads(report_content, report_name="Report.csv"):
    file_path, timestamp_label = prepare_file_path(report_name)
    try:
        with open(file_path, 'w') as file:
            file.write(report_content)
            file.write("\n\n")
            file.write(timestamp_label)
        print(Fore.GREEN + f'Report saved to {file_path}\n')
    except FileNotFoundError as e:
        print(Fore.RED + f"Error: The directory {file_path} was not found. Please ensure the Downloads directory exists.\n")
    except Exception as e:
        print(Fore.RED + f"An error occurred while trying to save the report: {e}\n")


def save_report_prediction(report_content, report_name,subject,body,receiver):
    file_path, timestamp_label = prepare_file_path(report_name)
    print("the path is: "+file_path)
    try:
        with open(file_path, 'x') as file:
            # Replace commas with newline character
            report_content = report_content.replace(',', '\n')

            # Write the report content
            file.write(report_content)
            file.write("\n\n")
            file.write(timestamp_label)
            file.write("\n")
            file.write("Note: The average confidence refers to the possibility or the certainty of the prediction.\n\n")
            file.write("The findings presented here represent potential avenues, "
                       "yet they necessitate thorough testing and deeper analysis to ascertain their validity and significance.")
        print(Fore.GREEN + f'Report saved to {file_path}\n')
        send_email(subject, body, receiver)
    except FileNotFoundError as e:
        print(Fore.RED + f"Error: The directory {file_path} was not found. Please ensure the Downloads directory exists.\n")
    except Exception as e:
        print(Fore.RED + f"An error occurred while trying to save the report: {e}\n")



def find_reports_in_downloads():
    if os.name == 'nt':  # Windows
        downloads_path = os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')
    else:  # macOS, Linux
        downloads_path = os.path.join(os.environ.get('HOME', ''), 'Downloads')
    # Check if the Downloads directory exists
    if not os.path.exists(downloads_path):
        print(Fore.RED+"Downloads directory does not exist." + Fore.RESET)
        return

    # Define the base name and extension for your files
    name = "ReportAPT"
    extension = ".txt"

    # Create a regex pattern to match filenames
    pattern = rf"{re.escape(name)}_\d{{4}}-\d{{2}}-\d{{2}}_\d{{2}}-\d{{2}}-\d{{2}}{re.escape(extension)}"

    # List and filter files based on the regex pattern
    report_files = [f for f in os.listdir(downloads_path) if re.match(pattern, f)]

    # Check if any matching files were found
    if report_files:
        print(Fore.LIGHTBLUE_EX + "\nFound report files:")
        for file in report_files:
            print(os.path.join(downloads_path, file))
    else:
        print(Fore.RED+"No history records found.\n" + Fore.RESET)

def Mitre_CTI_Group_Extract():
    try:
        url = 'https://attack.mitre.org/groups/'
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            table = soup.find('table')
            if table:
                data = []
                for row in table.find_all('tr'):
                    cols = row.find_all(['td', 'th'])
                    cols_text = [ele.text.strip() for ele in cols]
                    first_cell = row.find('td') or row.find('th')
                    if first_cell and first_cell.find('a'):
                        group_name = first_cell.text.strip()
                        group_url = first_cell.find('a')['href']
                        if not group_url.startswith('http'):
                            group_url = 'https://attack.mitre.org' + group_url
                        cols_text.append(group_url)
                    data.append(cols_text)
                headers = data.pop(0) if data else []
                save_CTI_csv(headers, data)
            else:
                print("\033[91mNo table found on the page.\033[0m")
        else:
            print("\033[91mFailed to retrieve webpage: HTTP Status Code", response.status_code, "\033[0m" + Fore.RESET)
    except requests.ConnectionError:
        print("\033[91mThere were connection errors. Please try to reconnect or check your network connection.\033[0m" + Fore.RESET)
    except Exception as e:
        print("\033[91mAn unexpected error occurred:", str(e), "\033[0m")


def save_CTI_csv(headers, data, report_name="CTI_report.csv"):
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    if "Techniques" not in headers:
        headers.append("Techniques")
    name, extension = os.path.splitext(report_name)
    report_name_with_timestamp = f"{name}_{timestamp}.csv"  # Force .csv extension
    if os.name == 'nt':  # Windows
        downloads_path = os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')
    else:  # macOS, Linux
        downloads_path = os.path.join(os.environ.get('HOME', ''), 'Downloads')
    file_path = os.path.join(downloads_path, report_name_with_timestamp)
    if not os.path.exists(downloads_path):
        os.makedirs(downloads_path)
    try:
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            csvwriter = csv.writer(csvfile)
            # Write headers to the CSV file
            csvwriter.writerow(headers)
            # Write data to the CSV file
            for row in data:
                csvwriter.writerow(row)

            print(Fore.GREEN + f'Report saved to {file_path}\n')
    except FileNotFoundError:
        print(
            Fore.RED + f"Error: The directory {downloads_path} was not found. Please ensure the Downloads directory exists.\n")
    except Exception as e:
        print(Fore.RED + f"An error occurred while trying to save the report: {e}\n")


def send_email(subject, body, receiver, sender="ForceField.IAU@gmail.com"):
    # change the path  /media/sf_Shared_with_Kali/email.ini
    email_config = get_config('C:\Shared with Kali\email.ini', 'EMAIL')
    password = email_config.get('password')

    message = MIMEMultipart()
    message["From"] = sender
    message["To"] = receiver
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    # Sending email
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)  # Use 465 for SSL
        server.starttls()  # Secure the connection
        server.login(sender, password)
        text = message.as_string()
        server.sendmail(sender, receiver, text)
        print(Fore.GREEN + "Email has been sent successfully." + Fore.RESET)
    except Exception as e:
        print(Fore.RED + f"Something went wrong... {e}" + Fore.RESET)
    finally:
        server.quit()


def sniff_it(packet):
    logging.basicConfig(level=logging.INFO)

    token_config = get_config('C:\Shared with Kali\SplunkToken.ini', 'token')
    # Splunk HEC configuration
    splunk_hec_url = token_config.get('splunk_hec_url')
    splunk_hec_token = token_config.get('splunk_hec_token')
    # change the path
    org_path = "/media/sf_Shared_with_Kali/"
    pcap_file = 'captured_traffic.pcap'
    # Set up PCAP writer
    pcap_writer = PcapWriter(pcap_file, append=True, sync=True)
    # Write packet to the PCAP file
    pcap_writer.write(packet)
    try:
        headers = {
            'Authorization': f'Splunk {splunk_hec_token}',
            'Content-Type': 'application/json',
        }
        # Check if packet contains IP layer
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            proto = packet[scapy.IP].proto
        else:
            src_ip = None
            dst_ip = None
            proto = None
        # Customize the data to send to Splunk
        payload = {
            'time': int(time.time()),  # Current timestamp
            'source': 'ForceField',  # Source identifier
            'sourcetype': 'network_traffic_all',
            'host': socket.gethostbyname(socket.gethostname()),  # Hostname or IP address of the sending system
            'event': {
                'summary': packet.summary(),  # Summary of the packet
                'src_ip': src_ip,  # Source IP address
                'dst_ip': dst_ip,  # Destination IP address
                'protocol': proto,  # Protocol
                'timestamp': int(packet.time),  # Packet timestamp
            }
        }
        response = requests.post(splunk_hec_url, headers=headers, data=json.dumps(payload), verify=False)
        if response.status_code != 200:
            # print(f"Failed to send data to Splunk: make sure your connection is stable.")
            logging.error(f"Failed to send data to Splunk: {response.status_code} {response.text}")
        else:
            logging.info(f"Packet sent to Splunk: {payload}")
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
    # Close the PCAP file
    pcap_writer.close()
    # File conversion
    subprocess.run(
        ["cicflowmeter", "-f", org_path + pcap_file, "-c", "resulted2.csv"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def main():
    interface()
    try:
        if not authenticate():
            return
        while True:
            command = input("Enter command ('help' for available commands): ").strip().lower()
            if command == 'exit':
                logout_message()
                break
            execute_command(command)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nInterrupted by user, exiting..." + Fore.RESET)
        logout_message()
    except ModuleNotFoundError as e:
        print(Fore.YELLOW + "Looks like you're facing missing libraries...Try installing one of these libraries: "
                            "colorama, bs4, scapy, requests, bcrypt, mysql-connector, and cicflowmeter ")
        logout_message()
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e.args}")


if __name__ == "__main__":
    main()



