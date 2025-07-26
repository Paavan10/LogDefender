import re
import pandas as pd
from datetime import datetime

apache_log_path = "access.log"
ssh_log_path = "auth.log"

def parse_apache_logs(filepath):
    apache_entries = []
    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] ".*?" \d+ \d+')
    
    with open(filepath) as f:
        for line in f:
            match = pattern.search(line)
            if match:
                ip, timestamp = match.groups()
                timestamp = datetime.strptime(timestamp.split()[0], "%d/%b/%Y:%H:%M:%S")
                apache_entries.append({'IP': ip, 'Timestamp': timestamp})
    return pd.DataFrame(apache_entries)

def parse_ssh_logs(filepath):
    ssh_entries = []
    pattern = re.compile(r'Failed password.*from (\d+\.\d+\.\d+\.\d+)')
    
    with open(filepath) as f:
        for line in f:
            match = pattern.search(line)
            if match:
                ip = match.group(1)
                timestamp = " ".join(line.split()[:3])
                timestamp = datetime.strptime(timestamp, "%b %d %H:%M:%S")
                ssh_entries.append({'IP': ip, 'Timestamp': timestamp})
    return pd.DataFrame(ssh_entries)

def parse_ftp_logs(filepath):  # 🔹 Your new function goes here!
    entries = []
    pattern = re.compile(r'FAIL LOGIN: Client "(\d+\.\d+\.\d+\.\d+)", USER "(.*?)"')
    with open(filepath) as f:
        for line in f:
            match = pattern.search(line)
            if match:
                ip, user = match.groups()
                entries.append({'IP': ip, 'User': user})
    return pd.DataFrame(entries)

def detect_brute_force(df, threshold=5):
    attempts = df.groupby('IP').size().reset_index(name='Attempts')
    return attempts[attempts['Attempts'] > threshold]

def detect_scanning(df):
    return df[df['IP'].duplicated(keep=False)]

import matplotlib.pyplot as plt
import seaborn as sns

def visualize_attempts(df, title="Access Frequency"):
    df['Hour'] = df['Timestamp'].dt.hour
    hourly_counts = df.groupby(['Hour']).size()
    hourly_counts.plot(kind='bar', title=title, color='orange')
    plt.xlabel('Hour')
    plt.ylabel('Requests')
    plt.tight_layout()
    plt.show()
    
def visualize_ftp_attacker_ips(df, title="Top Attacker IPs in FTP Logs"):
    ip_counts = df['IP'].value_counts()
    ip_counts.plot(kind='bar', color='skyblue', title=title)
    plt.xlabel('IP Address')
    plt.ylabel('Failed Attempts')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def visualize_ftp_user_targets(df, title="FTP Login Attempted Usernames"):
    user_counts = df['User'].value_counts()
    user_counts.plot(kind='bar', color='salmon', title=title)
    plt.xlabel('Username')
    plt.ylabel('Failed Attempts')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


import requests

def is_ip_blacklisted(ip):
    url = f"https://blacklist-api.enciva.io/check/{ip}"  # Use your own trusted IP blacklist API
    try:
        response = requests.get(url)
        return response.json().get('blacklisted', False)
    except:
        return False

def flag_blacklisted_ips(df):
    df['Blacklisted'] = df['IP'].apply(is_ip_blacklisted)
    return df[df['Blacklisted']]

def export_report(df, filename='incident_report.csv'):
    df.to_csv(filename, index=False)
    print(f"[+] Exported report to {filename}")

if __name__ == "__main__":
    apache_df = parse_apache_logs(apache_log_path)
    ssh_df = parse_ssh_logs(ssh_log_path)
    ftp_df = parse_ftp_logs("ftp.log")

    # 🚨 Detect & Report FTP Brute Force
    brute_force_ftp = detect_brute_force(ftp_df)
    export_report(brute_force_ftp, "ftp_brute_force_report.csv")

    # 📊 Visualize FTP Attacks
    visualize_ftp_attacker_ips(ftp_df, "Top Attacker IPs in FTP Logs")
    visualize_ftp_user_targets(ftp_df, "Top Usernames Targeted in FTP")

    # 🚨 Detect & Report SSH Brute Force
    brute_force_ips = detect_brute_force(ssh_df)
    export_report(brute_force_ips, 'brute_force_report.csv')

    # 🚨 Check Apache Blacklisted IPs
    blacklisted_apache = flag_blacklisted_ips(apache_df)
    export_report(blacklisted_apache, 'blacklisted_apache_report.csv')

    # 📊 Visualize Apache and SSH Logs
    visualize_attempts(apache_df, "Apache Hourly Access")
    visualize_attempts(ssh_df, "SSH Failed Attempts")
