import speedtest
import requests
import os
from getpass import getpass
from cryptography.fernet import Fernet
from wifiAlerter.encrypt_decrypt_config import decrypt_file
from dotenv import load_dotenv

# Decrypt environment variables before starting
password = getpass("Enter decryption password: ")
decrypt_file(password)

# Now load the decrypted environment variables
load_dotenv("config/encrypted_env.enc")

# Retrieve environment variables
HOME_IP = '103.74.140.160'
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_TOKEN')
CHAT_ID=1271078205


# Define constants
HOME_ISP = "Atri Networks And Media Pvt Ltd"
DOWNLOAD_THRESHOLD = 80.0  
UPLOAD_THRESHOLD = 80.0

def get_current_ip_info():
    """Get the current public IP address and ISP information."""
    response = requests.get("http://ip-api.com/json/")
    ip_data = response.json()
    return ip_data['query'], ip_data['isp']

def send_telegram_message(message):
    """Send a message to the Telegram chat via bot."""
    url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
    data = {'chat_id': CHAT_ID, 'text': message}
    response = requests.post(url, data=data)
    if response.status_code != 200:
        raise Exception(f"Error sending message: {response.text}")

def check_speed():
    """Check the internet speed (both download and upload) and send an alert if below threshold."""
    current_ip, current_isp = get_current_ip_info()

    if current_ip != HOME_IP or current_isp != HOME_ISP:
        message = (f"⚠️ Not connected to home Wi-Fi. "
                   f"Current IP: {current_ip}, ISP: {current_isp}. Speed test skipped.")
        send_telegram_message(message)
        return

    st = speedtest.Speedtest()
    st.get_best_server()

    # Check download speed
    download_speed = st.download() / 1_000_000  # Convert to Mbps
    # Check upload speed
    upload_speed = st.upload() / 1_000_000  # Convert to Mbps

    # Create a message based on the speed check
    if download_speed < DOWNLOAD_THRESHOLD or upload_speed < UPLOAD_THRESHOLD:
        message = (f"⚠️ Alert! Internet speed is below the threshold.\n"
                   f"Download speed: {download_speed:.2f} Mbps (Threshold: {DOWNLOAD_THRESHOLD} Mbps)\n"
                   f"Upload speed: {upload_speed:.2f} Mbps (Threshold: {UPLOAD_THRESHOLD} Mbps)")
        send_telegram_message(message)
    else:
        print(f"✅ Speed is fine. Download: {download_speed:.2f} Mbps, Upload: {upload_speed:.2f} Mbps")

if __name__ == "__main__":
    check_speed()
