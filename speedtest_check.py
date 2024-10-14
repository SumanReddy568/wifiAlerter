import os
import requests
import speedtest
from getpass import getpass
from dotenv import load_dotenv
from encrypt_decrypt_config import decrypt_file

# Function to safely get the password
# def get_password(prompt):
#     try:
#         return getpass(prompt)
#     except Exception as e:
#         print(f"Warning: {e}. Attempting to read password from an environment variable.")
#         # Optionally read from an environment variable or set a default
#         return os.getenv('DECRYPTION_PASSWORD', 'default_password')  # Change 'default_password' as needed

# Decrypt environment variables before starting
# password = get_password("Enter decryption password: ")
# decrypt_file(password)

# Now load the decrypted environment variables
load_dotenv("config/encrypted_env.enc")

# Retrieve environment variables
HOME_IP = '103.74.140.160'
TELEGRAM_BOT_TOKEN = '7830200237:AAF0RCojXgWJMgUENms9RwDb9xni6Ax4Mp4'
CHAT_ID = 1271078205

# Define constants
HOME_ISP = "Atri Networks And Media Pvt Ltd"
DOWNLOAD_THRESHOLD = 80.0  # in Mbps
UPLOAD_THRESHOLD = 80.0    # in Mbps

def get_current_ip_info():
    """Get the current public IP address and ISP information."""
    try:
        response = requests.get("http://ip-api.com/json/")
        response.raise_for_status()  # Raise an error for bad responses
        ip_data = response.json()
        return ip_data['query'], ip_data['isp']
    except Exception as e:
        print(f"Error retrieving IP info: {e}")
        return None, None

def send_telegram_message(message):
    """Send a message to the Telegram chat via bot."""
    url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
    data = {'chat_id': CHAT_ID, 'text': message}
    try:
        response = requests.post(url, data=data)
        response.raise_for_status()  # Raise an error for bad responses
    except Exception as e:
        print(f"Error sending message: {e}")

def check_speed():
    """Check the internet speed (both download and upload) and send an alert if below threshold."""
    current_ip, current_isp = get_current_ip_info()

    if current_ip is None or current_isp is None:
        print("Failed to get current IP information. Exiting.")
        return

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
