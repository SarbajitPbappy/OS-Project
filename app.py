from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timedelta
import threading
import ipaddress
import socket
import time

app = Flask(__name__)
app.secret_key = 'sby25001'

LEASE_TIME_SECONDS = 3600

def generate_ip_pool(start_ip="192.168.1.100", end_ip="192.168.1.200"):
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    return [str(ip) for ip in range(int(start), int(end) + 1)]

IP_POOL = generate_ip_pool()

leases_dict = {}
lock = threading.Lock()

messages = {}
sent_messages = {}

def lease_cleanup_loop():
    while True:
        with lock:
            now = datetime.utcnow()
            expired_users = [user for user, lease in leases_dict.items() if lease['expiry'] < now]
            for user in expired_users:
                print(f"Lease expired for user: {user} (IP {leases_dict[user]['ip']})")
                del leases_dict[user]
                if user in messages:
                    del messages[user]
        time.sleep(60)

def get_free_ip():
    assigned_ips = {lease['ip'] for lease in leases_dict.values()}
    for ip in IP_POOL:
        ip_str = str(ipaddress.IPv4Address(ip)) if isinstance(ip, int) else ip
        if ip_str not in assigned_ips:
            return ip_str
    return None

def add_message(sender, recipient, content):
    with lock:
        msg = {'from': sender, 'content': content, 'ack': False}
        messages.setdefault(recipient, []).append(msg)
        sent_messages.setdefault(sender, []).append({'to': recipient, 'content': content, 'ack': False})

def ack_message(recipient, sender, content):
    with lock:
        if recipient in messages:
            for m in messages[recipient]:
                if m['from'] == sender and m['content'] == content and not m['ack']:
                    m['ack'] = True
                    break
        if sender in sent_messages:
            for m in sent_messages[sender]:
                if m['to'] == recipient and m['content'] == content and not m['ack']:
                    m['ack'] = True
                    break

def format_lease(lease):
    if not lease:
        return None
    ip_val = lease['ip']
    if isinstance(ip_val, int):
        ip_val = str(ipaddress.IPv4Address(ip_val))
    return {
        'ip': ip_val,
        'expiry': lease['expiry'].strftime("%Y-%m-%d %H:%M:%S UTC")
    }

def domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        print(f"Error resolving domain '{domain}': {e}")
        return None

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        if not username:
            return render_template('login.html', error="Please enter a username.")
        session['username'] = username
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    with lock:
        lease = leases_dict.get(username)
    lease = format_lease(lease)
    return render_template('index.html', username=username, lease=lease)

@app.route('/discover')
def discover():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    domain = "example.com"  # Change or make dynamic if you want
    domain_ip = domain_to_ip(domain)
    
    with lock:
        if username in leases_dict:
            message = f"You already have a lease!"
        else:
            ip = get_free_ip()
            if ip:
                ip_str = str(ipaddress.IPv4Address(ip)) if isinstance(ip, int) else ip
                leases_dict[username] = {'ip': ip_str, 'expiry': datetime.utcnow() + timedelta(seconds=LEASE_TIME_SECONDS)}
                if domain_ip:
                    message = f"IP {ip_str} offered to you. Domain '{domain}' resolves to {domain_ip}."
                else:
                    message = f"IP {ip_str} offered to you. Could not resolve domain '{domain}'."
            else:
                message = "No IP available."
        lease = leases_dict.get(username)
    lease = format_lease(lease)
    return render_template('index.html', username=username, lease=lease, message=message)

@app.route('/request')
def request_ip():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    with lock:
        lease = leases_dict.get(username)
        if lease:
            lease['expiry'] = datetime.utcnow() + timedelta(seconds=LEASE_TIME_SECONDS)
            message = f"Lease for IP {lease['ip']} confirmed."
        else:
            message = "No IP offered. Please discover first."
    lease = leases_dict.get(username)
    lease = format_lease(lease)
    return render_template('index.html', username=username, lease=lease, message=message)

@app.route('/release')
def release():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    with lock:
        if username in leases_dict:
            del leases_dict[username]
            if username in messages:
                del messages[username]
            message = "Lease released."
        else:
            message = "No lease to release."
    return render_template('index.html', username=username, lease=None, message=message)

@app.route('/leases')
def leases():
    with lock:
        leases_copy = {
            u: {
                'ip': str(ipaddress.IPv4Address(l['ip'])) if isinstance(l['ip'], int) else l['ip'],
                'expiry': l['expiry'].strftime("%Y-%m-%d %H:%M:%S UTC")
            }
            for u, l in leases_dict.items()
        }
    return render_template('leases.html', leases=leases_copy)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('login'))
    sender = session['username']
    with lock:
        if sender not in leases_dict:
            flash("You must have an active IP lease to send messages!")
            return redirect(url_for('dashboard'))
    recipient = request.form.get('recipient').strip()
    content = request.form.get('message').strip()
    with lock:
        if recipient not in leases_dict:
            flash(f"Recipient '{recipient}' does not have an active IP lease. Cannot send message.")
            return redirect(url_for('dashboard'))
    if not recipient or not content:
        flash("Recipient and message content required.")
        return redirect(url_for('dashboard'))
    if recipient == sender:
        flash("You cannot send message to yourself.")
        return redirect(url_for('dashboard'))
    add_message(sender, recipient, content)
    flash(f"Message sent to {recipient}")
    return redirect(url_for('dashboard'))

@app.route('/inbox')
def inbox():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = session['username']
    with lock:
        if user not in leases_dict:
            flash("You must have an active IP lease to receive messages.")
            return redirect(url_for('dashboard'))
        user_msgs = messages.get(user, [])
    return render_template('inbox.html', messages=user_msgs)

@app.route('/ack_message', methods=['POST'])
def ack_message_route():
    if 'username' not in session:
        return redirect(url_for('login'))
    recipient = session['username']
    sender = request.form.get('sender')
    content = request.form.get('content')
    ack_message(recipient, sender, content)
    flash(f"Acknowledgment sent to {sender}")
    return redirect(url_for('inbox'))

@app.route('/sent_messages')
def sent_msgs():
    if 'username' not in session:
        return redirect(url_for('login'))
    sender = session['username']
    s_msgs = sent_messages.get(sender, [])
    return render_template('sent_messages.html', messages=s_msgs)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    threading.Thread(target=lease_cleanup_loop, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=True)

