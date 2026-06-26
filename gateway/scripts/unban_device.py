#!/usr/bin/env python3
"""
Recovery script for devices banned by the Trust Engine
Allows you to unblock a banned device and restore its trust score
"""
import sqlite3
import sys
import os
from datetime import datetime

# Database path
DB_PATH = os.getenv("DB_PATH", "/app/data/gateway.db")

def list_banned_devices():
    '''List of all currently banned devices'''
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT node_id, trust_score, last_seen, created_at 
            FROM devices 
            WHERE status = 1
        """)
        devices = cursor.fetchall()
        conn.close()
        return devices
    except Exception as e:
        print(f"Error while reading the database: {e}")
        return []

def get_device_info(node_id):
    '''Show detailed information about a device'''
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT node_id, trust_score, status, last_seen, created_at 
            FROM devices 
            WHERE node_id = ?
        """, (node_id,))
        device = cursor.fetchone()
        conn.close()
        return device
    except Exception as e:
        print(f"Error while reading the database: {e}")
        return None

def unban_device(node_id, reset_trust=True):
    '''
    Unblock a banned device
    
    Args:
        node_id: ID of the device to be unblocked
        reset_trust: If True, resets the trust score to 100
    '''
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check that the device exists
        cursor.execute("SELECT node_id, status, trust_score FROM devices WHERE node_id = ?", (node_id,))
        device = cursor.fetchone()
        
        if not device:
            print(f"Devide '{node_id}' not found in database,")
            conn.close()
            return False
        
        current_status = device[1]
        current_trust = device[2]
        
        if current_status == 0:
            print(f"Device '{node_id}' it's not banned (status=0)")
            print(f"    Actual Trust Score: {current_trust:.1f}")
            conn.close()
            return False
        
        # Update the status and the trust score (optionally)
        if reset_trust:
            cursor.execute("""
                UPDATE devices 
                SET status = 0, trust_score = 100.0, last_seen = ? 
                WHERE node_id = ?
            """, (datetime.now(), node_id))
            print(f"Device '{node_id}' unbanned.")
            print(f"   Status: 1 (banned) → 0 (active)")
            print(f"   Trust score: {current_trust:.1f} → 100.0 (restored)")
        else:
            cursor.execute("""
                UPDATE devices 
                SET status = 0, last_seen = ? 
                WHERE node_id = ?
            """, (datetime.now(), node_id))
            print(f"Device '{node_id}' unbanned,")
            print(f"   Status: 1 (banned) → 0 (active)")
            print(f"   Trust score retained: {current_trust:.1f}")
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        print(f"Error while device unbanning: {e}")
        return False

def main():
    print("=" * 60)
    print("   Smart MicroGrid - Recovery Tool for banned devides")
    print("=" * 60)
    print()
    
    # Check the DB path
    if not os.path.exists(DB_PATH):
        print(f"Database not fount in: {DB_PATH}")
        print("Check that the path is correct or set DB_PATH")
        sys.exit(1)
    
    print("Devices currently banned:")
    print("-" * 60)
    banned_devices = list_banned_devices()
    
    if not banned_devices:
        print("No banned devices found!")
        return
    
    for device in banned_devices:
        node_id, trust_score, last_seen, created_at = device
        print(f"  • Node ID: {node_id}")
        print(f"    Trust score: {trust_score:.1f}")
        print(f"    Last activity: {last_seen or 'N/A'}")
        print(f"    Registered: {created_at}")
        print()
    
    # Unban request
    print("-" * 60)
    node_id = input("Enter the Node ID to unlock (or “exit” to leave): ").strip()
    
    if node_id.lower() in ['exit', 'quit', 'q']:
        print("Exiting...")
        return
    
    if not node_id:
        print("Node ID not valid")
        return
    
    # Shows device info
    device_info = get_device_info(node_id)
    if not device_info:
        return
    
    print()
    print("Device info:")
    print(f"   Node ID: {device_info[0]}")
    print(f"   Trust score: {device_info[1]:.1f}")
    print(f"   Status: {device_info[2]} ({'bannato' if device_info[2] == 1 else 'attivo'})")
    print()
    
    # Trust restoration option
    reset_choice = input("Would you like to reset the trust score to 100 as well? (y/n) [y]: ").strip().lower()
    reset_trust = reset_choice in ['', 'y', 'yes']
    
    # Confirm
    confirm = input(f"Do you confirm unbanning device: '{node_id}'? (y/n): ").strip().lower()
    if confirm not in ['', 'y', 'yes']:
        print("Aborted")
        return
    
    # Unblocking
    print()
    success = unban_device(node_id, reset_trust=reset_trust)
    
    if success:
        print()
        print("=" * 60)
        print("Operation completed!")
        print("   The device can now reconnect to the system.")
        print("=" * 60)

if __name__ == "__main__":
    main()