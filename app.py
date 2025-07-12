from flask import Flask, render_template, request, jsonify, session, make_response, send_from_directory
from flask_session import Session
import sqlite3
from datetime import datetime
import hashlib
import csv
from io import StringIO, BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import logging
import re

app = Flask(__name__)

# Configure Flask-Session
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_NAME'] = 'camera_service_session'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True

# Initialize Flask-Session
Session(app)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Valid statuses
VALID_STATUSES = ['Received', 'In Diagnosis', 'Under Repair', 'Ready', 'Delivered']

# Database setup
def init_db():
    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()

    # Check if tables exist and create them only if they don't
    c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='customers' ''')
    if c.fetchone()[0] == 0:
        c.execute('''
            CREATE TABLE customers (
                customer_id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_name TEXT NOT NULL,
                customer_email TEXT NOT NULL,
                phone_number TEXT NOT NULL UNIQUE
            )
        ''')

    c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='service_records' ''')
    if c.fetchone()[0] == 0:
        c.execute('''
            CREATE TABLE service_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER NOT NULL,
                camera_brand TEXT NOT NULL,
                camera_model TEXT NOT NULL,
                serial_number TEXT NOT NULL,
                service_issue TEXT NOT NULL,
                received_date TEXT NOT NULL,
                delivery_date TEXT,
                status TEXT NOT NULL,
                total_amount REAL NOT NULL DEFAULT 0,
                amount_paid REAL NOT NULL DEFAULT 0,
                admin_id INTEGER NOT NULL,
                FOREIGN KEY (customer_id) REFERENCES customers (customer_id),
                FOREIGN KEY (admin_id) REFERENCES admins (admin_id)
            )
        ''')
    else:
        # Check if admin_id column exists, add it if not
        c.execute('PRAGMA table_info(service_records)')
        columns = [info[1] for info in c.fetchall()]
        if 'admin_id' not in columns:
            c.execute('ALTER TABLE service_records ADD COLUMN admin_id INTEGER NOT NULL DEFAULT 1')
            # Set default admin_id to 1 (superadmin) for existing records
            c.execute('''
                UPDATE service_records SET admin_id = 1
                WHERE admin_id IS NULL
            ''')

        # Check if total_amount and amount_paid columns exist, add them if not
        if 'total_amount' not in columns:
            c.execute('ALTER TABLE service_records ADD COLUMN total_amount REAL NOT NULL DEFAULT 0')
        if 'amount_paid' not in columns:
            c.execute('ALTER TABLE service_records ADD COLUMN amount_paid REAL NOT NULL DEFAULT 0')

    c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='admins' ''')
    if c.fetchone()[0] == 0:
        c.execute('''
            CREATE TABLE admins (
                admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('super_admin', 'admin')),
                created_at TEXT NOT NULL
            )
        ''')

        # Insert default Super Admin
        default_super_admin = {
            'username': 'superadmin',
            'password': hashlib.sha256('SuperAdmin2025'.encode()).hexdigest(),
            'role': 'super_admin',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        c.execute('''
            INSERT INTO admins (username, password, role, created_at)
            VALUES (?, ?, ?, ?)
        ''', (
            default_super_admin['username'],
            default_super_admin['password'],
            default_super_admin['role'],
            default_super_admin['created_at']
        ))

        # Insert default Admin
        default_admin = {
            'username': 'admin',
            'password': hashlib.sha256('CameraPro2025'.encode()).hexdigest(),
            'role': 'admin',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        c.execute('''
            INSERT INTO admins (username, password, role, created_at)
            VALUES (?, ?, ?, ?)
        ''', (
            default_admin['username'],
            default_admin['password'],
            default_admin['role'],
            default_admin['created_at']
        ))

    else:
        # Ensure default Super Admin exists
        c.execute('SELECT COUNT(*) FROM admins WHERE username = ?', ('superadmin',))
        if c.fetchone()[0] == 0:
            default_super_admin = {
                'username': 'superadmin',
                'password': hashlib.sha256('SuperAdmin2025'.encode()).hexdigest(),
                'role': 'super_admin',
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            c.execute('''
                INSERT INTO admins (username, password, role, created_at)
                VALUES (?, ?, ?, ?)
            ''', (
                default_super_admin['username'],
                default_super_admin['password'],
                default_super_admin['role'],
                default_super_admin['created_at']
            ))

        # Ensure default Admin exists
        c.execute('SELECT COUNT(*) FROM admins WHERE username = ?', ('admin',))
        if c.fetchone()[0] == 0:
            default_admin = {
                'username': 'admin',
                'password': hashlib.sha256('CameraPro2025'.encode()).hexdigest(),
                'role': 'admin',
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            c.execute('''
                INSERT INTO admins (username, password, role, created_at)
                VALUES (?, ?, ?, ?)
            ''', (
                default_admin['username'],
                default_admin['password'],
                default_admin['role'],
                default_admin['created_at']
            ))

    conn.commit()
    conn.close()

# Serve favicon
@app.route('/favicon.ico')
def favicon():
    try:
        return send_from_directory(app.static_folder, 'favicon.ico')
    except FileNotFoundError:
        logger.warning("Favicon not found in static folder")
        return '', 204

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = hashlib.sha256(data.get('password').encode()).hexdigest()

    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()
    c.execute('SELECT role, admin_id FROM admins WHERE username = ? AND password = ?', (username, password))
    admin = c.fetchone()
    conn.close()

    if admin:
        session['logged_in'] = True
        session['username'] = username
        session['role'] = admin[0]
        session['admin_id'] = admin[1]
        logger.debug(f"User {username} logged in successfully")
        return jsonify({'message': 'Login successful', 'role': admin[0]}), 200
    else:
        logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('admin_id', None)
    logger.debug("User logged out")
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/check_session', methods=['GET'])
def check_session():
    logged_in = session.get('logged_in', False)
    role = session.get('role', 'admin')
    username = session.get('username', 'Admin')
    return jsonify({'logged_in': logged_in, 'role': role, 'username': username})

@app.route('/api/records', methods=['GET'])
def get_records():
    if not session.get('logged_in'):
        logger.warning("Unauthorized attempt to access records")
        return jsonify({'message': 'Unauthorized'}), 401

    name = request.args.get('name', '')
    serial = request.args.get('serial', '')
    phone = request.args.get('phone', '')
    status = request.args.get('status', '')
    admin = request.args.get('admin', '')
    role = session.get('role', 'admin')
    admin_id = session.get('admin_id')

    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()
    query = '''
        SELECT sr.id, c.customer_id, c.customer_name, c.customer_email, c.phone_number,
               sr.camera_brand, sr.camera_model, sr.serial_number, sr.service_issue,
               sr.received_date, sr.delivery_date, sr.status, sr.total_amount, sr.amount_paid,
               a.username
        FROM service_records sr
        JOIN customers c ON sr.customer_id = c.customer_id
        JOIN admins a ON sr.admin_id = a.admin_id
        WHERE 1=1
    '''
    params = []

    # Restrict regular admins to their own records
    if role == 'admin':
        query += ' AND sr.admin_id = ?'
        params.append(admin_id)
    elif role == 'super_admin' and admin:
        query += ' AND a.username = ?'
        params.append(admin)

    if name:
        query += ' AND c.customer_name LIKE ?'
        params.append(f'%{name}%')
    if serial:
        query += ' AND sr.serial_number LIKE ?'
        params.append(f'%{serial}%')
    if phone:
        query += ' AND c.phone_number LIKE ?'
        params.append(f'%{phone}%')
    if status:
        query += ' AND sr.status = ?'
        params.append(status)

    try:
        c.execute(query, params)
        records = c.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Database error in get_records: {str(e)}")
        conn.close()
        return jsonify({'message': 'Database error'}), 500

    conn.close()

    return jsonify([
        {
            'id': record[0],
            'customer_id': record[1],
            'customer_name': record[2],
            'customer_email': record[3],
            'phone_number': record[4],
            'camera_brand': record[5],
            'camera_model': record[6],
            'serial_number': record[7],
            'service_issue': record[8],
            'received_date': record[9],
            'delivery_date': record[10],
            'status': record[11],
            'total_amount': record[12],
            'amount_paid': record[13],
            'admin_username': record[14]
        } for record in records
    ])

@app.route('/api/records', methods=['POST'])
def add_record():
    if not session.get('logged_in'):
        logger.warning("Unauthorized attempt to add record")
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.get_json()
    required_fields = [
        'customer_name', 'customer_email', 'phone_number',
        'camera_brand', 'camera_model', 'serial_number',
        'service_issue', 'received_date', 'status'
    ]

    if not all(field in data for field in required_fields):
        missing = [field for field in required_fields if field not in data]
        logger.error(f"Missing fields: {missing}")
        return jsonify({'message': f'Missing required fields: {", ".join(missing)}'}), 400

    # Check if received_date is empty
    if not data['received_date']:
        logger.error("Received Date is empty")
        return jsonify({'message': 'Received Date is required and cannot be empty'}), 400

    # Validate data formats and lengths
    try:
        if not (2 <= len(data['customer_name']) <= 50):
            logger.error(f"Invalid customer_name length: {len(data['customer_name'])}")
            return jsonify({'message': 'Customer name must be 2-50 characters'}), 400
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', data['customer_email']):
            logger.error(f"Invalid email format: {data['customer_email']}")
            return jsonify({'message': 'Invalid email format'}), 400
        if not (10 <= len(data['phone_number']) <= 15 and data['phone_number'].isdigit()):
            logger.error(f"Invalid phone_number: {data['phone_number']}")
            return jsonify({'message': 'Phone number must be 10-15 digits'}), 400
        if not (2 <= len(data['camera_brand']) <= 50):
            logger.error(f"Invalid camera_brand length: {len(data['camera_brand'])}")
            return jsonify({'message': 'Camera brand must be 2-50 characters'}), 400
        if not (2 <= len(data['camera_model']) <= 50):
            logger.error(f"Invalid camera_model length: {len(data['camera_model'])}")
            return jsonify({'message': 'Camera model must be 2-50 characters'}), 400
        if not (5 <= len(data['serial_number']) <= 20):
            logger.error(f"Invalid serial_number length: {len(data['serial_number'])}")
            return jsonify({'message': 'Serial number must be 5-20 characters'}), 400
        if not (10 <= len(data['service_issue']) <= 200):
            logger.error(f"Invalid service_issue length: {len(data['service_issue'])}")
            return jsonify({'message': 'Service issue must be 10-200 characters'}), 400
        datetime.strptime(data['received_date'], '%Y-%m-%d')
        if data.get('delivery_date'):
            datetime.strptime(data.get('delivery_date'), '%Y-%m-%d')
        if data['status'] not in VALID_STATUSES:
            logger.error(f"Invalid status: {data['status']}")
            return jsonify({'message': f"Invalid status: {data['status']}. Must be one of {VALID_STATUSES}"}), 400
        total_amount = float(data.get('total_amount', 0))
        amount_paid = float(data.get('amount_paid', 0))
        if total_amount < 0 or amount_paid < 0:
            logger.error(f"Negative amounts: total_amount={total_amount}, amount_paid={amount_paid}")
            return jsonify({'message': 'Total Amount and Amount Paid must be non-negative'}), 400
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return jsonify({'message': 'Invalid date or numeric format'}), 400

    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()

    try:
        # Check if customer exists by phone_number
        c.execute('SELECT customer_id FROM customers WHERE phone_number = ?', (data['phone_number'],))
        customer = c.fetchone()

        if customer:
            customer_id = customer[0]
            c.execute('''
                UPDATE customers SET customer_name = ?, customer_email = ?
                WHERE customer_id = ?
            ''', (data['customer_name'], data['customer_email'], customer_id))
        else:
            c.execute('''
                INSERT INTO customers (customer_name, customer_email, phone_number)
                VALUES (?, ?, ?)
            ''', (data['customer_name'], data['customer_email'], data['phone_number']))
            customer_id = c.lastrowid

        # Insert service record with admin_id
        c.execute('''
            INSERT INTO service_records (
                customer_id, camera_brand, camera_model, serial_number,
                service_issue, received_date, delivery_date, status,
                total_amount, amount_paid, admin_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            customer_id, data['camera_brand'], data['camera_model'], data['serial_number'],
            data['service_issue'], data['received_date'], data.get('delivery_date'), data['status'],
            total_amount, amount_paid, session['admin_id']
        ))
        record_id = c.lastrowid
        conn.commit()
        logger.debug(f"Record added successfully: id={record_id}, customer_name={data['customer_name']}")
        conn.close()
        return jsonify({'message': 'Record added successfully', 'id': record_id}), 201
    except sqlite3.IntegrityError as e:
        logger.error(f"Database integrity error: {str(e)}")
        conn.close()
        return jsonify({'message': 'Phone number already exists for another customer'}), 400
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)}")
        conn.close()
        return jsonify({'message': 'Database error'}), 500

@app.route('/api/records/<int:record_id>', methods=['PUT'])
def update_record(record_id):
    if not session.get('logged_in'):
        logger.warning("Unauthorized attempt to update record")
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.get_json()
    role = session.get('role', 'admin')
    admin_id = session.get('admin_id')

    # Define required fields based on role
    if role == 'super_admin':
        required_fields = [
            'customer_name', 'customer_email', 'phone_number',
            'camera_brand', 'camera_model', 'serial_number',
            'service_issue', 'received_date', 'status'
        ]
    else:
        required_fields = [
            'customer_name', 'customer_email', 'phone_number',
            'camera_brand', 'camera_model', 'serial_number', 'status'
        ]

    # Check for missing required fields
    if not all(field in data for field in required_fields):
        missing = [field for field in required_fields if field not in data]
        logger.error(f"Missing fields for update: {missing}")
        return jsonify({'message': f'Missing required fields: {", ".join(missing)}'}), 400

    # Validate common fields
    try:
        if not (2 <= len(data['customer_name']) <= 50):
            logger.error(f"Invalid customer_name length: {len(data['customer_name'])}")
            return jsonify({'message': 'Customer name must be 2-50 characters'}), 400
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', data['customer_email']):
            logger.error(f"Invalid email format: {data['customer_email']}")
            return jsonify({'message': 'Invalid email format'}), 400
        if not (10 <= len(data['phone_number']) <= 15 and data['phone_number'].isdigit()):
            logger.error(f"Invalid phone_number: {data['phone_number']}")
            return jsonify({'message': 'Phone number must be 10-15 digits'}), 400
        if not (2 <= len(data['camera_brand']) <= 50):
            logger.error(f"Invalid camera_brand length: {len(data['camera_brand'])}")
            return jsonify({'message': 'Camera brand must be 2-50 characters'}), 400
        if not (2 <= len(data['camera_model']) <= 50):
            logger.error(f"Invalid camera_model length: {len(data['camera_model'])}")
            return jsonify({'message': 'Camera model must be 2-50 characters'}), 400
        if not (5 <= len(data['serial_number']) <= 20):
            logger.error(f"Invalid serial_number length: {len(data['serial_number'])}")
            return jsonify({'message': 'Serial number must be 5-20 characters'}), 400
        if data['status'] not in VALID_STATUSES:
            logger.error(f"Invalid status: {data['status']}")
            return jsonify({'message': f"Invalid status: {data['status']}. Must be one of {VALID_STATUSES}"}), 400
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return jsonify({'message': 'Invalid data format'}), 400

    # Additional validations for Super Admin
    if role == 'super_admin':
        try:
            if not (10 <= len(data['service_issue']) <= 200):
                logger.error(f"Invalid service_issue length: {len(data['service_issue'])}")
                return jsonify({'message': 'Service issue must be 10-200 characters'}), 400
            if not data['received_date']:
                logger.error("Received Date is empty")
                return jsonify({'message': 'Received Date is required'}), 400
            datetime.strptime(data['received_date'], '%Y-%m-%d')
            if data.get('delivery_date'):
                datetime.strptime(data.get('delivery_date'), '%Y-%m-%d')
            total_amount = float(data.get('total_amount', 0))
            amount_paid = float(data.get('amount_paid', 0))
            if total_amount < 0 or amount_paid < 0:
                logger.error(f"Negative amounts: total_amount={total_amount}, amount_paid={amount_paid}")
                return jsonify({'message': 'Total Amount and Amount Paid must be non-negative'}), 400
        except ValueError as e:
            logger.error(f"Super Admin validation error: {str(e)}")
            return jsonify({'message': 'Invalid date or numeric format'}), 400

    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()

    try:
        # Check if the record exists and belongs to the admin (for regular admins)
        c.execute('SELECT customer_id, admin_id FROM service_records WHERE id = ?', (record_id,))
        record = c.fetchone()
        if not record:
            conn.close()
            logger.error(f"Record not found: id={record_id}")
            return jsonify({'message': 'Record not found'}), 404

        customer_id = record[0]
        record_admin_id = record[1]
        if role == 'admin' and record_admin_id != admin_id:
            conn.close()
            logger.warning(f"Unauthorized update attempt by admin_id={admin_id} on record_id={record_id}")
            return jsonify({'message': 'Unauthorized: You can only update your own records'}), 403

        # Update customer details
        c.execute('''
            UPDATE customers SET
                customer_name = ?, customer_email = ?, phone_number = ?
            WHERE customer_id = ?
        ''', (data['customer_name'], data['customer_email'], data['phone_number'], customer_id))

        # Update service record based on role
        if role == 'super_admin':
            c.execute('''
                UPDATE service_records SET
                    camera_brand = ?, camera_model = ?, serial_number = ?,
                    service_issue = ?, received_date = ?, delivery_date = ?,
                    status = ?, total_amount = ?, amount_paid = ?
                WHERE id = ?
            ''', (
                data['camera_brand'], data['camera_model'], data['serial_number'],
                data['service_issue'], data['received_date'], data.get('delivery_date'),
                data['status'], total_amount, amount_paid, record_id
            ))
        else:
            c.execute('''
                UPDATE service_records SET
                    camera_brand = ?, camera_model = ?, serial_number = ?, status = ?
                WHERE id = ?
            ''', (
                data['camera_brand'], data['camera_model'], data['serial_number'],
                data['status'], record_id
            ))

        conn.commit()
        logger.debug(f"Record updated successfully: id={record_id}, role={role}")
        conn.close()
        return jsonify({'message': 'Record updated successfully'}), 200
    except sqlite3.IntegrityError as e:
        logger.error(f"Database integrity error: {str(e)}")
        conn.close()
        return jsonify({'message': 'Phone number already exists for another customer'}), 400
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)}")
        conn.close()
        return jsonify({'message': 'Database error'}), 500

@app.route('/api/records/<int:record_id>', methods=['DELETE'])
def delete_record(record_id):
    if not session.get('logged_in'):
        logger.warning("Unauthorized attempt to delete record")
        return jsonify({'message': 'Unauthorized'}), 401

    role = session.get('role', 'admin')
    admin_id = session.get('admin_id')

    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()

    try:
        # Check if the record exists and belongs to the admin (for regular admins)
        c.execute('SELECT customer_id, admin_id FROM service_records WHERE id = ?', (record_id,))
        record = c.fetchone()
        if not record:
            conn.close()
            logger.error(f"Record not found: id={record_id}")
            return jsonify({'message': 'Record not found'}), 404

        customer_id = record[0]
        record_admin_id = record[1]
        if role == 'admin' and record_admin_id != admin_id:
            conn.close()
            logger.warning(f"Unauthorized delete attempt by admin_id={admin_id} on record_id={record_id}")
            return jsonify({'message': 'Unauthorized: You can only delete your own records'}), 403

        # Delete the service record
        c.execute('DELETE FROM service_records WHERE id = ?', (record_id,))

        # Check if the customer has other service records
        c.execute('SELECT COUNT(*) FROM service_records WHERE customer_id = ?', (customer_id,))
        if c.fetchone()[0] == 0:
            c.execute('DELETE FROM customers WHERE customer_id = ?', (customer_id,))

        conn.commit()
        logger.debug(f"Record deleted successfully: id={record_id}")
        conn.close()
        return jsonify({'message': 'Record deleted successfully'}), 200
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)}")
        conn.close()
        return jsonify({'message': 'Database error'}), 500

@app.route('/api/records/bulk_delete', methods=['DELETE'])
def bulk_delete_records():
    if not session.get('logged_in'):
        logger.warning("Unauthorized attempt to bulk delete records")
        return jsonify({'message': 'Unauthorized'}), 401

    role = session.get('role', 'admin')
    admin_id = session.get('admin_id')
    data = request.get_json()
    record_ids = data.get('record_ids', [])

    if not record_ids:
        logger.error("No record IDs provided for bulk delete")
        return jsonify({'message': 'No records selected for deletion'}), 400

    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()

    try:
        # Verify that all records belong to the admin (for regular admins)
        if role == 'admin':
            c.execute('''
                SELECT id FROM service_records
                WHERE id IN ({}) AND admin_id = ?
            '''.format(','.join('?' * len(record_ids))), record_ids + [admin_id])
            valid_record_ids = [row[0] for row in c.fetchall()]
            if len(valid_record_ids) != len(record_ids):
                conn.close()
                logger.warning(f"Unauthorized bulk delete attempt by admin_id={admin_id} on some records")
                return jsonify({'message': 'Unauthorized: You can only delete your own records'}), 403
        else:
            valid_record_ids = record_ids

        # Get customer IDs for the records to be deleted
        customer_ids = []
        for record_id in valid_record_ids:
            c.execute('SELECT customer_id FROM service_records WHERE id = ?', (record_id,))
            record = c.fetchone()
            if record:
                customer_ids.append(record[0])

        # Delete the service records
        c.executemany('DELETE FROM service_records WHERE id = ?', [(id,) for id in valid_record_ids])

        # Check and delete customers with no remaining service records
        for customer_id in set(customer_ids):
            c.execute('SELECT COUNT(*) FROM service_records WHERE customer_id = ?', (customer_id,))
            if c.fetchone()[0] == 0:
                c.execute('DELETE FROM customers WHERE customer_id = ?', (customer_id,))

        conn.commit()
        logger.debug(f"Bulk deleted {len(valid_record_ids)} records")
        conn.close()
        return jsonify({'message': f'{len(valid_record_ids)} records deleted successfully'}), 200
    except sqlite3.Error as e:
        logger.error(f"Database error in bulk delete: {str(e)}")
        conn.close()
        return jsonify({'message': 'Database error'}), 500

@app.route('/api/records/<int:record_id>/invoice', methods=['GET'])
def generate_invoice(record_id):
    if not session.get('logged_in'):
        logger.warning("Unauthorized attempt to generate invoice")
        return jsonify({'message': 'Unauthorized'}), 401

    role = session.get('role', 'admin')
    admin_id = session.get('admin_id')

    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()

    query = '''
        SELECT c.customer_name, c.customer_email, c.phone_number,
               sr.camera_brand, sr.camera_model, sr.serial_number, sr.service_issue,
               sr.received_date, sr.delivery_date, sr.status, sr.total_amount, sr.amount_paid
        FROM service_records sr
        JOIN customers c ON sr.customer_id = c.customer_id
        WHERE sr.id = ?
    '''
    params = [record_id]
    if role == 'admin':
        query += ' AND sr.admin_id = ?'
        params.append(admin_id)

    c.execute(query, params)
    record = c.fetchone()
    conn.close()

    if not record:
        logger.error(f"Record not found for invoice: id={record_id}")
        return jsonify({'message': 'Record not found or unauthorized'}), 404

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Add logo if available
    from reportlab.platypus import Image
    import os
    logo_path = os.path.join("static", "logo.png")
    if os.path.exists(logo_path):
        img = Image(logo_path, width=120, height=50)
        elements.append(img)

    # Title
    title_style = styles['Title']
    title_style.fontSize = 18
    title_style.leading = 20
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("CAMERA PORT", title_style))
    elements.append(Spacer(1, 12))

    # Two-column layout: Left = Customer Info, Right = Device Info
    customer_data = [
        ['Customer Name:', record[0]],
        ['Email:', record[1]],
        ['Phone:', record[2]]
    ]
    device_data = [
        ['Camera Brand:', record[3]],
        ['Camera Model:', record[4]],
        ['Serial Number:', record[5]],
    ]

    # Create two tables and place them side by side
    customer_table = Table(customer_data, colWidths=[100, 200])
    device_table = Table(device_data, colWidths=[100, 200])
    customer_table.setStyle(TableStyle([('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                                        ('FONTSIZE', (0, 0), (-1, -1), 10)]))
    device_table.setStyle(TableStyle([('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                                      ('FONTSIZE', (0, 0), (-1, -1), 10)]))
    elements.append(Table([[customer_table, device_table]]))
    elements.append(Spacer(1, 20))

    # Service Info Table
    service_data = [
        ['Service Issue', record[6]],
        ['Received Date', record[7]],
        ['Delivery Date', record[8] or 'N/A'],
        ['Status', record[9]],
        ['Total Amount', f"Rs {record[10]:.2f}"],
        ['Amount Paid', f"Rs {record[11]:.2f}"],
        ['Amount Due', f"Rs {(record[10] - record[11]):.2f}"]
    ]
    service_table = Table([['Field', 'Details']] + service_data, colWidths=[120, 280])
    service_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black)
    ]))
    elements.append(service_table)
    elements.append(Spacer(1, 20))

    # Footer
    footer_style = ParagraphStyle(name='FooterStyle', fontSize=8, alignment=1, textColor=colors.grey)
    elements.append(Paragraph("Thank you for choosing Camera Store Service Pro!", footer_style))
    elements.append(Paragraph("Address: 123 Market Street, Cityville, Country", footer_style))
    elements.append(Paragraph("Phone: +123-456-7890 | Email: support@camerastore.com", footer_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", footer_style))

    doc.build(elements)
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=invoice_{record_id}.pdf'
    buffer.close()
    logger.debug(f"Invoice generated for record: id={record_id}")
    return response
@app.route('/api/dashboard', methods=['GET'])
def dashboard():
    if not session.get('logged_in'):
        logger.warning("Unauthorized attempt to access dashboard")
        return jsonify({'message': 'Unauthorized'}), 401

    role = session.get('role', 'admin')
    admin_id = session.get('admin_id')
    admin = request.args.get('admin', '')

    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()

    # Build base query with role-based filtering
    total_query = 'SELECT COUNT(*) FROM service_records sr'
    status_query = '''
        SELECT sr.status, COUNT(*) 
        FROM service_records sr
    '''
    recent_query = '''
        SELECT c.customer_name, sr.camera_model, sr.serial_number, sr.service_issue, sr.status
        FROM service_records sr
        JOIN customers c ON sr.customer_id = c.customer_id
    '''
    params = []

    # Restrict regular admins to their own records
    if role == 'admin':
        total_query += ' WHERE sr.admin_id = ?'
        status_query += ' WHERE sr.admin_id = ?'
        recent_query += ' WHERE sr.admin_id = ?'
        params.append(admin_id)
    elif role == 'super_admin' and admin:
        total_query += ' JOIN admins a ON sr.admin_id = a.admin_id WHERE a.username = ?'
        status_query += ' JOIN admins a ON sr.admin_id = a.admin_id WHERE a.username = ?'
        recent_query += ' JOIN admins a ON sr.admin_id = a.admin_id WHERE a.username = ?'
        params.append(admin)

    # Total records
    c.execute(total_query, params)
    total_records = c.fetchone()[0]

    # Status counts
    status_query += ' GROUP BY sr.status'
    c.execute(status_query, params)
    status_counts = dict(c.fetchall())

    # Recent records (last 5)
    recent_query += ' ORDER BY sr.received_date DESC LIMIT 5'
    c.execute(recent_query, params)
    recent_records = [
        {
            'customer_name': row[0],
            'camera_model': row[1],
            'serial_number': row[2],
            'service_issue': row[3],
            'status': row[4]
        } for row in c.fetchall()
    ]

    conn.close()

    return jsonify({
        'total_records': total_records,
        'status_counts': status_counts,
        'recent_records': recent_records
    })

@app.route('/api/upload_csv', methods=['POST'])
def upload_csv():
    if not session.get('logged_in'):
        logger.warning("Unauthorized attempt to upload CSV")
        return jsonify({'message': 'Unauthorized'}), 401

    if 'file' not in request.files:
        logger.error("No file part in CSV upload request")
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']
    if not file.filename.endswith('.csv'):
        logger.error("Uploaded file is not a CSV")
        return jsonify({'message': 'File must be a CSV'}), 400

    try:
        text = file.read().decode('utf-8')
        csv_file = StringIO(text)
        reader = csv.DictReader(csv_file)
        required_headers = [
            'Customer Name', 'Email', 'Phone Number',
            'Camera Brand', 'Camera Model', 'Serial Number',
            'Service Issue', 'Received Date', 'Status'
        ]

        if not all(header in reader.fieldnames for header in required_headers):
            missing = [header for header in required_headers if header not in reader.fieldnames]
            logger.error(f"Missing CSV headers: {missing}")
            return jsonify({'message': f'Missing required headers: {", ".join(missing)}'}), 400

        conn = sqlite3.connect('camera_service.db')
        c = conn.cursor()
        inserted = 0

        for row in reader:
            # Validate required fields
            if not all(row.get(header) for header in required_headers):
                logger.warning(f"Skipping row due to missing required fields: {row}")
                continue

            # Validate data formats
            try:
                customer_name = row['Customer Name']
                customer_email = row['Email']
                phone_number = row['Phone Number']
                camera_brand = row['Camera Brand']
                camera_model = row['Camera Model']
                serial_number = row['Serial Number']
                service_issue = row['Service Issue']
                received_date = row['Received Date']
                status = row['Status']
                delivery_date = row.get('Delivery Date', '')
                total_amount = float(row.get('Total Amount', 0))
                amount_paid = float(row.get('Amount Paid', 0))

                if not (2 <= len(customer_name) <= 50):
                    logger.warning(f"Invalid customer_name length in CSV: {customer_name}")
                    continue
                if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', customer_email):
                    logger.warning(f"Invalid email format in CSV: {customer_email}")
                    continue
                if not (10 <= len(phone_number) <= 15 and phone_number.isdigit()):
                    logger.warning(f"Invalid phone_number in CSV: {phone_number}")
                    continue
                if not (2 <= len(camera_brand) <= 50):
                    logger.warning(f"Invalid camera_brand length in CSV: {camera_brand}")
                    continue
                if not (2 <= len(camera_model) <= 50):
                    logger.warning(f"Invalid camera_model length in CSV: {camera_model}")
                    continue
                if not (5 <= len(serial_number) <= 20):
                    logger.warning(f"Invalid serial_number length in CSV: {serial_number}")
                    continue
                if not (10 <= len(service_issue) <= 200):
                    logger.warning(f"Invalid service_issue length in CSV: {service_issue}")
                    continue
                datetime.strptime(received_date, '%Y-%m-%d')
                if delivery_date:
                    datetime.strptime(delivery_date, '%Y-%m-%d')
                if status not in VALID_STATUSES:
                    logger.warning(f"Invalid status in CSV: {status}")
                    continue
                if total_amount < 0 or amount_paid < 0:
                    logger.warning(f"Negative amounts in CSV: total_amount={total_amount}, amount_paid={amount_paid}")
                    continue
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid data format in CSV row: {row}, error: {str(e)}")
                continue

            try:
                # Check if customer exists
                c.execute('SELECT customer_id FROM customers WHERE phone_number = ?', (phone_number,))
                customer = c.fetchone()

                if customer:
                    customer_id = customer[0]
                    c.execute('''
                        UPDATE customers SET customer_name = ?, customer_email = ?
                        WHERE customer_id = ?
                    ''', (customer_name, customer_email, customer_id))
                else:
                    c.execute('''
                        INSERT INTO customers (customer_name, customer_email, phone_number)
                        VALUES (?, ?, ?)
                    ''', (customer_name, customer_email, phone_number))
                    customer_id = c.lastrowid

                # Insert service record with admin_id
                c.execute('''
                    INSERT INTO service_records (
                        customer_id, camera_brand, camera_model, serial_number,
                        service_issue, received_date, delivery_date, status,
                        total_amount, amount_paid, admin_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    customer_id, camera_brand, camera_model, serial_number,
                    service_issue, received_date, delivery_date or None, status,
                    total_amount, amount_paid, session.get('admin_id', 1)
                ))
                inserted += 1
            except sqlite3.IntegrityError as e:
                logger.warning(f"Integrity error in CSV row: {row}, error: {str(e)}")
                continue
            except sqlite3.Error as e:
                logger.warning(f"Database error in CSV row: {row}, error: {str(e)}")
                continue

        conn.commit()
        conn.close()
        logger.debug(f"CSV upload completed: {inserted} records inserted")
        return jsonify({'message': f'{inserted} records imported successfully'}), 200
    except Exception as e:
        logger.error(f"Error processing CSV: {str(e)}")
        return jsonify({'message': 'Error processing CSV file'}), 500

@app.route('/api/admins', methods=['GET'])
def get_admins():
    if not session.get('logged_in') or session.get('role') != 'super_admin':
        logger.warning("Unauthorized attempt to access admins")
        return jsonify({'message': 'Unauthorized'}), 401

    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()
    c.execute('SELECT admin_id, username, role, created_at FROM admins')
    admins = c.fetchall()
    conn.close()

    return jsonify([
        {
            'admin_id': admin[0],
            'username': admin[1],
            'role': admin[2],
            'created_at': admin[3]
        } for admin in admins
    ])

@app.route('/api/admins', methods=['POST'])
def create_admin():
    if not session.get('logged_in') or session.get('role') != 'super_admin':
        logger.warning("Unauthorized attempt to create admin")
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        logger.error("Missing username or password in create admin request")
        return jsonify({'message': 'Username and password are required'}), 400

    if not (3 <= len(username) <= 20):
        logger.error(f"Invalid username length: {len(username)}")
        return jsonify({'message': 'Username must be 3-20 characters'}), 400

    if len(password) < 8:
        logger.error("Password too short")
        return jsonify({'message': 'Password must be at least 8 characters'}), 400

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()

    try:
        c.execute('''
            INSERT INTO admins (username, password, role, created_at)
            VALUES (?, ?, ?, ?)
        ''', (
            username,
            password_hash,
            'admin',
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))
        conn.commit()
        logger.debug(f"Admin created successfully: username={username}")
        conn.close()
        return jsonify({'message': 'Admin created successfully'}), 201
    except sqlite3.IntegrityError:
        logger.error(f"Username already exists: {username}")
        conn.close()
        return jsonify({'message': 'Username already exists'}), 400
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)}")
        conn.close()
        return jsonify({'message': 'Database error'}), 500

@app.route('/api/admins/<int:admin_id>', methods=['PUT'])
def update_admin(admin_id):
    if not session.get('logged_in') or session.get('role') != 'super_admin':
        logger.warning("Unauthorized attempt to update admin")
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        logger.error("Missing username or password in update admin request")
        return jsonify({'message': 'Username and password are required'}), 400

    if not (3 <= len(username) <= 20):
        logger.error(f"Invalid username length: {len(username)}")
        return jsonify({'message': 'Username must be 3-20 characters'}), 400

    if len(password) < 8:
        logger.error("Password too short")
        return jsonify({'message': 'Password must be at least 8 characters'}), 400

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect('camera_service.db')
    c = conn.cursor()

    try:
        c.execute('''
            UPDATE admins SET username = ?, password = ?
            WHERE admin_id = ?
        ''', (username, password_hash, admin_id))
        if c.rowcount == 0:
            conn.close()
            logger.error(f"Admin not found: id={admin_id}")
            return jsonify({'message': 'Admin not found'}), 404
        conn.commit()
        logger.debug(f"Admin updated successfully: id={admin_id}")
        conn.close()
        return jsonify({'message': 'Admin updated successfully'}), 200
    except sqlite3.IntegrityError:
        logger.error(f"Username already exists: {username}")
        conn.close()
        return jsonify({'message': 'Username already exists'}), 400
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)}")
        conn.close()
        return jsonify({'message': 'Database error'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)