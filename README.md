# 📸 CameraPort – Camera Service Management System

A modern, secure, and responsive web application for managing camera repair and service operations. Built with a **Flask** backend and a **HTML/CSS/JavaScript** frontend, it offers role-based access for admins and super admins, service record management, CSV uploads, and PDF invoice generation.

![Preview](/preview-images/preview.png)
<!-- Replace with your actual screenshot -->

---

## ✨ Features

- 🔒 **Secure Authentication**: Login/logout with session management and SHA-256 password hashing.
- 📊 **Interactive Dashboard**: Displays total records, status distribution (via Chart.js pie chart), and recent activity.
- 📋 **Service Record Management**:
  - Add, edit, view, and delete service records with client-side and server-side validation.
  - Bulk record deletion and CSV upload for efficient data entry.
  - Generate PDF invoices for individual records using ReportLab.
- 👑 **Role-Based Access**:
  - **Admins**: Manage their own records (add, edit limited fields, delete).
  - **Super Admins**: Full access, including admin account management and extended record editing.
- 📱 **Responsive Design**: Optimized for desktop and mobile devices with smooth animations.
- 📂 **CSV Import/Export**: Bulk upload records and export filtered data to CSV.
- 🔔 **Logging**: Comprehensive error and debug logging for backend operations.
- ⚡ **Fast Performance**: Lightweight SQLite database and minimal frontend dependencies.

---

## 🧰 Technologies Used

### Frontend
- **HTML5**: Application structure.
- **CSS3**: Styling with fade-in, slide-in, and hover animations.
- **JavaScript (Vanilla)**: Client-side logic, form handling, and API interactions.
- **Chart.js**: Status distribution pie chart.
- **Font Awesome**: Icons for UI elements.
- **Google Fonts**: Poppins font for typography.
- **Fetch API**: Backend communication.

### Backend
- **Python 3.x**: Core language.
- **Flask**: RESTful API framework.
- **Flask-Session**: Filesystem-based session management.
- **SQLite**: Lightweight database for data storage.
- **ReportLab**: PDF invoice generation.
- **CSV**: Handling CSV uploads/exports.
- **hashlib**: SHA-256 password hashing.
- **logging**: Debug and error tracking.

---

## 🚀 Installation & Usage

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/aswapathyraj/cameraport-camera-service-management-system.git
   cd cameraport-camera-service-management-system
   ```

2. **Install Dependencies**:
   ```bash
   pip install flask flask-session reportlab
   ```

3. **Set Up the Environment**:
   - Update the `SECRET_KEY` in `app.py`:
     ```python
     app.config['SECRET_KEY'] = 'your-secret-key-here'
     ```
   - Ensure write permissions for the session directory.

4. **Initialize the Database**:
   - Run the backend to create `camera_service.db` with default admin accounts:
     - **Super Admin**: `superadmin` / `SuperAdmin2025`
     - **Admin**: `admin` / `CameraPro2025`
     ```bash
     python app.py
     ```

5. **Run the Application**:
   - Start the Flask server (runs on `http://localhost:5000`):
     ```bash
     python app.py
     ```
   - Open `http://localhost:5000` in a browser to access the frontend.

6. **Optional**: Place a `logo.png` in the `static/` directory for invoice branding.

---

## 🖌️ Customization

- **Theme Colors**: Modify CSS variables in `index.html` (e.g., `#1a3c34`, `#a8d5ba`).
- **Content**: Update text and labels directly in `index.html`.
- **Logo**: Replace `static/logo.png` for custom invoice branding.
- **CSV Format**: Adjust validation rules in `app.py` for custom CSV headers.
- **Database**: Switch to PostgreSQL by modifying the database connection in `app.py`.

---

## 📬 Contact

**Aswapathy Raj**  
📧 [aswapathyraj@gmail.com](mailto:aswapathyraj@gmail.com)  
📍 Mavelikara, Alappuzha, Kerala  
🌐 [LinkedIn](https://www.linkedin.com/in/aswapathy-raj-b9417a2b5)  
📸 [Instagram](https://www.instagram.com/aswapathy_raj/)  
💻 [GitHub](https://github.com/aswapathyraj)

---

## 🧾 License

This project is licensed under the **MIT License**.  
Feel free to use, modify, and share with credit.

```text
MIT License

Copyright (c) 2025 Aswapathy Raj

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

## 🙌 Credits

- Developed by **Aswapathy Raj**.
- Frontend inspired by modern UI trends.
- Fonts via [Google Fonts – Poppins](https://fonts.google.com/specimen/Poppins).
- Icons from [Font Awesome](https://fontawesome.com).
- Charting via [Chart.js](https://www.chartjs.org).
- PDF generation via [ReportLab](https://www.reportlab.com).

---

## 🤝 Contributing

Contributions, suggestions, or improvements are welcome!  
Please open an issue or pull request on [GitHub](https://github.com/aswapathyraj/cameraport-camera-service-management-system).
