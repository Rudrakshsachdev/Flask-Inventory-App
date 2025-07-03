# 📦 Flask Inventory Management System

A powerful and modern **Inventory Management System** built using **Flask**, offering complete user/admin authentication, OTP verification, image uploads, and role-based access.

---

## 🚀 Features

- 👥 **User & Admin Authentication**
- ✉️ **OTP Verification for Admin Registration**
- 🔐 **Password Reset via Email**
- 🛒 **Product & Order Management**
- 📷 **Profile and Product Image Upload**
- 🧑‍💼 **Role-based Access Control**
- 📊 **Admin Dashboard to Manage Everything**
- 🎨 **Responsive UI with Bootstrap 5**

---

## 🧱 Tech Stack

| Technology | Usage |
|------------|-------|
| Flask | Backend Framework |
| SQLite | Database |
| SQLAlchemy | ORM |
| Flask-Login | User Authentication |
| Flask-Mail | Email OTP & Password Reset |
| Jinja2 | Templating |
| Bootstrap | UI Styling |

---

## 📁 Folder Structure

inventory/ <br>
├── static/<br>
│ ├── uploads/ # Product images<br>
│ └── profiles/ # User profile images<br>
├── templates/<br>
│ ├── auth/ # Login/Register/Forgot/Reset <br>
│ ├── admin/ # Admin templates <br>
│ ├── dashboard.html # Dashboard view <br>
│ └── ...
├── init.py # App factory <br>
├── models.py # SQLAlchemy models <br>
├── routes.py # User routes <br>
├── auth_routes.py # Authentication routes <br>
├── extensions.py # DB, Login, Mail config <br>
└── run.py # App runner <br>


