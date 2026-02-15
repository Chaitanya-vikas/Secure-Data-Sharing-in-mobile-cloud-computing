# 🔒 SecureVault: End-to-End Encrypted Data Sharing Platform

[![Deployed on Render](https://img.shields.io/badge/Deployed-Render-46E3B7?style=flat&logo=render&logoColor=white)](https://secure-vault-live.onrender.com)
[![Database](https://img.shields.io/badge/Database-TiDB_MySQL-4479A1?style=flat&logo=mysql&logoColor=white)](https://tidbcloud.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Framework-Django_5.1-092E20?style=flat&logo=django&logoColor=white)](https://www.djangoproject.com/)

> **A secure, cloud-native web application for storing and sharing sensitive data with military-grade encryption and Multi-Factor Authentication.**

---

## 🚀 Live Demo
**View the Live Application:** [https://secure-vault-live.onrender.com](https://secure-vault-live.onrender.com)  
*(Note: As this is a free tier deployment, the initial load may take 50 seconds while the server wakes up.)*

---

## 📖 Project Overview

**SecureVault** is a robust file-sharing solution designed to address data privacy concerns in cloud storage. Unlike traditional storage where files are stored as plain text, SecureVault implements **Application-Level Encryption**. Every file is encrypted using the **Fernet (AES)** symmetric encryption algorithm before it ever touches the database.

This project demonstrates a modern **Multi-Cloud Architecture**, utilizing **Render** for application compute and **TiDB (Serverless MySQL)** for distributed data persistence.

### Key Features
* **🔐 Military-Grade Encryption:** Files are encrypted using the `cryptography` library (Fernet/AES) prior to storage. Even if the database is compromised, the files remain unreadable.
* **🛡️ Two-Factor Authentication (2FA):** Integrated TOTP-based 2FA using `django-otp` and `qrcode` (compatible with Google Authenticator).
* **☁️ Serverless Database:** Powered by **TiDB Cloud**, a distributed SQL database that offers high availability and MySQL compatibility.
* **🤝 Secure Sharing:** A granular permission system allowing users to share encrypted files with specific other users without exposing the raw data.
* **📱 Responsive UI:** Built with Bootstrap to ensure seamless access across mobile and desktop devices.

---

## 🛠️ Tech Stack

| Component | Technology |
| :--- | :--- |
| **Backend Framework** | Django 5.1 (Python) |
| **Database** | TiDB Cloud (MySQL 8.0 Compatible) |
| **Security** | `cryptography` (Encryption), `django-otp` (2FA) |
| **Deployment** | Render PaaS (Compute), Whitenoise (Static Files) |
| **Frontend** | HTML5, CSS3, Bootstrap |
| **Version Control** | Git & GitHub |

---

## 🏗️ System Architecture

The application follows a standard **MVT (Model-View-Template)** architecture, enhanced with a distributed cloud database.

1.  **Client:** User interacts via Browser (HTTPS).
2.  **Security Layer:** Django Security Middleware + 2FA Verification.
3.  **Application Logic:** * **Encryption Engine:** Encrypts file bytes in memory.
    * **Decryption Engine:** Decrypts only upon verified request by the owner or shared user.
4.  **Data Layer:** TiDB Serverless Cluster (Stores User Data & Encrypted File Blobs).

---

## 📸 Screenshots

| **Login & 2FA** | **Secure Dashboard** |
| :---: | :---: |
| ![Login Screen](path/to/login_screenshot.png) | ![Dashboard](path/to/dashboard_screenshot.png) |

| **Encrypted File Upload** | **Mobile View** |
| :---: | :---: |
| ![Upload](path/to/upload_screenshot.png) | ![Mobile](path/to/mobile_screenshot.png) |

*(Note to Recruiter: Replace the paths above with actual image links from your repository)*

---

## 💻 Local Installation

To run this project locally for development:

**1. Clone the Repository**
```bash
git clone [https://github.com/YOUR_USERNAME/Secure-Data-Sharing-in-mobile-cloud-computing.git](https://github.com/YOUR_USERNAME/Secure-Data-Sharing-in-mobile-cloud-computing.git)
cd Secure-Data-Sharing-in-mobile-cloud-computing
