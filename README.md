# Email-Verification
# Email OTP App

This project is a simple Flask-based email OTP (One Time Password) generation and verification application. It is Dockerized for easy deployment.

## 🚀 Getting Started

Follow these steps to get the project up and running locally using Docker.

### 1. Clone the Repository

First, clone the repository to your local machine:

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

# Build the Docker Image
 -docker build -t flask-email-otp-app

# Run the Application
 -docker run -p 5000:5000 flask-email-otp-app

# Access the API Documentation
 -http://localhost:5000/apidocs
