\# Gmail OTP Login System



A simple email OTP (One-Time Password) login system built with Python, Flask, and Gmail SMTP.



Users enter their email address, receive a 6-digit OTP by email, and use that OTP to log in.



\---



\## Features



\- Email-based OTP login

\- 6-digit OTP

\- Gmail SMTP for sending emails

\- OTP expires after 3 minutes

\- Maximum 5 incorrect OTP attempts

\- 60-second wait between OTP requests

\- Flask session-based login

\- Logout functionality

\- No paid email service or custom domain required

\- Gmail App Password authentication

\- Secrets are kept outside the source code



\---



\## Project Structure



```text

gmail-otp/

│

├── templates/

│   └── index.html

│

├── app.py

├── requirements.txt

├── .env.example

├── .gitignore

└── README.md

```



> The `venv/` folder is created locally but should NOT be uploaded to GitHub.



\---



\# Requirements



Before starting, install:



\- Python 3.10 or newer

\- Git

\- A Gmail account



You also need Google 2-Step Verification enabled because Gmail App Passwords require it.



\---



\# 1. Clone the Repository



Open Command Prompt or Terminal:



```bash

git clone https://github.com/YOUR\_USERNAME/gmail-otp.git

```



Enter the project folder:



```bash

cd gmail-otp

```



\---



\# 2. Create a Virtual Environment



Windows:



```cmd

python -m venv venv

```



Activate it:



```cmd

venv\\Scripts\\activate

```



You should see something similar to:



```text

(venv)

```



\---



\# 3. Install Dependencies



Run:



```cmd

python -m pip install -r requirements.txt

```



The project currently requires:



```text

Flask

```



Python's built-in libraries are used for Gmail SMTP, so no separate SMTP package is required.



\---



\# 4. Create a Gmail App Password



Do NOT use your normal Gmail password.



You need a Gmail App Password.



\## Step 1: Enable 2-Step Verification



Go to your Google Account security settings:



https://myaccount.google.com/security



Enable:



\*\*2-Step Verification\*\*



\---



\## Step 2: Create an App Password



Go to:



https://myaccount.google.com/apppasswords



Create a new App Password.



Google will give you a 16-character App Password.



Keep this password private.



Do NOT upload it to GitHub.



\---



\# 5. Configure Gmail Credentials



This application needs three environment variables:



```text

GMAIL\_ADDRESS

GMAIL\_APP\_PASSWORD

SECRET\_KEY

```



The repository contains `.env.example` as a template.



Example:



```text

GMAIL\_ADDRESS=your-gmail@gmail.com

GMAIL\_APP\_PASSWORD=your-16-character-app-password

SECRET\_KEY=your-secret-key

```



\---



\# 6. Set Environment Variables



\## Windows Command Prompt



Run:



```cmd

set GMAIL\_ADDRESS=your-gmail@gmail.com

set GMAIL\_APP\_PASSWORD=your-16-character-app-password

set SECRET\_KEY=your-secret-key

```



Example:



```cmd

set GMAIL\_ADDRESS=myaccount@gmail.com

set GMAIL\_APP\_PASSWORD=abcdefghijklmnop

set SECRET\_KEY=my-random-secret-key

```



Replace the example values with your own values.



\### Important



Do NOT commit these values to GitHub.



These variables only exist in the current Command Prompt session.



If you close the Command Prompt, set them again.



\---



\# 7. Run the Application



Start Flask:



```cmd

python app.py

```



You should see:



```text

\* Running on http://127.0.0.1:5000

```



Open your browser and visit:



```text

http://127.0.0.1:5000

```



\---



\# 8. Test OTP Login



1\. Enter an email address.

2\. Click \*\*Send OTP\*\*.

3\. Check the email inbox.

4\. Enter the 6-digit OTP.

5\. Click \*\*Verify OTP\*\*.

6\. You should see that login was successful.



\---



\# OTP Rules



The application currently uses these rules:



| Rule | Value |

|---|---:|

| OTP length | 6 digits |

| OTP lifetime | 3 minutes |

| Maximum incorrect attempts | 5 |

| Resend wait time | 60 seconds |



\---



\# Gmail SMTP



The application uses Gmail's SMTP server:



```text

smtp.gmail.com

```



Port:



```text

465

```



SSL encryption is used for the SMTP connection.



The application authenticates using the Gmail App Password.



\---



\# Security



Never commit passwords or secrets to GitHub.



The following should NEVER contain real credentials:



```text

app.py

README.md

.env.example

```



Do not upload:



```text

.env

```



Do not upload:



```text

venv/

```



The `.gitignore` file is included to help prevent accidental uploads.



\---



\# Important Security Notes



This project is intended as a simple learning/demo project.



For production use, additional security measures should be considered, including:



\- Persistent database storage

\- Hashed OTP storage

\- Strong production secret keys

\- Rate limiting

\- CSRF protection where appropriate

\- HTTPS

\- Secure session cookies

\- Account lockout / abuse prevention

\- Email verification controls

\- Logging and monitoring

\- Protection against automated OTP requests

\- Production-grade secret management



The current OTP storage is in memory. Restarting the Flask application clears active OTPs.



\---



\# Troubleshooting



\## "Could not send email"



Check that:



1\. Your Gmail address is correct.

2\. Your Gmail App Password is correct.

3\. 2-Step Verification is enabled.

4\. The environment variables are set in the current terminal.

5\. You are using the App Password, not your normal Gmail password.



\---



\## "Gmail configuration is missing"



Check:



```cmd

echo %GMAIL\_ADDRESS%

```



and:



```cmd

echo %GMAIL\_APP\_PASSWORD%

```



The first should show your Gmail address.



The second should show that a value exists.



Do not share the App Password publicly.



\---



\## Port already in use



If port 5000 is already being used, stop the other Flask application or change the port in `app.py`.



\---



\# Stopping the Application



In the Command Prompt running Flask, press:



```text

Ctrl + C

```



\---



\# License



This project is provided for educational and development purposes.

