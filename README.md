# flask_api_midterm
Flask JWT Authentication, CRUD operations, and file handling Mid term project by Gabriel Bulosan

DEMO RECORDING:
https://youtu.be/TXfcLeI3RuQ

HOW TO RUN:
-----------
1. Clone this repository to your local machine.
2. Set Up MySQL Database:
  - Start your MySQL server locally.
  - A script for creating the database and tables may be provided in the repository. If not,     
    create the necessary database and tables manually:
        - Table 1 - user: Columns - id, username, password
        - Table 2 - uploads: Columns - file_id, file_name, file_type, uploaded_by
3. Run the Application:
  - Make sure the 'uploads' file is created and is in the same workspace as app.py
  - Start up a virtual environment
  - run app.py
  - Use Postman to test the following endpoints:
  - /register: Register a new user
  - /login: Log in and obtain JWT
  - /upload: Upload a file (JWT required)
  - /update_file/<file_name>: Replace a previously uploaded file with a new one (JWT required)
  - /delete_file/<file_name>: Delete a previously uploaded file (JWT required)
  - /public: view all uploaded files
