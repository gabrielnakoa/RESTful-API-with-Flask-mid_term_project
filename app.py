from flask import Flask
from flask_mysqldb import MySQL
from flask import jsonify, request, render_template, redirect, url_for, abort
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, exceptions as jwt_exceptions
import os, shutil
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Thisismy1!'
app.config['MYSQL_DB'] = 'flask_project_db'
app.config['MYSQL_HOST'] = 'localhost'

app.config['SECRET_KEY'] = 'ABC'

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 #2MB

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

jwt = JWTManager(app)
mysql = MySQL(app)

@app.route('/register', methods=['POST'])
def register():
    credentials = request.get_json()
    username = credentials.get('username')
    password = credentials.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    try:
        cursor = mysql.connection.cursor()
        
        cursor.execute("SELECT * FROM flask_project_db.user WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            cursor.close()
            return jsonify({'message': 'Username already taken. Try again.'}), 400
        
        cursor.execute("INSERT INTO flask_project_db.user (username, password) VALUES (%s, %s)", (username, password))
        mysql.connection.commit()
        
        cursor.close()
        return jsonify({'message': 'Register Successful'}), 201

    except Exception as e:
        cursor.close()
        print(f"Error: {e}")
        return jsonify({'message': 'Registration not successful. Try again.'}), 500

@app.route('/delete_user', methods=['DELETE'])
def delete_user():
    data = request.get_json()
    user_id = data.get('id')

    if not user_id:
        return jsonify({'error': 'Provide a User ID'}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT * FROM flask_project_db.user WHERE id = %s;", (user_id,))
        user = cursor.fetchone()

        if user is None:
            return jsonify({'message': 'User not found'}), 404

        cursor.execute("DELETE FROM flask_project_db.user WHERE id = %s", (user_id,))
        mysql.connection.commit()

        return jsonify({'message': f'User {user_id} successfully deleted'}), 200
    except Exception:
        return jsonify({'error': 'Some error occurred while attempting to delete the user'}), 500
    finally:
        cursor.close()
    
@app.route('/update_user', methods=['PUT'])
def update_username():
    data = request.get_json()
    old_user = data.get('old_username')
    new_user = data.get('new_username')

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT * FROM flask_project_db.user WHERE username = %s;", (old_user,))
        user = cursor.fetchone()

        if user is None:
            return jsonify({'message': 'User not found'}), 404
        
        cursor.execute("UPDATE flask_project_db.user SET username = %s WHERE username = %s;", (new_user, old_user))
        mysql.connection.commit()
        return jsonify({'message': f'Username updated from {old_user} to {new_user}'}), 200

    except Exception:
        return jsonify({'error': 'Some error occurred while attempting to upadte the username'}), 500
    finally:
        cursor.close()

@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    username = auth.get('username')
    password = auth.get('password')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, username, password FROM flask_project_db.user WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    if not user:
        return jsonify({'message': 'try again'}),401
    if user[2] != password:
        return jsonify({'message': 'Invalid credentials'}), 401

    user_id = user[0]
    #print("User data:")
    #for index, value in enumerate(user):
    #    print(f"{index}: {value}")    
    token = create_access_token(identity=user_id)
    return jsonify({'message': 'Login successful. Here is your token:', 'token': token})


@app.route('/upload', methods=['POST'])
@jwt_required() 
def upload_file():
    current_user = get_jwt_identity()

    if 'file' not in request.files:
        return jsonify({'error': 'Must name the Key \'file\' '}), 400

    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    upload_file_to_database(current_user, file)
    return jsonify({'message': 'Uploaded successful', 'filename': filename}), 200

def upload_file_to_database(current_user, file):
    file_name = secure_filename(file.filename)
    file_type = file_name.rsplit('.', 1)[1].lower() if '.' in file_name else 'unknown'

    cursor = mysql.connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO flask_project_db.uploads (file_name, file_type, uploaded_by) VALUES (%s, %s, %s)",
            (file_name, file_type, current_user)
        )
        mysql.connection.commit()
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        cursor.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/delete_file/<filename>', methods=['DELETE'])
@jwt_required()
def delete_file(filename):
    current_user = get_jwt_identity()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    filename = secure_filename(filename)
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM flask_project_db.uploads WHERE file_name = %s AND uploaded_by = %s", (filename, current_user))
    metadata = cursor.fetchone()
    cursor.close()

    if not metadata:
        return jsonify({"message": "You haven't uploaded that file"}), 404

    try:
        os.remove(file_path)
    except Exception as e:
        print(f"Error occurred while deleting file: {e}")
        return jsonify({'error': 'Could not delete the file'}), 500
    
    delete_file_metadata(filename, current_user)
    
    return jsonify({'message': f'File {filename} successfully deleted'}), 200

def delete_file_metadata(filename, user):
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("DELETE FROM flask_project_db.uploads WHERE file_name = %s AND uploaded_by = %s", (filename, user))
        mysql.connection.commit()
        print(filename)
        print(user)
    except Exception as e:
        print(f"Error occurred while deleting file metadata: {e}")
    finally:
        cursor.close()

@app.route('/update_file/<old_file>', methods=['PUT'])
@jwt_required()
def update_file(old_file):
    current_user = get_jwt_identity()
    cursor = mysql.connection.cursor()

    cursor.execute("SELECT * FROM flask_project_db.uploads WHERE file_name = %s AND uploaded_by = %s", (old_file, current_user))
    metadata = cursor.fetchone()
    cursor.close()

    if not metadata:
        return jsonify({"message": "You haven't uploaded that file"}), 404

    if 'file' not in request.files:
        return jsonify({'error': 'Must name the Key \'file\' '}), 400

    new_file = request.files['file']
    new_file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_file.filename)
    new_file.save(new_file_path)

    if new_file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(new_file.filename):
        return jsonify({'error': f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'}), 400


    file_path = os.path.join(app.config['UPLOAD_FOLDER'], old_file)
    if os.path.isfile(file_path):
        os.remove(file_path)
        update_file_metadata(metadata[0], new_file)
        return jsonify({"message": "File updated successfully"}), 200
    else:
        return jsonify({"message": "Old file not found"}), 404

def update_file_metadata(file_id, new_file):
    cursor = mysql.connection.cursor()
    file_name = secure_filename(new_file.filename)
    file_type = file_name.rsplit('.', 1)[1].lower() if '.' in file_name else 'unknown'
    try:
        cursor.execute("UPDATE flask_project_db.uploads SET file_name = %s, file_type = %s WHERE file_id = %s", (file_name, file_type, file_id))
        mysql.connection.commit()
    except Exception as e:
        print(f"Error occurred while updating file metadata: {e}")
    finally:
        cursor.close()



@app.route('/public', methods=['GET'])
def view_public_info():
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT file_name, file_type, uploaded_by FROM uploads")
        files_info = cursor.fetchall()

        if not files_info:
            return jsonify({'message': 'There hasnt been any uploads yet.'}), 200
        
        response = {
            'total_files': len(files_info),
            'files': [{'name': file[0], 'type': file[1], 'uploaded_by': file[2]} for file in files_info]
        }
        
        return jsonify(response), 200

    except Exception as e:
        return jsonify({'error': 'An error occurred while retrieving files.', 'details': str(e)}), 500
    finally:
        cursor.close()



@app.errorhandler(413)
def request_file_too_large(error):
    return jsonify({'error': 'File too large. Maximum size is 2MB.'}), 413

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request', 'message': str(error)}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized', 'message': 'Authentication required'}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'message': 'The requested resource could not be found'}), 404

@app.errorhandler(jwt_exceptions.NoAuthorizationError)
def handle_missing_token_error(e):
    return jsonify({"error": "Authorization required. Log in to get a token."}), 401



if __name__ == '__main__':
    app.run(debug=True)


