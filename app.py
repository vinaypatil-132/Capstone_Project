from flask import Flask, request, jsonify, render_template
import os
import yara
import re

app = Flask(__name__)

# Function to extract strings from the file
def extract_strings(file_path):
    strings = set()
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            # Extract ASCII strings
            ascii_strings = re.findall(b'[ -~]{4,}', content)  # Finds printable ASCII strings of length >= 4
            for s in ascii_strings:
                strings.add(s.decode('utf-8', errors='ignore'))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return strings

# Function to sanitize strings for YARA rules
def sanitize_string(s):
    # Escape quotes and backslashes
    return s.replace('\\', '\\\\').replace('"', '\\"')

# Function to generate a YARA rule based on extracted strings
def create_yara_rule(file_paths):
    rule_strings = []
    string_count = 0

    for file_path in file_paths:
        extracted_strings = extract_strings(file_path)
        for s in extracted_strings:
            sanitized = sanitize_string(s)
            # Avoid duplicate strings
            rule_strings.append(f'$string_{string_count} = "{sanitized}"')
            string_count += 1

    if not rule_strings:
        return "rule no_matches { strings: $string_0 = \"dummy\" condition: false }"  # A fallback rule

    rule_content = "\n        ".join(rule_strings)

    rule = f"""
rule generated_rule {{
    strings:
        {rule_content}
    condition:
        any of them
}}
"""
    return rule

# Function to scan files using the generated YARA rule
def scan_files_with_rule(file_paths, rule):
    try:
        yara_rule = yara.compile(source=rule)
    except Exception as e:
        print(f"Error compiling YARA rule: {e}")
        return {file: [f"YARA rule compilation failed: {str(e)}"] for file in file_paths}

    results = {}
    for file_path in file_paths:
        try:
            matches = yara_rule.match(file_path)
            results[file_path] = [str(match.rule) for match in matches] if matches else ["No matches found"]
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
            results[file_path] = [f"Error: {str(e)}"]

    return results

# Route to render the index page
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle file upload and scanning
@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        files = request.files.getlist('files')
        if not files:
            return jsonify({"error": "No files uploaded"}), 400

        if not os.path.exists('uploads'):
            os.makedirs('uploads')

        file_paths = []
        for file in files:
            path = os.path.join('uploads', file.filename)
            file.save(path)
            file_paths.append(path)

        print(f"Uploaded files: {file_paths}")  # Log uploaded file paths

        rule = create_yara_rule(file_paths)
        print(f"Generated YARA rule:\n{rule}")  # Log the generated rule

        scan_results = scan_files_with_rule(file_paths, rule)

        return jsonify({"rule": rule, "results": scan_results})

    except Exception as e:
        print(f"Error during file upload: {e}")  # Log the error
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
