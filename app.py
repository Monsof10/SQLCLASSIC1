from flask import Flask, render_template, request, redirect, url_for, session
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with something secure

SCENARIOS = [
    {
        "id": 1,
        "description": (
            "This scenario demonstrates a **login authentication bypass** vulnerability. "
            "Because the SQL query is constructed by directly concatenating the username "
            "and password, an attacker can supply malicious input (e.g., ' OR '1'='1) to "
            "bypass the authentication check entirely. If successful, the attacker can log "
            "in without valid credentials, potentially gaining unauthorized access."
        ),
        "vulnerable_code": (
            "query = \"SELECT * FROM users WHERE username = '\" + username + \"' "
            "AND password = '\" + password + \"'\""
        ),
        "correct_code": "SELECT * FROM users WHERE username = %s AND password = %s",
        "starter_code": (
            "# This code is vulnerable. Fix it with placeholders.\n"
            "# Original vulnerable code:\n"
            "query = \"SELECT * FROM users WHERE username = '\" + username + \"' AND password = '\" + password + \"'\"\n"
            "\n"
            "# Replace the above line with a secure statement.\n"
            "# e.g.: SELECT * FROM users WHERE username = ? AND password = ?\n"
            "\n"
            "# Type your final code below:\n"
        ),
        "hints": [
            "Hint 1: Use parameterized queries with placeholders (e.g., %s).\n\n"
            "Example:\n```\nSELECT * FROM users WHERE username = %s AND password = %s\n```",
            "Hint 2: Never concatenate raw user input directly into a query.\n\n"
            "Bad:\n```\nSELECT * FROM users WHERE username = '\" + username + \"'\n```\n"
            "Good:\n```\nSELECT * FROM users WHERE username = %s\n```",
            "Hint 3: Validate or sanitize all user inputs.\n\n"
            "For example:\n```\nif len(username) > 0 and len(password) > 0:\n    # proceed\n```"
        ]
    },
    {
        "id": 2,
        "description": (
            "This scenario covers an **admin panel access** vulnerability. "
            "The application checks for admin credentials by directly concatenating "
            "the username and password. An attacker can exploit this by injecting "
            "malicious strings to gain unauthorized admin privileges. Proper input "
            "handling and parameterization is crucial to prevent this."
        ),
        "vulnerable_code": (
            "query = \"SELECT * FROM admin WHERE username = '\" + admin_username + \"' "
            "AND password = '\" + admin_password + \"'\""
        ),
        "correct_code": "SELECT * FROM admin WHERE username = %s AND password = %s",
        "starter_code": (
            "# This code is vulnerable. Fix it with placeholders.\n"
            "# Original vulnerable code:\n"
            "query = \"SELECT * FROM admin WHERE username = '\" + admin_username + \"' AND password = '\" + admin_password + \"'\"\n"
            "\n"
            "# Replace the above line with a secure statement.\n"
            "# e.g.: SELECT * FROM admin WHERE username = ? AND password = ?\n"
            "\n"
            "# Type your final code below:\n"
        ),
        "hints": [
            "Hint 1: Use parameterized queries with placeholders.\n\n"
            "Example:\n```\nSELECT * FROM admin WHERE username = %s AND password = %s\n```",
            "Hint 2: Watch out for single quotes around user inputs.\n\n"
            "Bad:\n```\nSELECT * FROM admin WHERE username = '\" + admin_username + \"'\n```\n"
            "Good:\n```\nSELECT * FROM admin WHERE username = %s\n```",
            "Hint 3: Always check user roles before granting admin access.\n\n"
            "For example:\n```\n# after verifying credentials:\nif user_is_admin:\n    # allow admin actions\nelse:\n    # deny\n```"
        ]
    },
    {
        "id": 3,
        "description": (
            "This scenario focuses on **search functionality**. The query uses a LIKE clause "
            "and concatenates the user's search term. Attackers can inject wildcard symbols "
            "and SQL logic to read or filter data in unintended ways. By parameterizing the "
            "search term, you ensure user input doesn't break out of the intended query structure."
        ),
        "vulnerable_code": (
            "query = \"SELECT * FROM products WHERE name LIKE '%\" + search_term + \"%'\""
        ),
        "correct_code": "SELECT * FROM products WHERE name LIKE %s",
        "starter_code": (
            "# This code is vulnerable. Fix it with placeholders.\n"
            "# Original vulnerable code:\n"
            "query = \"SELECT * FROM products WHERE name LIKE '%\" + search_term + \"%'\"\n"
            "\n"
            "# Replace the above line with a secure statement.\n"
            "# e.g.: SELECT * FROM products WHERE name LIKE %s\n"
            "\n"
            "# Type your final code below:\n"
        ),
        "hints": [
            "Hint 1: Use placeholders for LIKE statements.\n\n"
            "Example:\n```\nSELECT * FROM products WHERE name LIKE %s\n```",
            "Hint 2: Avoid concatenating the search term with wildcards directly.\n\n"
            "Bad:\n```\nSELECT * FROM products WHERE name LIKE '%\" + search_term + \"%'\n```\n"
            "Good:\n```\nSELECT * FROM products WHERE name LIKE %s\n```",
            "Hint 3: Validate or sanitize the search term.\n\n"
            "For instance:\n```\nif len(search_term) > 0:\n    # proceed\n```"
        ]
    },
    {
        "id": 4,
        "description": (
            "This scenario deals with **user profile retrieval**. The query uses a user_id "
            "taken directly from user input. Attackers can manipulate user_id to read "
            "another user’s profile or even inject extra SQL statements. Proper parameterization "
            "and type checks (e.g., ensuring user_id is an integer) help prevent this attack."
        ),
        "vulnerable_code": (
            "query = \"SELECT * FROM profiles WHERE user_id = '\" + user_id + \"'\""
        ),
        "correct_code": "SELECT * FROM profiles WHERE user_id = %s",
        "starter_code": (
            "# This code is vulnerable. Fix it with placeholders.\n"
            "# Original vulnerable code:\n"
            "query = \"SELECT * FROM profiles WHERE user_id = '\" + user_id + \"'\"\n"
            "\n"
            "# Replace the above line with a secure statement.\n"
            "# e.g.: SELECT * FROM profiles WHERE user_id = %s\n"
            "\n"
            "# Type your final code below:\n"
        ),
        "hints": [
            "Hint 1: Use parameterized queries with placeholders.\n\n"
            "Example:\n```\nSELECT * FROM profiles WHERE user_id = %s\n```",
            "Hint 2: Handle quotes properly in the WHERE clause.\n\n"
            "Bad:\n```\nSELECT * FROM profiles WHERE user_id = '\" + user_id + \"'\n```\n"
            "Good:\n```\nSELECT * FROM profiles WHERE user_id = %s\n```",
            "Hint 3: Double-check that user_id is the correct type (int).\n\n"
            "For example:\n```\nuser_id = int(user_id)\nSELECT * FROM profiles WHERE user_id = %s\n```"
        ]
    },
    {
        "id": 5,
        "description": (
            "This scenario highlights a **dynamic ORDER BY clause** vulnerability. "
            "The application sorts products based on a user-provided column name (order_by). "
            "If you concatenate the column name directly, attackers can inject arbitrary SQL. "
            "Whitelisting valid columns or defaulting to a safe column is essential."
        ),
        "vulnerable_code": (
            "query = \"SELECT * FROM products ORDER BY \" + order_by"
        ),
        "correct_code": (
            "IF order_by IN ('name','price','date'):\n"
            "    SELECT * FROM products ORDER BY order_by\n"
            "ELSE:\n"
            "    # handle invalid column"
        ),
        "starter_code": (
            "# This code is vulnerable. Fix it with a whitelist approach.\n"
            "# Original vulnerable code:\n"
            "query = \"SELECT * FROM products ORDER BY \" + order_by\n"
            "\n"
            "# A safer approach might be:\n"
            "# IF order_by IN ('name','price','date'):\n"
            "#     SELECT * FROM products ORDER BY order_by\n"
            "# ELSE:\n"
            "#     # handle invalid column\n"
            "\n"
            "# Type your final code below:\n"
        ),
        "hints": [
            "Hint 1: Whitelist valid ORDER BY columns (e.g., name, price, date).\n\n"
            "Example:\n```\nIF order_by IN ('name','price','date'):\n    SELECT * FROM products ORDER BY order_by\nELSE:\n    # handle invalid column\n```",
            "Hint 2: Do not directly concatenate unvalidated user input.\n\n"
            "Bad:\n```\nSELECT * FROM products ORDER BY \" + order_by + \"\n```\n"
            "Good:\n```\nIF order_by IN ('name','price','date'):\n    # proceed\n```",
            "Hint 3: Fallback to a default column if user input is invalid.\n\n"
            "For example:\n```\nIF order_by NOT IN ('name','price','date'):\n    order_by = 'name'\nSELECT * FROM products ORDER BY order_by\n```"
        ]
    },
    {
        "id": 6,
        "description": (
            "This scenario illustrates an **UPDATE statement** vulnerability. By concatenating "
            "the new_email and user_id, an attacker can modify unintended records or inject additional "
            "SQL. Using placeholders and validating inputs (e.g., ensuring email format is correct and "
            "user_id is an integer) is crucial to avoid malicious updates."
        ),
        "vulnerable_code": (
            "query = \"UPDATE users SET email = '\" + new_email + \"' WHERE user_id = '\" + user_id + \"'\""
        ),
        "correct_code": "UPDATE users SET email = %s WHERE user_id = %s",
        "starter_code": (
            "# This code is vulnerable. Fix it with placeholders.\n"
            "# Original vulnerable code:\n"
            "query = \"UPDATE users SET email = '\" + new_email + \"' WHERE user_id = '\" + user_id + \"'\"\n"
            "\n"
            "# A safer approach might be:\n"
            "# UPDATE users SET email = %s WHERE user_id = %s\n"
            "\n"
            "# Type your final code below:\n"
        ),
        "hints": [
            "Hint 1: Use placeholders for both email and user_id.\n\n"
            "Example:\n```\nUPDATE users SET email = %s WHERE user_id = %s\n```",
            "Hint 2: Validate email format before updating.\n\n"
            "For example:\n```\nimport re\nif re.match(r'^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$', new_email):\n    UPDATE users SET email = %s WHERE user_id = %s\nelse:\n    # invalid email\n```",
            "Hint 3: Ensure user_id is the correct type (int).\n\n"
            "For example:\n```\nuser_id = int(user_id)\nUPDATE users SET email = %s WHERE user_id = %s\n```"
        ]
    }
]

ERROR_SIGN_MESSAGES = {
    1: "Unexpected System Behavior: Your system might produce unpredictable results if compromised.",
    2: "SQL Error Messages: Detailed SQL errors can expose underlying vulnerabilities.",
    3: "Slow Performance: Malicious queries can severely slow down your database.",
    4: "Data Breach: Unauthorized data access is a major security risk.",
    5: "Log File Anomalies: Suspicious entries in your log files indicate potential attacks.",
    6: "Unexpected Outgoing Traffic: Abnormal network activity could indicate data exfiltration."
}

def normalize_code(code):
    """ Remove whitespace and convert to lowercase for a simple 'string match' approach. """
    return re.sub(r'\s+', '', code.lower())

@app.route('/')
def index():
    # Reset session data for a new training session
    session['current_index'] = 0
    session['results'] = []
    session['attempts'] = 0
    session['failed_scenarios'] = 0
    # Instead of showing the training immediately, redirect to the interactive explanation page
    return redirect(url_for('explanation'))

@app.route('/explanation')
def explanation():
    # Render the interactive explanation page (with JS transitions) before the intro/training begins
    return render_template('sql_injection_interactive.html')

@app.route('/intro')
def intro():
    return render_template('intro.html')  # Ensure you have intro.html in your templates directory

@app.route('/attack', methods=['GET', 'POST'])
def attack():
    current_index = session.get('current_index', 0)
    if current_index >= len(SCENARIOS):
        return redirect(url_for('final', index=0))

    scenario = SCENARIOS[current_index]
    attempts = session.get('attempts', 0)
    message = None

    if request.method == 'POST':
        user_answer = request.form.get('user_answer', '')
        correct_normalized = normalize_code(scenario['correct_code'])
        user_normalized = normalize_code(user_answer)

        if user_normalized == correct_normalized:
            session['results'].append({
                'id': scenario['id'],
                'description': scenario['description'],
                'vulnerable_code': scenario['vulnerable_code'],
                'correct_code': scenario['correct_code'],
                'user_answer': user_answer,
                'is_correct': True
            })
            session['attempts'] = 0
            return redirect(url_for('feedback', scenario_id=scenario['id']))
        else:
            attempts += 1
            session['attempts'] = attempts

            if attempts >= 3:
                # On the third failed attempt, create an error message and mark the scenario as failed
                sign = ERROR_SIGN_MESSAGES.get(scenario['id'], "Unexpected Web Application Input detected.")
                error_message = f"Warning: The SQL code is compromised and might get hacked. {sign}"

                session['results'].append({
                    'id': scenario['id'],
                    'description': scenario['description'],
                    'vulnerable_code': scenario['vulnerable_code'],
                    'correct_code': scenario['correct_code'],
                    'user_answer': user_answer,
                    'is_correct': False,
                    'error_message': error_message
                })

                failed_scenarios = session.get('failed_scenarios', 0)
                session['failed_scenarios'] = failed_scenarios + 1

                session['attempts'] = 0

                # Redirect to the Danger/Warning page before showing feedback
                return redirect(url_for('danger', scenario_id=scenario['id']))
            else:
                message = f"Incorrect. You have {3 - attempts} attempts left. Try again."

    return render_template(
        'base.html',
        page="attack",
        scenario=scenario,
        scenario_index=current_index + 1,
        total=len(SCENARIOS),
        message=message
    )

@app.route('/danger/<int:scenario_id>')
def danger(scenario_id):
    """
    Render the danger/warning page with a color-coded risk meter after 3 failed attempts.
    """
    results = session.get('results', [])
    scenario_result = next((r for r in results if r['id'] == scenario_id), None)
    if not scenario_result:
        return redirect(url_for('attack'))

    failed_scenarios = session.get('failed_scenarios', 0)

    return render_template(
        'base.html',
        page="danger",
        result=scenario_result,
        failed_scenarios=failed_scenarios
    )

@app.route('/feedback/<int:scenario_id>')
def feedback(scenario_id):
    results = session.get('results', [])
    scenario_result = next((r for r in results if r['id'] == scenario_id), None)
    if not scenario_result:
        return redirect(url_for('attack'))
    return render_template('base.html', page="feedback", result=scenario_result)

@app.route('/next_scenario/<int:scenario_id>')
def next_scenario(scenario_id):
    current_index = session.get('current_index', 0) + 1
    session['current_index'] = current_index
    session['attempts'] = 0

    if current_index >= len(SCENARIOS):
        return redirect(url_for('final', index=0))
    else:
        return redirect(url_for('attack'))

@app.route('/final/<int:index>')
def final(index):
    results = session.get('results', [])
    total = len(results)
    if not results or index < 0 or index >= total:
        return redirect(url_for('index'))

    scenario_result = results[index]
    score = sum(1 for r in results if r['is_correct'])
    return render_template(
        'final_results.html',
        index=index,
        total=total,
        result=scenario_result,
        score=score
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
