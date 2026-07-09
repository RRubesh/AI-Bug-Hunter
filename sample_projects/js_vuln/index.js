const child_process = require('child_process');

function renderProfile(userProfile) {
    // 1. XSS vulnerability via innerHTML
    const el = document.getElementById('username-display');
    el.innerHTML = userProfile.username;
    
    // 2. React dangerouslySetInnerHTML bypass match
    const customContent = { __html: userProfile.bio };
}

function executeSystemPing(ipAddress) {
    // 3. Command Injection via child_process.exec
    child_process.exec("ping -c 1 " + ipAddress, (err, stdout, stderr) => {
        console.log(stdout);
    });
}

function verifyDatabaseRecord(userId) {
    // 4. SQL Injection via string query concatenation
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    db.query(query, (err, results) => {
        console.log(results);
    });
}

// 5. Hardcoded Slack OAuth Token for secret scanning check
const slackToken = "xoxb-123456789012345678901234567890";
