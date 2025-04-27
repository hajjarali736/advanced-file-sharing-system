CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK(role IN ('admin', 'user')) NOT NULL
);

-- Insert default admin user if it doesn't already exist
INSERT OR IGNORE INTO users (username, password_hash, role) 
VALUES ("Admin", "713bfda78870bf9d1b261f565286f85e97ee614efe5f0faf7c34e7ca4f65baca", 'admin');
