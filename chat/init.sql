-- Use the specified database (Replace 'chatdb' with your actual database name if different)
USE chatdb;

-- Drop tables if they already exist (to avoid conflicts during development/testing)
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS messages;

-- Create 'users' table
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- In a real application, this should store hashed passwords, not plain text
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_key VARCHAR(255)
);


-- Create 'ENCRYPTIONKEY' table
CREATE TABLE ENCRYPTIONKEY(
    key_id INT AUTO_INCREMENT PRIMARY KEY,
    key_type VARCHAR(255) NOT NULL,
    key_content TEXT NOT NULL,

    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,

    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (receiver_id) REFERENCES users(user_id)
);


-- Create 'messages' table
CREATE TABLE messages (
    message_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    message_text TEXT NOT NULL,

    iv TEXT NOT NULL,
    salt TEXT NOT NULL,
    additionalData TEXT,

    key_id INT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (receiver_id) REFERENCES users(user_id),
    FOREIGN KEY (key_id) REFERENCES ENCRYPTIONKEY(key_id)
);








-- Optionally, insert some initial data for testing
INSERT INTO users (username, password, session_key) VALUES ('Alice', 'password123', NULL); -- Use hashed passwords in production
INSERT INTO users (username, password, session_key) VALUES ('Bob', 'password456', NULL); -- Use hashed passwords in production
INSERT INTO ENCRYPTIONKEY (key_type, key_content, sender_id, receiver_id) VALUES ('false', 'false', '1', '2');
