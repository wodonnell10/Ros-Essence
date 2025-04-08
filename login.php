<?php
session_start();
require 'db_config.php'; // Connects to the database

// Get username and password from login form
$username = $_POST['username'];
$password = $_POST['password'];

// Secure the query using prepared statement
$stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

// If user exists
if ($result->num_rows === 1) {
    $row = $result->fetch_assoc();

    // Verify the password with the hashed version
    if (password_verify($password, $row['password'])) {
        // Save session data
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['username'] = $username;

        // Redirect to the protected home page
        header("Location: protected_home.html");
        exit();
    } else {
        // Password is incorrect
        echo "<!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <title>Login Failed</title>
            <script>
                alert('Incorrect password. Please try again.');
                window.location.href = 'index.html';
            </script>
        </head>
        <body></body>
        </html>";
    }
} else {
    // Username not found
    echo "<!DOCTYPE html>
    <html lang='en'>
    <head>
        <meta charset='UTF-8'>
        <title>User Not Found</title>
        <script>
            alert('User not found. Please check your username.');
            window.location.href = 'index.html';
        </script>
    </head>
    <body></body>
    </html>";
}

// Cleanup
$stmt->close();
$conn->close();
?>
