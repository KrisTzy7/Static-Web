<?php
// Retrieve input
$username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
$password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle POST request
} else {
    http_response_code(405);
    echo "Method Not Allowed";
}

// Validate input
if (!empty($username)) {
    if (!empty($password)) {
        // Database credentials
        $host = "localhost";
        $dbusername = "root";
        $dbpassword = "";
        $dbname = "insert";

        // Create a connection
        $conn = new mysqli($host, $dbusername, $dbpassword, $dbname);

        // Check connection
        if ($conn->connect_error) {
            die('Connection failed: ' . $conn->connect_error);
        } else {
            // Hash the password for security
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            // Use a prepared statement to prevent SQL injection
            $sql = $conn->prepare("INSERT INTO insertuser (username, password) VALUES (?, ?)");
            $sql->bind_param("ss", $username, $hashed_password);

            // Execute the statement
            if ($sql->execute()) {
                echo "New record inserted successfully";
            } else {
                echo "Error: " . $sql->error;
            }

            // Close the statement and connection
            $sql->close();
            $conn->close();
        }
    } else {
        echo "Password should not be empty";
        die();
    }
} else {
    echo "Username should not be empty";
    die();
}
?>
