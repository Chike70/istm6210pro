<!DOCTYPE html>
<?php
// Initialize the session
session_start();

// Check if the user is already logged in, if yes then redirect him to welcome page
if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    header("location: welcome.php");
    exit;
}

// Include config file
require_once "config.php";

// Define variables and initialize with empty values
$username = $password = "";
$username_err = $password_err = $login_err = "";

// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){

    // Check if username is empty
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter username.";
    } else{
        $username = trim($_POST["username"]);
    }

    // Check if password is empty
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter your password.";
    } else{
        $password = trim($_POST["password"]);
    }

    // Validate credentials
    if(empty($username_err) && empty($password_err)){
        // Prepare a select statement
        $sql = "SELECT id, username, password FROM Login1 WHERE username = ?";

        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_username);

            // Set parameters
            $param_username = $username;

            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Store result
                mysqli_stmt_store_result($stmt);

                // Check if username exists, if yes then verify password
                if(mysqli_stmt_num_rows($stmt) == 1){
                    // Bind result variables
                    mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                    if(mysqli_stmt_fetch($stmt)){
                        if(password_verify($password, $hashed_password)){
                            // Password is correct, so start a new session
                            session_start();

                            // Store data in session variables
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["username"] = $username;

                            // Redirect user to welcome page
                            header("location: welcome.php");
                        } else{
                            // Password is not valid, display a generic error message
                            $login_err = "Invalid username or password.";
                        }
                    }
                } else{
                    // Username doesn't exist, display a generic error message
                    $login_err = "Invalid username or password.";
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }

    // Close connection
    mysqli_close($link);
}
?>

<html lang="en">
<head>
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <meta charset="utf-8">
   <title>Fairfax Clinical System</title>
   <link rel="stylesheet" href="./trial/test.css">
   <!-- <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
   <style>
       body{ font: 14px sans-serif; }
       .container{ width: 360px; padding: 20px; }
   </style> -->
</head>
<body>
    <div class="container">
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" class="form" id="login">
            <h1 class="form_title">Login to Patient Portal</h1>
            <div class="form_message form_message-error"></div>

            <div class="form_input-group">
                <input type="text" name="username" class="form_input <?php echo (!empty($username_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $username; ?>" autofocus placeholder="Email Address">
                <span class="invalid-feedback"><?php echo $username_err; ?></span>
                <!-- <div class="form_input-error-message"></div> -->
            </div>

            <div class="form_input-group">
                <input type="password" name="password" class="form_input <?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>" autofocus placeholder="Password">
                <span class="invalid-feedback"><?php echo $password_err; ?></span>
                 <!-- <div class="form_input-error-message"></div> -->
            </div>

            <?php
            if(!empty($login_err)){
                echo '<div class="alert alert-danger">' . $login_err . '</div>';
            }
            ?>

            <button class="button_form" type="submit">Log in</button>
            <p class="form_text">
                <a href="reset-password.php" class="form_link">Forgot your Password?</a>
            </p>
            <p class="form_text">
                <a a class="form_link" href="#" id="linkCreateAccount">Don't have an account? Sign up</a>
            </p>
        </form>




        <?php

        // This is for Register form_message

        // Include config file
        require_once "config.php";

        // Define variables and initialize with empty values
        $username = $password = $confirm_password = "";
        $username_err = $password_err = $confirm_password_err = "";

        // Processing form data when form is submitted
        if($_SERVER["REQUEST_METHOD"] == "POST"){

            // Validate username
            if(empty(trim($_POST["username"]))){
                $username_err = "Please enter a username.";
            } elseif(!preg_match('/^[a-zA-Z0-9_]+$/', trim($_POST["username"]))){
                $username_err = "Username can only contain letters, numbers, and underscores.";
            } else{
                // Prepare a select statement
                $sql = "SELECT id FROM Login1 WHERE username = ?";

                if($stmt = mysqli_prepare($link, $sql)){
                    // Bind variables to the prepared statement as parameters
                    mysqli_stmt_bind_param($stmt, "s", $param_username);

                    // Set parameters
                    $param_username = trim($_POST["username"]);

                    // Attempt to execute the prepared statement
                    if(mysqli_stmt_execute($stmt)){
                        /* store result */
                        mysqli_stmt_store_result($stmt);

                        if(mysqli_stmt_num_rows($stmt) == 1){
                            $username_err = "This username is already taken.";
                        } else{
                            $username = trim($_POST["username"]);
                        }
                    } else{
                        echo "Oops! Something went wrong. Please try again later.";
                    }

                    // Close statement
                    mysqli_stmt_close($stmt);
                }
            }

            // Validate password
            if(empty(trim($_POST["password"]))){
                $password_err = "Please enter a password.";
            } elseif(strlen(trim($_POST["password"])) < 6){
                $password_err = "Password must have atleast 6 characters.";
            } else{
                $password = trim($_POST["password"]);
            }

            // Validate confirm password
            if(empty(trim($_POST["confirm_password"]))){
                $confirm_password_err = "Please confirm password.";
            } else{
                $confirm_password = trim($_POST["confirm_password"]);
                if(empty($password_err) && ($password != $confirm_password)){
                    $confirm_password_err = "Password did not match.";
                }
            }

            // Check input errors before inserting in database
            if(empty($username_err) && empty($password_err) && empty($confirm_password_err)){

                // Prepare an insert statement
                $sql = "INSERT INTO Login1 (username, password) VALUES (?, ?)";

                if($stmt = mysqli_prepare($link, $sql)){
                    // Bind variables to the prepared statement as parameters
                    mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);

                    // Set parameters
                    $param_username = $username;
                    $param_password = password_hash($password, PASSWORD_DEFAULT); // Creates a password hash

                    // Attempt to execute the prepared statement
                    if(mysqli_stmt_execute($stmt)){
                        // Redirect to login page
                        header("location: login.php");
                    } else{
                        echo "Oops! Something went wrong. Please try again later.";
                    }

                    // Close statement
                    mysqli_stmt_close($stmt);
                }
            }

            // Close connection
            mysqli_close($link);
        }
        ?>

        <form  action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" class="form form-hidden" id="createaccount">
            <h1 class="form_title">Create Account</h1>

            <div class="form_input-group">
                <input type="text" name="username" class="form_input <?php echo (!empty($username_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $username; ?>" autofocus placeholder="Email Address">
                <span class="invalid-feedback"><?php echo $username_err; ?></span>
                <!-- <div class="form_input-error-message"></div> -->
            </div>

            <div class="form_input-group">
                <input type="password" name="password" class="form_input <?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $password; ?>" autofocus placeholder="Password">
                <span class="invalid-feedback"><?php echo $password_err; ?></span>
              <!--  <div class="form_input-error-message"></div> -->
            </div>

            <div class="form_input-group">
                <input type="password" name="confirm_password" class="form_input <?php echo (!empty($confirm_password_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $confirm_password; ?>" autofocus placeholder="Confirm Password">
                <span class="invalid-feedback"><?php echo $confirm_password_err; ?></span>
                <!-- <div class="form_input-error-message"></div> -->
            </div>

            <input type="submit" class="btn btn-primary" value="Submit">

            <p class="form_text">
                <a class="form_link" href="#" id="linkLogin">Already have an account? Sign in</a>
            </p>
        </form>

    </div>

    <script src ="./trial/test.js"></script>

</body>
</html>
