<?php
session_start();
?>
<html>
    <head>
    <link rel="stylesheet" href="css/bulma.min.css" />
    </head>
    <body>
    
    <nav class="navbar is-primary" role="navigation" aria-label="main navigation">
    <div class="navbar-brand">
        <a class="navbar-item">System Security Secure&copy; Site</a>
    </div>

    <div class="navbar-menu">
        <div class="navbar-start">
        </div>

        <div class="navbar-end">
        <div class="navbar-item">
            <div class="buttons">
            </div>
        </div>
        </div>
    </div>
    </nav>
    
    <div class="section">
        <div class="container">
            <h1 class="title">Comic of the day</h1>
            <h3 class="subtitle">Our security is no laugh though #blueteam #unhackable</h3>
        </div>
    </div>
    
    <div class="section">
        <div class="container">
        <?php
            $comic = isset($_GET['comic'])
                ? $_GET['comic']
                : 'bobby.jpg';

            $content = base64_encode(file_get_contents("img/" . $comic));
            
            echo "<img src='data:image/jpg;base64, $content' />";
        ?>
        </div>
        <br>
        <div class="container">
            <p>See more dank comics:</p>
            <ul>
                <li><a href="?comic=wrench.jpg">Crypto lolz</a></li>
                <li><a href="?comic=bobby.jpg">SQLi lolz</a></li>
            </ul>
        </div>
    </div>        
    
    <div class="section">
        <div class="container">
            <p>I'm so proud I even let you
            <a href="?source">View the source code</a>.<br/>
            <?php
                if(isset($_GET['source'])){
                    highlight_file ( __FILE__);
                }
            ?>
        </div>
    </div>
    
    </body>

</html>

