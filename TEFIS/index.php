<?php
/**
 * @file index.php (TEFIS)
 * 
 * @brief TEFIS - Temporary files storage (save files from someone else's computer without login to your important accounts)
 * @date 2020-10-22
 * @author F3lda
 */
// -----------------------------
$USERNAME = "admin";// <- change this
$PASSWORD = "admin";// <- change this
// -----------------------------
// maybe TODO - create dir, remove dir, move to dir, upload to dir; hash file number (file number+filename)
// -------------------------------------------------------------------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------------------------------------------------------------------
// SHOW FILE
if(isset($_GET["SHOW"]) && isset($_GET["ID"]) && isset($_POST["username"]) && isset($_POST["password"]) && $_POST["username"] == $USERNAME && $_POST["password"] == $PASSWORD){
	$files = scandir("./PRIVATE");
	$files = array_diff($files, array('.', '..', '.htaccess'));
	if(isset($files[$_GET["ID"]])){
		$file = "./PRIVATE/".$files[$_GET["ID"]];
		if(file_exists($file) && $files[$_GET["ID"]] != ""){
			//$file_info = new finfo(FILEINFO_MIME_TYPE);
			//$file_info_type = $file_info->file($file);
			$file_info_type = mime_content_type($file);
			$file_type = explode("/",$file_info_type);
			$allowed_files = array(
				"application/javascript", 
				"application/xhtml+xml",
				"application/json",
				"application/ld+json",
				"application/xml"
			);
			if($file_type[0] == "text" || array_search($file_info_type, $allowed_files, true) !== false){
				//ASCII
				echo "<pre>".file_get_contents($file)."</pre>";
			} else {
				//binary
				header('Content-Type: ' . $file_info_type);
				header('Content-Disposition: inline; filename="' . basename($file) . '"');
				header('Content-Transfer-Encoding: binary');
				header('Content-Length: ' . filesize($file));
				header('Accept-Ranges: bytes');
				header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
				header("Cache-Control: post-check=0, pre-check=0", false);
				header("Cache-Control: no-cache");
				header("Connection: close");
				header('Expires: 0');
				@ob_clean();
				@flush();
				@readfile($file);
				exit();
			}
		} else {
			echo "File doesn't exist!";
		}
	} else {
		echo "File doesn't exist!";
	}
// DOWNLOAD FILE
} else if(isset($_GET["DOWNLOAD"]) && isset($_GET["DIR"]) && isset($_GET["ID"]) && ($_GET["DIR"] != "PRIVATE" || (isset($_POST["username"]) && isset($_POST["password"]) && $_POST["username"] == $USERNAME && $_POST["password"] == $PASSWORD))){
	$files = scandir("./".$_GET["DIR"]);
	$files = array_diff($files, array('.', '..', '.htaccess'));
	if(isset($files[$_GET["ID"]])){
		$file = "./".$_GET["DIR"]."/".$files[$_GET["ID"]];
		if(file_exists($file) && $files[$_GET["ID"]] != ""){
			header('Content-Description: File Transfer');
			header('Content-Type: application/octet-stream');
			header('Content-Disposition: attachment; filename="' . basename($file) . '"');
			header('Content-Transfer-Encoding: binary');
			header('Content-Length: ' . filesize($file));
			header('Accept-Ranges: bytes');
			header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
			header("Cache-Control: post-check=0, pre-check=0", false);
			header("Cache-Control: no-cache");
			header("Connection: close");
			header('Expires: 0');
			@ob_clean();
			@flush();
			@readfile($file);
			exit();
		} else {
			echo "File doesn't exist!";
		}
	} else {
		echo "File doesn't exist!";
	}
	echo '<br><br><button onclick="window.history.back();">Back</button>';
}
// -------------------------------------------------------------------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------------------------------------------------------------------
?>
<!DOCTYPE html>
<html>
<head>
	<title>TEFIS - Temporary files storage</title>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Type" content="text/html; UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<link rel="icon" type="image/png" href="data:image/png;base64,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
	j/AwLQ3DbbVjUvAAAAAElFTkSuQmCC" />
	<style>
	body {
		background: #8a8a8a;
	}

	.content {
		max-width: 1250px;
		margin: auto;
		background: white;
		padding: 10px;
	}

	form {
		margin: 0;
	}

	.message {
		color: red;
	}

	input[type="submit"], input[type="button"], input[type="file"], button {
		background-color: lightgrey;
		padding: 4px;
		cursor: pointer;
	}

	.abutton {
		text-decoration: none;
	}
	
	textarea {
		height: 530px;
		width: 99%;
		display: block;
		resize: vertical;
	}
	</style>
</head>
<body>
	<div class="content">
	<?php
	// UPLOAD NOTES
	if(isset($_GET["NOTES"])){
		if(isset($_POST["username"]) && isset($_POST["password"]) && $_POST["username"] == $USERNAME && $_POST["password"] == $PASSWORD){
			if(isset($_POST["file"]) && isset($_POST["note"])){
				if(isset($_POST["dir"]) && is_dir($_POST["dir"])){
					$newFile = "./".$_POST["dir"]."/".$_POST["file"];
					if(!file_exists($newFile)){
						if(file_put_contents($newFile, $_POST["note"]) !== FALSE){
							chmod($newFile, 0777);
							echo "<p>Your note: {$_POST["file"]} has been successfully saved.</p>";
						} else {
							echo "<p>Failed to save the note.";
						}
					} else {
						echo "<p>File [". $_POST["file"] ."] already exists.</p>";
					}
				} else {
					echo "<p>Target directory not found.</p>";
				}
			} else {
				echo "<p>Invalid parameters.</p>";
			}
			echo '<button onclick="window.location.href = \'./\';">Exit and Relogin</button><br><br>';
			echo '<button onclick="window.history.back();">Back</button>';
		} else {
			?>
<div>
	<form action="./?NOTES" method="POST">
		Notes: <br><textarea name="note" wrap="hard"></textarea>
		File name: <input type="text" name="file" size="40" value="NOTE_<?php echo date("Y-m-d_H-i-s"); ?>.txt"><br>
		<span>Upload to: </span>
		<select name="dir">
			<option value="PRIVATE" selected="selected">Private files</option>
			<option value="SHARED">Shared files</option>
		</select>
		<br>
		<br>
		<br>
		<fieldset>
		<legend>TEFIS - upload notes</legend>
		<?php
			if(isset($_POST["dir"])) {
				echo '<span class="message">Nothing has been uploaded!</span><br>';
			}
		?>
			Username: <input type="text" name="username"><br>
			Password: <input type="password" name="password"><br>
			<input type="submit" name="submit" value="Upload notes">
		</fieldset>
	</form>
	<br>
	<button onclick="window.history.back();">Back</button>
</div>
			<?php
		}		
	// UPLOAD FILE
	} else if(isset($_GET["UPLOAD"])){
		if(isset($_POST["username"]) && isset($_POST["password"]) && $_POST["username"] == $USERNAME && $_POST["password"] == $PASSWORD){

			$files = array();
			foreach($_FILES as $upload => $fileUploads){
				$fileKeys = array_keys($fileUploads);
				
				if(isset($fileUploads["name"])){
					
					for($i = 0; $i < count($fileUploads["name"]); $i++) {
						
						foreach ($fileKeys as $key) {
							$files[$upload."-".($i+1)][$key] = $fileUploads[$key][$i];
						}
					}
				}
			}
			
			foreach($files as $file){
				echo "<p>";
				if(isset($file['error']) || !is_array($file['error'])){
					if($file['error'] == UPLOAD_ERR_OK){
						if(isset($_POST["dir"]) && is_dir($_POST["dir"])){
							$newFile = "./".$_POST["dir"]."/".$file['name'];
							if(!file_exists($newFile)){
								if(move_uploaded_file($file['tmp_name'], $newFile)){
									chmod($newFile, 0777);
									// UPLOAD OK!
									echo "Your file: {$file['name']} has been successfully received.";
								} else {
									echo "Failed to move uploaded file.";
								}
							} else {
								echo "File [". $file['name'] ."] already exists.";
							}
						} else {
							echo "Target directory not found.";
						}
					} else if($file['error'] == UPLOAD_ERR_NO_FILE){
						//echo "No file sent.";
					} else if($file['error'] == UPLOAD_ERR_INI_SIZE || $file['error'] == UPLOAD_ERR_FORM_SIZE){
						echo "Exceeded filesize limit.";
					} else {
						echo "Unknown error.";
					}
				} else {
					echo "Invalid parameters.";
				}
				echo "</p>";
			}
			echo '<button onclick="window.location.href = \'./\';">Exit and Relogin</button><br><br>';
			echo '<button onclick="window.history.back();">Back</button>';
		} else {
			?>
<div>
	<script type="text/javascript">
	function upload_changed(){
		var i;
		var count = 0;
		var used = 0;
		var last = 0;
		for(i = 0; i < document.upload.elements.length; i++){
			if(document.upload.elements[i].type == 'file'){
				count++;
				if(document.upload.elements[i].value.length > 0){
					used++;
				}
				last = i;
			}
		}
		if(used >= count){
			var lastfile = document.upload.elements[last];
			if(lastfile){
				count++;
				var inputfile = document.createElement('input');
				inputfile.type = 'file';
				inputfile.size = 40;
				inputfile.name = 'upload_'+count+"[]";
				inputfile.onchange = upload_changed;
				inputfile.multiple = ' ';
				lastfile.parentNode.insertBefore(inputfile, lastfile.nextSibling);
				var br = document.createElement('br');
				lastfile.parentNode.insertBefore(br, lastfile.nextSibling);
				lastfile.parentNode.insertBefore(br, lastfile.nextSibling);
			}
		}
	}
	</script>
	<form name="upload" action="./?UPLOAD" method="POST" enctype="multipart/form-data">
		Files: <br>
		<input type="file" name="upload_1[]" size="40" onchange="upload_changed()" multiple>
		<br>
		<br>
		<span>Upload to: </span>
		<select name="dir">
			<option value="PRIVATE" selected="selected">Private files</option>
			<option value="SHARED">Shared files</option>
		</select>
		<br>
		<br>
		<br>
		<fieldset>
		<legend>TEFIS - upload files</legend>
		<?php
			if(isset($_FILES) && count($_FILES) > 1) {
				echo '<span class="message">Nothing has been uploaded!</span><br>';
			}
		?>
			Username: <input type="text" name="username"><br>
			Password: <input type="password" name="password"><br>
			<input type="submit" name="submit" value="Upload files">
		</fieldset>
	</form>
	<br>
	<button onclick="window.history.back();">Back</button>
</div>
			<?php
		}	
	// SHOW FILE
	} else if(isset($_GET["SHOW"]) && isset($_GET["ID"])){
		?>
		<fieldset>
		<legend>TEFIS - show file</legend>
		<form action="./<?php echo "?SHOW&ID=".$_GET["ID"]; ?>" method="POST">
		<?php
			if(isset($_POST["username"]) && isset($_POST["password"]) && ($_POST["username"] != $USERNAME || $_POST["password"] != $PASSWORD)) {
				echo '<span class="message">Wrong login credentials!</span><br>';
			}
		?>
			Username: <input type="text" name="username"><br>
			Password: <input type="password" name="password"><br>
			<input type="submit" name="submit" value="Show file">
		</form>
		</fieldset>
		<?php
	// DOWNLOAD FILE
	} else if(isset($_GET["DOWNLOAD"]) && isset($_GET["DIR"]) && isset($_GET["ID"])){
		?>
		<fieldset>
		<legend>TEFIS - download file</legend>
		<form action="./<?php echo "?DOWNLOAD&DIR=".$_GET["DIR"]."&ID=".$_GET["ID"]; ?>" method="POST">
		<?php
			if(isset($_POST["username"]) && isset($_POST["password"]) && ($_POST["username"] != $USERNAME || $_POST["password"] != $PASSWORD)) {
				echo '<span class="message">Wrong login credentials!</span><br>';
			}
		?>
			Username: <input type="text" name="username"><br>
			Password: <input type="password" name="password"><br>
			<input type="submit" name="submit" value="Download file">
		</form>
		</fieldset>
		<br>
		<button onclick="window.history.back();">Back</button>
		<?php
	// EDIT FILE
	} else if(isset($_GET["EDIT"]) && isset($_GET["DIR"]) && isset($_GET["ID"])){
		if(isset($_POST["username"]) && isset($_POST["password"]) && $_POST["username"] == $USERNAME && $_POST["password"] == $PASSWORD){
			$files = scandir("./".$_GET["DIR"]);
			$files = array_diff($files, array('.', '..', '.htaccess'));
			if(isset($files[$_GET["ID"]])){
				$file = "./".$_GET["DIR"]."/".$files[$_GET["ID"]];
				if(file_exists($file) && $files[$_GET["ID"]] != ""){
					if(isset($_GET["SAVE"]) && isset($_POST["content"])){// edit or save
						if(file_put_contents($file, $_POST["content"]) !== FALSE){
							chmod($file, 0777);
							echo "<p>Your file: {$files[$_GET["ID"]]} has been successfully saved.</p>";
							echo '<button onclick="window.location.href = \'./\';">Exit and Relogin</button>';
							echo '<br><br><button onclick="window.history.back();">Back</button>';
						} else {
							echo "<p>Failed to save the file.";
						}
					} else {
						?>		
						<form action="./<?php echo "?EDIT&DIR=".$_GET["DIR"]."&ID=".$_GET["ID"]."&SAVE"; ?>" method="POST">
							Filename: <?php echo $files[$_GET["ID"]]; ?><br>
							Content: <br><textarea name="content" wrap="hard"><?php echo file_get_contents($file); ?></textarea>
							<br>
							<br>
							<br>
							<fieldset>
							<legend>TEFIS - save file</legend>
								Username: <input type="text" name="username"><br>
								Password: <input type="password" name="password"><br>
								<input type="submit" name="submit" value="Save file">
							</fieldset>
						</form>
						<br>
						<button onclick="window.history.back();">Back</button>
						<?php
					}
				} else {
					echo "File doesn't exist!";
				}
			} else {
				echo "File doesn't exist!";
			}
		} else {
			?>
		<fieldset>
		<legend>TEFIS - edit file</legend>
		<form action="./<?php echo "?EDIT&DIR=".$_GET["DIR"]."&ID=".$_GET["ID"]; ?>" method="POST">
		<?php
			if(isset($_POST["username"]) && isset($_POST["password"]) && ($_POST["username"] != $USERNAME || $_POST["password"] != $PASSWORD)) {
				echo '<span class="message">Wrong login credentials!</span><br>';
			}
		?>
			Username: <input type="text" name="username"><br>
			Password: <input type="password" name="password"><br>
			<input type="submit" name="submit" value="Edit file">
		</form>
		</fieldset>
		<br>
		<button onclick="window.history.back();">Back</button>
			<?php
		}
	// RENAME FILE
	} else if(isset($_GET["RENAME"]) && isset($_GET["DIR"]) && isset($_GET["ID"])){
		if(isset($_POST["username"]) && isset($_POST["password"]) && $_POST["username"] == $USERNAME && $_POST["password"] == $PASSWORD){
			$files = scandir("./".$_GET["DIR"]);
			$files = array_diff($files, array('.', '..', '.htaccess'));
			if(isset($files[$_GET["ID"]])){
				$file = "./".$_GET["DIR"]."/".$files[$_GET["ID"]];
				if(file_exists($file) && $files[$_GET["ID"]] != ""){
					if(isset($_POST["newfilename"]) && $_POST["newfilename"] != ""){
						rename($file,"./".$_GET["DIR"]."/".$_POST["newfilename"]);
						echo "<p>File successfully renamed to: <span style='font-weight: bold;'>".$_POST["newfilename"]."</span></p>";
						echo '<button onclick="window.location.href = \'./\';">Exit and Relogin</button>';
					} else {
						echo "New Filename is empty!";
					}
				} else {
					echo "File doesn't exist!";
				}
			} else {
				echo "File doesn't exist!";
			}
			echo '<br><br><button onclick="window.history.back();">Back</button>';
		} else {
			$files = scandir("./".$_GET["DIR"]);
			$files = array_diff($files, array('.', '..', '.htaccess'));
			if(isset($files[$_GET["ID"]])){
			?>
			<form action="./<?php echo "?RENAME&DIR=".$_GET["DIR"]."&ID=".$_GET["ID"]; ?>" method="POST">
				<span>New filename: </span>
				<input type="text" name="newfilename" size="40" value="<?php echo $files[$_GET["ID"]]; ?>">
				<br>
				<br>
				<br>
				<fieldset>
				<legend>TEFIS - rename file</legend>
				<?php
					if(isset($_POST["username"]) && isset($_POST["password"]) && ($_POST["username"] != $USERNAME || $_POST["password"] != $PASSWORD)) {
						echo '<span class="message">Wrong login credentials!</span><br>';
					}
				?>
					Username: <input type="text" name="username"><br>
					Password: <input type="password" name="password"><br>
					<input type="submit" name="submit" value="Rename file">
				</fieldset>
			</form>
			<br>
			<button onclick="window.history.back();">Back</button>
			<?php
			} else {
				echo "File doesn't exist!";
			}
		}
	// DELETE FILE
	} else if(isset($_GET["DELETE"]) && isset($_GET["DIR"]) && isset($_GET["ID"])){
		if(isset($_POST["username"]) && isset($_POST["password"]) && $_POST["username"] == $USERNAME && $_POST["password"] == $PASSWORD){
			$files = scandir("./".$_GET["DIR"]);
			$files = array_diff($files, array('.', '..', '.htaccess'));
			if(isset($files[$_GET["ID"]])){
				$file = "./".$_GET["DIR"]."/".$files[$_GET["ID"]];
				if(file_exists($file) && $files[$_GET["ID"]] != ""){
					unlink($file);
					echo "<h4>File [".$file."] deleted successfully!</h4>";
					echo '<button onclick="window.location.href = \'./\';">Exit and Relogin</button>';
				} else {
					echo "File doesn't exist!";
				}
			} else {
				echo "File doesn't exist!";
			}
			echo '<br><br><button onclick="window.history.back();">Back</button>';
		} else {
			?>
		<fieldset>
		<legend>TEFIS - delete file</legend>
		<form action="./<?php echo "?DELETE&DIR=".$_GET["DIR"]."&ID=".$_GET["ID"]; ?>" method="POST">
		<?php
			if(isset($_POST["username"]) && isset($_POST["password"]) && ($_POST["username"] != $USERNAME || $_POST["password"] != $PASSWORD)) {
				echo '<span class="message">Wrong login credentials!</span><br>';
			}
		?>
			Username: <input type="text" name="username"><br>
			Password: <input type="password" name="password"><br>
			<input type="submit" name="submit" value="Delete file">
		</form>
		</fieldset>
		<br>
		<button onclick="window.history.back();">Back</button>
			<?php
		}
	} else
	// SHOW LOGIN FORM
	if((!isset($_POST["username"]) || !isset($_POST["password"])) || ($_POST["username"] != $USERNAME || $_POST["password"] != $PASSWORD)){
	?>
		<fieldset>
		<legend><h3 style="margin: 5px;"><a href="https://github.com/F3lda/TEFIS" target="_blank">TEFIS</a> - Temporary files storage</h3></legend>
		<form action="./" method="POST">
		<?php
			if(isset($_POST["username"]) && isset($_POST["password"]) && ($_POST["username"] != $USERNAME || $_POST["password"] != $PASSWORD)) {
				echo '<span class="message">Wrong login credentials!</span><br>';
			}
		?>
			Username: <input type="text" name="username"><br>
			Password: <input type="password" name="password"><br>
			<input type="submit" value="Login">
		</form>
		</fieldset>
	<?php
	// LOGGED IN
	} else if($_POST["username"] == $USERNAME && $_POST["password"] == $PASSWORD){
		/* Name: human_filesize
		*  Source: https://www.php.net/manual/en/function.filesize.php#106569
		*  Date: 2020-11-09
		*  Author: rommel
		*  Edited: true
		*/
		function human_filesize($bytes, $decimals = 2) {
			$sizeChar = " KMGTP";
			$factor = floor((strlen($bytes) - 1) / 3);
			return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . " " . @$sizeChar[$factor] . "B";
		}
		/* ******* human_filesize - end ******* */

		function check_dir($dir){
			if(!file_exists($dir) && !is_dir($dir)) {
				mkdir("./".$dir, 0777);
				chmod("./".$dir, 0777);
			} else {
				$files = scandir("./".$dir);
				$files = array_diff($files, array('.', '..', '.htaccess'));
				foreach($files as $id => $file) {
					if($dir == "PRIVATE"){
						echo '<a title="Show/Download file" target="_blank" href="./?SHOW&ID='.$id.'">'.$file.'</a>';
					} else {
						echo '<a title="Show/Download file" target="_blank" href="./'.$dir.'/'.$file.'">'.$file.'</a>';
					}
					echo ' - (' .human_filesize(filesize('./'.$dir.'/'.$file)). ') - <a class="abutton" title="Download file" href="./?DOWNLOAD&DIR='.$dir.'&ID='.$id.'">\=/</a>
					- <a class="abutton" title="Edit file" href="./?EDIT&DIR='.$dir.'&ID='.$id.'">[E>]</a>
					- <a class="abutton" title="Rename file" href="./?RENAME&DIR='.$dir.'&ID='.$id.'">[R<]</a>
					- <a class="abutton" title="Delete file" href="./?DELETE&DIR='.$dir.'&ID='.$id.'">[X]</a>
					<br>';
				}
			}
		}
		
		echo "<h1>TEFIS - Temporary files storage</h1>";
		echo "<hr>";
		echo '<button onclick="window.location.href = \'./?UPLOAD\';" style="font-weight: bold;">UPLOAD FILES</button><span> </span>';
		echo '<button onclick="window.location.href = \'./?NOTES\';" style="font-weight: bold;">UPLOAD NOTES</button><span> </span>';
		echo '<button onclick="window.location.href = \'./\';">Logout</button><br>';
		
		echo "<h2>Private files</h2>";
		check_dir("PRIVATE");
		
		echo "<h2>Shared files</h2>";
		check_dir("SHARED");
	}
?>
	</div>
</body>
</html>