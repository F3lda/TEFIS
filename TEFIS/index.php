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
// TODO - create dir, upload to dir, remove dir, move to dir
if(!(isset($_GET["DOWNLOAD"]) && isset($_GET["DIR"]) && isset($_GET["ID"]) && ($_GET["DIR"] != "PRIVATE" || (isset($_POST["username"]) && isset($_POST["password"]) && $_POST["username"] == $USERNAME && $_POST["password"] == $PASSWORD)))){
?>
<!DOCTYPE html>
<html>
<head>
	<title>TEFIS - Temporary files storage</title>
	<meta name="viewport" content="width=device-width, initial-scale=1">
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
}
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
		<legend>TEFIS - upload files</legend>
		<?php
			if(isset($_POST["dir"])) {
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
		if(isset($_POST["username"]) && isset($_POST["password"]) && $_POST["username"] == $USERNAME && $_POST["password"] == $PASSWORD){
			$files = scandir("./PRIVATE");
			$files = array_diff($files, array('.', '..', '.htaccess'));
			if(isset($files[$_GET["ID"]])){
				if(file_exists("./PRIVATE/".$files[$_GET["ID"]]) && $files[$_GET["ID"]] != ""){
					echo "<pre>".file_get_contents("./PRIVATE/".$files[$_GET["ID"]])."</pre>";
				} else {
					echo "File doesn't exist!";
				}
			} else {
				echo "File doesn't exist!";
			}
		} else {
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
			<input type="submit" name="submit" value="Login">
		</form>
		</fieldset>
			<?php
		}
	// DOWNLOAD FILE
	} else if(isset($_GET["DOWNLOAD"]) && isset($_GET["DIR"]) && isset($_GET["ID"])){
		if($_GET["DIR"] != "PRIVATE" || (isset($_POST["username"]) && isset($_POST["password"]) && $_POST["username"] == $USERNAME && $_POST["password"] == $PASSWORD)){
			$files = scandir("./".$_GET["DIR"]);
			$files = array_diff($files, array('.', '..', '.htaccess'));
			if(isset($files[$_GET["ID"]])){
				$file = "./".$_GET["DIR"]."/".$files[$_GET["ID"]];
				if(file_exists($file) && $files[$_GET["ID"]] != ""){
					header("Content-Description: File Transfer"); 
					header("Content-Type: application/octet-stream"); 
					header("Content-Disposition: attachment; filename=\"". basename($file) ."\""); 

					readfile($file);
					exit(); 
				} else {
					echo "File doesn't exist!";
				}
			} else {
				echo "File doesn't exist!";
			}
		} else {
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
			<input type="submit" name="submit" value="Login">
		</form>
		</fieldset>
		<span>(After download you can close this window.)</span>
			<?php
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
					echo '<span>(Now you can close this window and relogin.)</span>';
				} else {
					echo "File doesn't exist!";
				}
			} else {
				echo "File doesn't exist!";
			}
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
			<input type="submit" name="submit" value="Login">
		</form>
		</fieldset>
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
					echo ' - <a class="abutton" title="Delete file" target="_blank" href="./?DELETE&DIR='.$dir.'&ID='.$id.'">X</a> - <a class="abutton" title="Download file" target="_blank" href="./?DOWNLOAD&DIR='.$dir.'&ID='.$id.'">\=/</a><br>';
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