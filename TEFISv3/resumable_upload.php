<?php

Class ResumableLargeFilesUpload {

    //FILE: resumable_upload.php - Complete resumable file upload system module
    /*error_reporting(E_ALL);
    ini_set('display_errors', 'On');*/

    private $upload_destination;
    private $bytes_per_chunk;
    
    private $action_param = 'action';
    private $data_param = 'data';

    // Configuration - can be overridden before including this file
    public function __construct($param_prefix = '', $upload_destination = './uploads/', $bytes_per_chunk = 30) {
        
        if (substr($upload_destination, -1) !== '/') {
            $upload_destination .= '/';
        }

        $this->upload_destination = $upload_destination;
        $this->bytes_per_chunk = $bytes_per_chunk;
        
        // Apply prefix to all parameter names
        if (!empty($param_prefix)) {
            $reflection = new ReflectionClass($this);
            $properties = $reflection->getProperties(ReflectionProperty::IS_PRIVATE);
            
            foreach ($properties as $property) {
                $property_name = $property->getName();
                if (strpos($property_name, '_param') !== false) {
                    $this->$property_name = $param_prefix . $this->$property_name;
                }
            }
        }
        
    }
    
    // use this upload module
    public function handleRequest() {
        
        // Handle different actions based on request
        if (isset($_GET[$this->action_param])) {
            switch ($_GET[$this->action_param]) {
                case 'upload':
                    $this->handleUpload();
                    break;
                case 'check':
                    $this->handleCheck();
                    break;
                case 'merge':
                    $this->handleMerge();
                    break;
                case 'delete':
                    $this->handleDelete();
                    break;
                case 'delete_completed':
                    $this->handleDeleteCompleted();
                    break;
                default:
                    return false;
                return true;
            }
        }
        return false;
    }
    
    public function isRequested() {
        return (isset($_GET[$this->action_param]) || isset($_GET[$this->data_param]));
    }

    private function handleUpload() {
        
        ignore_user_abort(true);
        
        $filename   = urldecode($_SERVER['HTTP_X_FILE_NAME']);
        $filesize   = $_SERVER['HTTP_X_FILE_SIZE'];
        $chunksize  = $_SERVER['HTTP_X_CHUNK_SIZE'];
        $chunkindex = $_SERVER['HTTP_X_CHUNK_INDEX'];
        
        // Validate required headers
        if (!isset($_SERVER['HTTP_X_FILE_NAME'])) {
            http_response_code(400);
            die("Name required");
        }
        
        if (!isset($_SERVER['HTTP_X_CHUNK_INDEX'])) {
            http_response_code(400);
            die("Index required");
        }
        
        if (!preg_match('/^[0-9]+$/', $_SERVER['HTTP_X_CHUNK_INDEX'])) {
            http_response_code(400);
            die("Index error");
        }
        
        if (!isset($_SERVER['HTTP_X_CHUNK_SIZE'])) {
            http_response_code(400);
            die("Size required");
        }
        
        if (!preg_match('/^[0-9]+$/', $_SERVER['HTTP_X_CHUNK_SIZE'])) {
            http_response_code(400);
            die("Size error");
        }
        
        if (!isset($_SERVER['HTTP_X_FILE_SIZE'])) {
            http_response_code(400);
            die("Size required");
        }
        
        if (!preg_match('/^[0-9]+$/', $_SERVER['HTTP_X_FILE_SIZE'])) {
            http_response_code(400);
            die("Size error");
        }
        
        // Create directories if they don't exist
        if (!file_exists($this->upload_destination."")){
            mkdir($this->upload_destination."");
            chmod($this->upload_destination."", octdec(777));
        }
        
        if (!file_exists($this->upload_destination."TEMP/")){
            mkdir($this->upload_destination."TEMP/");
            chmod($this->upload_destination."TEMP/", octdec(777));
        }
        
        // Create chunk directory
        $chunk_dir = $this->upload_destination."TEMP/" . str_replace(".", "_", $filename).'---'. $filesize .'/';
        if (!file_exists($chunk_dir)){
            mkdir($chunk_dir);
            chmod($chunk_dir, octdec(777));
        }
        
        // Save chunk
        $target = $chunk_dir . $filename . '-' . $chunkindex;
        unlink($target);
        
        $putdata = fopen("php://input", "r");
        $fp = fopen($target, "w");
        $file_size_uploaded = 0;
        
        while ($data = fread($putdata, 1024)) {
            $file_size_uploaded += fwrite($fp, $data);
        }
        
        fclose($fp);
        fclose($putdata);
        chmod($target, octdec(777));
        
        // Verify chunk size
        if($file_size_uploaded != (int)$chunksize) {
            unlink($target);
            http_response_code(500);
            die("Chunk size mismatch");
        }
    }

    private function handleCheck() {
        
        if (!isset($_REQUEST['FileName'])) {
            throw new Exception('Name required');
        }
        
        if (!isset($_REQUEST['FileSize'])) {
            throw new Exception('Size required');
        }
        
        if (!preg_match('/^[0-9]+$/', $_REQUEST['FileSize'])) {
            throw new Exception('Size error');
        }
        
        $result = ["fileExists" => false, "chunksExist" => false, "chunksSize" => "0 B", "uploadedChunks" => []];
        $target = $this->upload_destination."" . $_REQUEST['FileName'];
        $target_temp_dir = $this->upload_destination."TEMP/" . str_replace(".", "_", $_REQUEST['FileName']).'---'. $_REQUEST['FileSize'] .'/';
        
        // Check if file already exists
        if (file_exists($target) && filesize($target) == (int)$_REQUEST['FileSize']){
            $result["fileExists"] = true;
        }
        
        // Check for existing chunks
        if (is_dir($target_temp_dir)) {
            $chunksExist = [];
            $chunksSize = 0;
            
            $files = array_diff(scandir($target_temp_dir), array('.','..'));
            foreach($files as $file) {
                $index = substr($file, strrpos($file, '-')+1);
                if(is_numeric($index) && is_int((int)$index)) {
                    array_push($chunksExist, (int)$index);
                    $chunksSize += filesize($target_temp_dir."/".$file);
                }
            }
            
            if($chunksExist != []) {
                $result["chunksExist"] = true;
                $result["chunksSize"] = $this->humanFilesize($chunksSize, 2);
                $result["uploadedChunks"] = $chunksExist;
            }
        }
        
        header('Content-Type: application/json');
        echo json_encode($result);
        exit;
    }

    private function handleMerge() {

        
        ignore_user_abort(true);
        
        if (!isset($_REQUEST['name'])) {
            throw new Exception('Name required');
        }
        
        if (!isset($_REQUEST['indexes'])) {
            throw new Exception('Indexes required');
        }
        
        if (!preg_match('/^[0-9]+$/', $_REQUEST['indexes'])) {
            throw new Exception('Indexes error');
        }
        
        if (!isset($_REQUEST['size'])) {
            throw new Exception('Size required');
        }
        
        if (!preg_match('/^[0-9]+$/', $_REQUEST['size'])) {
            throw new Exception('Size error');
        }
        
        $filesize = $_REQUEST['size'];
        $target = $this->upload_destination."full_" . $_REQUEST['name'];
        $dst = fopen($target, 'wb');
        
        // Merge all chunks
        for ($i = 0; $i < $_REQUEST['indexes']; $i++) {
            $slice = $this->upload_destination.'TEMP/' . str_replace(".", "_", $_REQUEST['name']) .'---'. $filesize . '/' . $_REQUEST['name'] . '-' . $i;
            $src = fopen($slice, 'rb');
            stream_copy_to_stream($src, $dst);
            fclose($src);
        }
        
        fclose($dst);
        chmod($target, octdec(777));
        
        // Verify merged file size
        if($_REQUEST['size'] == filesize($target)) {
            @unlink($this->upload_destination."" . $_REQUEST['name']); // remove if overriding
            rename($target, $this->upload_destination."" . $_REQUEST['name']);
            
            // Clean up chunk files and directory
            $dir = $this->upload_destination."TEMP/" . str_replace(".", "_", $_REQUEST['name']) .'---'. $filesize;
            $files = array_diff(scandir($dir), array('.','..'));
            foreach($files as $file) {
                unlink("$dir/$file");
            }
            rmdir($dir);
            
            @rmdir($this->upload_destination."TEMP/"); // if empty -> remove parts dir
        } else {
            unlink($target);
        }
        
        echo hash_file('sha1', $this->upload_destination."" . $_REQUEST['name']);
        exit;
    }

    private function handleDelete() {
        
        $deleteFile = $_GET[$this->data_param] ?? '';
        
        if ($deleteFile && file_exists($this->upload_destination."TEMP/" . str_replace(".", "_", $deleteFile).'/')){
            // Remove parts files and directory
            $dir = $this->upload_destination."TEMP/" . str_replace(".", "_", $deleteFile).'/';
            $files = array_diff(scandir($dir), array('.','..'));
            foreach($files as $file) {
                unlink("$dir/$file");
            }
            rmdir($dir);
            
            @rmdir($this->upload_destination."TEMP/"); // if empty -> remove parts dir
        }
        
        // Get current URL without delete and data parameters
        $redirect_url = $this->getCurrentUrlWithoutAllParams();
        header('Location: ' . $redirect_url);
        exit;
    }

    private function handleDeleteCompleted() {
        
        $deleteFile = $_GET[$this->data_param] ?? '';
        
        if ($deleteFile) {
            $filePath = $this->upload_destination . $deleteFile;
            
            // Security check - ensure file is within upload directory
            $realUploadPath = realpath($this->upload_destination);
            $realFilePath = realpath($filePath);
            
            if ($realFilePath && strpos($realFilePath, $realUploadPath) === 0 && file_exists($filePath)) {
                // Additional security check - don't allow deletion of directories or system files
                if (is_file($filePath) && basename($filePath) !== 'TEMP') {
                    unlink($filePath);
                }
            }
        }
        
        // Get current URL without delete_completed and data parameters
        $redirect_url = $this->getCurrentUrlWithoutAllParams();
        header('Location: ' . $redirect_url);
        exit;
    }

    private function getCurrentUrlWithoutParams($params) {
        $url_parts = parse_url($_SERVER['REQUEST_URI']);
        $base_url = $url_parts['path'];
        
        if (isset($url_parts['query'])) {
            parse_str($url_parts['query'], $query_params);
            foreach ($params as $param) {
                unset($query_params[$param]);
            }
            
            if (!empty($query_params)) {
                $base_url .= '?' . http_build_query($query_params);
            }
        }
        
        return $base_url;
    }
    
    private function getCurrentUrlWithoutAllParams() {
        $url_parts = parse_url($_SERVER['REQUEST_URI']);
        $base_url = $url_parts['path'];
        
        if (isset($url_parts['query'])) {
            parse_str($url_parts['query'], $query_params);
            
            // Get all param variable values to remove from URL
            $reflection = new ReflectionClass($this);
            $properties = $reflection->getProperties(ReflectionProperty::IS_PRIVATE);
            
            foreach ($properties as $property) {
                $property_name = $property->getName();
                if (strpos($property_name, '_param') !== false) {
                    $param_value = $this->$property_name;
                    unset($query_params[$param_value]);
                }
            }
            
            if (!empty($query_params)) {
                $base_url .= '?' . http_build_query($query_params);
            }
        }
        
        return $base_url;
    }

    public function getParamVariableNames() {
        $param_vars = [];
        $reflection = new ReflectionClass($this);
        $properties = $reflection->getProperties(ReflectionProperty::IS_PRIVATE);
        
        foreach ($properties as $property) {
            $property_name = $property->getName();
            if (strpos($property_name, '_param') !== false) {
                $param_vars[$property_name] = $this->$property_name;
            }
        }
        
        return $param_vars;
    }

    private function getCurrentUrlWithAction($action) {
        $url_parts = parse_url($_SERVER['REQUEST_URI']);
        $base_url = $url_parts['path'];
        
        $query_params = [];
        if (isset($url_parts['query'])) {
            parse_str($url_parts['query'], $query_params);
        }
        
        $query_params[$this->action_param] = $action;
        
        return $base_url . '?' . http_build_query($query_params);
    }

    private function getCurrentUrlBase() {
        $url_parts = parse_url($_SERVER['REQUEST_URI']);
        $base_url = $url_parts['path'];
        
        $query_params = [];
        if (isset($url_parts['query'])) {
            parse_str($url_parts['query'], $query_params);
            // Remove action parameter for base URL
            unset($query_params[$this->action_param]);
        }
        
        if (!empty($query_params)) {
            $base_url .= '?' . http_build_query($query_params);
        }
        
        return $base_url;
    }

    private function humanFilesize($bytes, $decimals = 2) {
        $sz = 'BKMGTP';
        $factor = floor((strlen($bytes) - 1) / 3);
        return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . " " . @$sz[$factor] . "B";
    }

    private function dirToArray($dir, $depth = -1) {
        $result = array();
        
        if (!file_exists($dir) || $depth === 0) {
            return $result;
        }

        $cdir = scandir($dir);

        foreach ($cdir as $key => $value) {
            if (!in_array($value,array(".",".."))) {
                if (is_dir($dir . DIRECTORY_SEPARATOR . $value)) {
                    if ($depth === -1) {
                        $result[$value] = $this->dirToArray($dir . DIRECTORY_SEPARATOR . $value);
                    } else if ($depth > 1){
                        $result[$value] = $this->dirToArray($dir . DIRECTORY_SEPARATOR . $value, $depth-1);
                    } else {
                        $result[] = $value;
                    }
                } else {
                    $result[] = $value;
                } 
            }
        }

        return $result;
    }

    private function tempDirsSizes($temp_dir_tree, $dir_path) {
        $chunks_sizes = [];
        foreach($temp_dir_tree as $index => $dir) {
            $pos = strrpos($index, "---");
            if ($pos === false) {
                $chunks_sizes[$index]['full_size'] = 0;
                $chunks_sizes[$index]['human_full_size'] = "0 B";
                $chunks_sizes[$index]['name'] = '';
            } else {
                $chunks_sizes[$index]['full_size'] = (int)substr($index, $pos+3);
                $chunks_sizes[$index]['human_full_size'] = $this->humanFilesize((int)substr($index, $pos+3));
                $chunks_sizes[$index]['name'] = substr($index, 0, $pos);
            }
            
            $chunks_sizes[$index]['full_name'] = $index;
            $chunks_sizes[$index]['size'] = 0;
            
            foreach($dir as $file) {
                $chunks_sizes[$index]['size'] += filesize(join('/', [trim($dir_path, '/'), trim($index, '/'), trim($file, '/')]));
            }
            
            $chunks_sizes[$index]['human_size'] = $this->humanFilesize($chunks_sizes[$index]['size']);
        }
        
        return $chunks_sizes;
    }

    private function getFileInfo($filepath) {
        if (!file_exists($filepath)) {
            return null;
        }
        
        return [
            'name' => basename($filepath),
            'size' => filesize($filepath),
            'human_size' => $this->humanFilesize(filesize($filepath)),
            'modified' => date('Y-m-d H:i:s', filemtime($filepath))
        ];
    }

    public function show() {
        
        // Get file lists
        $dir = realpath($this->upload_destination.'TEMP');
        $temp_files_list = [];
        $uploaded_list = [];
        
        if ($dir !== false) {
            $temp_files_list = $this->dirToArray($dir);
            $temp_files_list = $this->tempDirsSizes($temp_files_list, $this->upload_destination.'TEMP');
        }
        
        if (file_exists($this->upload_destination.'')) {
            $uploaded_files = $this->dirToArray($this->upload_destination.'', 1);
            foreach($uploaded_files as $file) {
                if ($file !== "TEMP") {
                    $fileInfo = $this->getFileInfo($this->upload_destination . $file);
                    if ($fileInfo) {
                        $uploaded_list[] = $fileInfo;
                    }
                }
            }
        }
        
        $check_url = $this->getCurrentUrlWithAction('check');
        $upload_url = $this->getCurrentUrlWithAction('upload');
        $merge_url = $this->getCurrentUrlWithAction('merge');
        $base_url = $this->getCurrentUrlBase();
        
        ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Resumable File Upload</title>
        <meta charset="utf-8">
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
            }
            .delete-btn {
                color: red;
                text-decoration: none;
                font-weight: bold;
                margin-right: 10px;
            }
            .delete-btn:hover {
                background-color: #ffebee;
                padding: 2px 4px;
                border-radius: 3px;
            }
            .file-info {
                margin-left: 20px;
                color: #666;
                font-size: 0.9em;
            }
            .file-link {
                color: #0066cc;
                text-decoration: none;
            }
            .file-link:hover {
                text-decoration: underline;
            }
            ul {
                list-style-type: none;
                padding-left: 0;
            }
            li {
                margin: 10px 0;
                padding: 5px;
                border-bottom: 1px solid #eee;
            }
        </style>
    </head>
    <body>

    <script type="text/javascript">
    const BYTES_PER_CHUNK = 1024 * 1024 * <?php echo $this->bytes_per_chunk; ?>; // 1MB chunk sizes
    var fileSlices = 0;
    var fileSlicesTotal = 0;
    var fileSizeTotal = 0;
    var fileSizeUploaded = 0;
    var fileUploadThreadsAvailable = 20;
    var fileUploadStartTime = null;
    var fileProcessingStartTime = null;

    // URLs for different actions
    const CHECK_URL = '<?php echo $check_url; ?>';
    const UPLOAD_URL = '<?php echo $upload_url; ?>';
    const MERGE_URL = '<?php echo $merge_url; ?>';

    function confirmDelete(filename) {
        return confirm('Are you sure you want to delete "' + filename + '"?');
    }

    async function uploadCheck(fileData) {
        var percentageDiv = document.getElementById("percent");  
        var progressBar = document.getElementById("progressBar");
        percentageDiv.innerHTML = 'Upload started...';
        progressBar.value = 0;
        
        const formData = new FormData();
        formData.append("FileName", fileData.name);
        formData.append("FileSize", fileData.size);

        try {
            fetch(CHECK_URL, {
                method: "POST",
                body: formData
            }).then((response) => {
                if (!response.ok) {
                    console.error("HTTP error! Status: " + response.status);
                    throw new Error("HTTP error! Status: " + response.status);
                }
                return response.json();
            }).then((response) => {
                if (response.fileExists) {
                    if (!confirm("File with the same Name and Size already exists!\nDo you wanna upload it again and override?")) {
                        return;
                    }
                }
                
                if (response.chunksExist && confirm(response.chunksSize + " of file with the same name was already uploaded!\nDo you wanna continue in upload?")) {
                    uploadFile(fileData, response.uploadedChunks);
                } else {
                    uploadFile(fileData, []);
                }
            });
        } catch (error) {
            console.error("There has been a problem with your fetch operation:", error);
        }
    }

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    function included(array, object) {
        for (var i = 0; i < array.length; i++) {
            if (array[i] == object) {
                return true;
            }
        }
        return false;
    }

    async function calculateFileHash(file, algorithm = 'SHA-1') {
        try {
            const arrayBuffer = await file.arrayBuffer();
            const hashBuffer = await crypto.subtle.digest(algorithm, arrayBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            return hashHex;
        } catch (error) {
            throw new Error(`Hash calculation failed: ${error.message}`);
        }
    }

    async function uploadFile(fileData, uploadedChunks) {
        var percentageDiv = document.getElementById("percent");
        percentageDiv.innerHTML = 'Calculating checksum...';
        
        const fileHash = await calculateFileHash(fileData);
        
        var fileChunkStart = 0;
        var fileChunkEnd = 0;
        var fileChunkIndex = 0;

        fileSlices = Math.ceil(fileData.size / BYTES_PER_CHUNK);
        fileSlicesTotal = fileSlices;
        fileSizeTotal = fileData.size;
        fileSizeUploaded = 0;
        fileUploadStartTime = performance.now();

        while(fileChunkStart < fileData.size && fileSlices > 0) {
            fileChunkEnd = fileChunkStart + BYTES_PER_CHUNK;
            if(fileChunkEnd > fileData.size) {
                fileChunkEnd = fileData.size;
            }
            
            if (!included(uploadedChunks, fileChunkIndex)) {
                var fileChunk = null;
                if (fileData.webkitSlice) {
                    fileChunk = fileData.webkitSlice(fileChunkStart, fileChunkEnd);
                } else if (fileData.mozSlice) {
                    fileChunk = fileData.mozSlice(fileChunkStart, fileChunkEnd);
                } else {
                    fileChunk = fileData.slice(fileChunkStart, fileChunkEnd); 
                }
            
                fileUploadThreadsAvailable--;
                uploadChunk(fileData.name, fileChunk, fileChunkIndex, fileSizeTotal, fileHash);
            } else {
                fileSizeUploaded += fileChunkEnd-fileChunkStart;
                uploadShowInfo(fileSizeUploaded, fileSizeTotal);
                fileSlices--;

                if(fileSlices == 0) {
                    uploadMerge(fileData.name, fileHash);
                }
            }
            
            while(fileUploadThreadsAvailable == 0) {await sleep(10);}

            fileChunkStart = fileChunkEnd;
            fileChunkIndex++;
        }
        
        if (fileSlices < 0) {
            window.stop();
        }
    }

    function uploadChunk(fileName, fileChunk, fileChunkIndex, fileSizeTotal, fileHash) {
        var xhr;
        var prevFileSizeUploaded = 0;

        xhr = new XMLHttpRequest();

        xhr.addEventListener("load", function (evt) {
            if(evt.target.status != 200) {
                fileSlices = -1;
                window.stop();
                alert("ERROR: " + evt.target.status + " - " + evt.target.response);
                
                var percentageDiv = document.getElementById("percent");  
                percentageDiv.innerHTML = "ERROR: " + evt.target.status + " - " + evt.target.response;
            } else {
                fileUploadThreadsAvailable++;
                fileSlices--;

                if(fileSlices == 0) {
                    uploadMerge(fileName, fileHash);
                }
            }
        }, false);

        xhr.upload.addEventListener("progress", function (evt) {
            if (evt.lengthComputable) {
                fileSizeUploaded += evt.loaded - prevFileSizeUploaded;
                prevFileSizeUploaded = evt.loaded;
                uploadShowInfo(fileSizeUploaded, fileSizeTotal);
            }
        }, false);

        xhr.open("post", UPLOAD_URL, true);
        xhr.setRequestHeader("X-File-Name", encodeURIComponent(fileName));
        xhr.setRequestHeader("X-File-Size", fileSizeTotal);
        xhr.setRequestHeader("X-Chunk-Size", fileChunk.size);
        xhr.setRequestHeader("X-Chunk-Index", fileChunkIndex);
        
        xhr.send(fileChunk);
    }

    function uploadShowInfo(fileSizeUploaded, fileSizeTotal) {
        var percentageDiv = document.getElementById("percent");  
        var progressBar = document.getElementById("progressBar");
        
        progressBar.max = fileSizeTotal;  
        progressBar.value = fileSizeUploaded;
        
        var uploadTime = performance.now() - fileUploadStartTime;
        
        const uploadInSeconds = Math.floor(uploadTime/1000);
        const uploadInMinutes = Math.floor((uploadTime/1000/60)*100) / 100;
        
        var MBs = Math.round(((fileSizeUploaded/uploadInSeconds) / 1024 / 1024) * 100) / 100;
        var MBm = Math.round(((fileSizeUploaded/uploadInMinutes) / 1024 / 1024) * 100) / 100;

        var REMInMinutes = "...";
        if (MBs === Infinity) {
            MBs = "...";
        }
        if (MBm !== Infinity) {
            REMInMinutes = Math.ceil((((fileSizeTotal-fileSizeUploaded) / 1024 / 1024)/MBm)*100)/100;
        }
        
        const uploadedMBs = Math.round((fileSizeUploaded / 1024 / 1024) * 100) / 100;
        const totalMBs = Math.round((fileSizeTotal / 1024 / 1024) * 100) / 100;
        
        percentageDiv.innerHTML = Math.round(fileSizeUploaded/fileSizeTotal * 100) + "% [" + decimalTrailingZeros(uploadedMBs, 2) + "/" + decimalTrailingZeros(totalMBs, 2) + " MB] (" + decimalTrailingZeros(MBs, 2) + " MB/s) [ELA: "+getTimefromMillis(uploadTime)+"] (REM: " + decimalTrailingZeros(REMInMinutes, 2) + " min)";

        if (fileSizeUploaded == fileSizeTotal) {
            percentageDiv.innerHTML = "Processing...";
            fileProcessingStartTime = performance.now();
        }
    }

    function uploadMerge(fileName, fileHash) {
        var xhr = new XMLHttpRequest();
        var fd = new FormData();
        
        fd.append("name", fileName);
        fd.append("indexes", fileSlicesTotal);
        fd.append("size", fileSizeTotal);
        
        xhr.addEventListener("load", function (evt) {
            console.log(evt.target.responseText);
            console.log(fileHash);
            const checksum = (evt.target.responseText == fileHash) ? 'OK' : 'Invalid';
            
            var percentageDiv = document.getElementById("percent");  
            var uploadTime = performance.now() - fileUploadStartTime;
            var processingTime = performance.now() - fileProcessingStartTime;
            
            percentageDiv.innerHTML = "Done - checksum: "+checksum+"! ("+Math.round((fileSizeTotal / 1024 / 1024) * 100) / 100+" MB) [All: "+getTimefromMillis(uploadTime)+"] (Processing: "+getTimefromMillis(processingTime)+")";  
            
            // Refresh page after successful upload
            setTimeout(function() {
                window.location.href = '<?php echo $base_url; ?>';
            }, 2000);
        }, false);

        xhr.open("POST", MERGE_URL, true);
        xhr.send(fd);
    }

    function decimalTrailingZeros(number, decimals) {
        number = ('' + number);
        if (!isNaN(number) && !isNaN(parseFloat(number))) {
            var decNumb = ('' + number).split('.');
            if (decNumb.length == 2) {
                return decNumb[0] + "." + decNumb[1].padEnd(decimals, '0');
            } else if (decNumb.length == 1) {
                return decNumb[0] + "." + "".padEnd(decimals, '0');
            }
        }
        return number;
    }

    function getTimefromMillis(timeMillis) {
        const d = new Date(Date.UTC(0,0,0,0,0,0,timeMillis)),
          parts = [
            d.getUTCHours(),
            d.getUTCMinutes(),
            d.getUTCSeconds()
          ],
          formatted = parts.map(s => String(s).padStart(2,'0')).join(':');
         return formatted;
    }
    </script>

    <h2>Resumable large files upload</h2>
    <input type="file" name="file" id="fileToUpload">
    <button onclick="uploadCheck(document.getElementById('fileToUpload').files[0])">Upload</button>
    <br><br>
    <progress id="progressBar" value="0" max="100" style="width: 270px;"></progress>
    <br>
    <span id="percent">Select file...</span>

    <div id="incompleted">
        <h2>Incompleted:</h2>
        <ul>
        <?php foreach($temp_files_list as $fl): ?>
            <li>
                <a href="<?php echo $base_url . (strpos($base_url, '?') !== false ? '&' : '?') . $this->action_param . '=delete&' . $this->data_param . '=' . urlencode($fl['full_name']); ?>" class="delete-btn" onclick="return confirmDelete('<?php echo htmlspecialchars($fl['name'], ENT_QUOTES); ?>')">X</a> - <span><?=$fl['name']?> (<?=$fl['human_size']?>/<?=$fl['human_full_size']?>)</span>
                <br>
                <progress value="<?=$fl['size']?>" max="<?=$fl['full_size']?>" style="width: 270px;"></progress>
            </li>
        <?php endforeach; ?>
        </ul>
    </div>

    <div id="completed">
        <h2>Completed:</h2>
        <ul>
        <?php foreach($uploaded_list as $file): ?>
            <li>
                <a href="<?php echo $base_url . (strpos($base_url, '?') !== false ? '&' : '?') . $this->action_param . '=delete_completed&' . $this->data_param . '=' . urlencode($file['name']); ?>" class="delete-btn" onclick="return confirmDelete('<?php echo htmlspecialchars($file['name'], ENT_QUOTES); ?>')">X</a> - 
                <a href="<?php echo $this->upload_destination . $file['name']; ?>" class="file-link"><?php echo htmlspecialchars($file['name']); ?></a>
                <div class="file-info">
                    Size: <?php echo $file['human_size']; ?> | Modified: <?php echo $file['modified']; ?>
                </div>
            </li>
        <?php endforeach; ?>
        </ul>
    </div>

    </body>
    </html>
        <?php
    }
    
}

?>
