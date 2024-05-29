<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>File Manager</title>
<style>
/* Add your styles here */
</style>
</head>
<body>
<div id="top">
  <form id="mkdir" action="?" method="post">
    <label for="dirname">Create Folder: </label><input id="dirname" name="name" type="text">
    <input type="submit" value="Create">
  </form>
  <form id="file_drop_target" enctype="multipart/form-data" method="post" action="?">
    <input type="hidden" name="do" value="upload">
    <input type="hidden" name="xsrf" value="<?=$_COOKIE['_sfm_xsrf']?>">
    <input type="file" name="file_data[]" multiple>
    <input type="submit" value="Upload">
  </form>
  <button id="unzip_button" style="display: none;">Unzip</button>
</div>
<div id="breadcrumb">&nbsp;</div>
<table id="list">
<thead>
<tr>
<th>Name</th>
<th>Size</th>
<th>Modified</th>
<th>Permissions</th>
<th>Actions</th>
</tr>
</thead>
<tbody id="list_body"></tbody>
</table>
<script src="//code.jquery.com/jquery-1.11.1.min.js"></script>
<script>
/* JavaScript and jQuery code */

function updateBreadcrumb(path) {
    var breadcrumb = $('#breadcrumb');
    var parts = path.split('/');
    var breadcrumbPath = '';
    breadcrumb.empty();
    parts.forEach(function(part, index) {
        if (index !== 0) {
            breadcrumb.append(' / ');
        }
        breadcrumbPath += (index > 0 ? '/' : '') + part;
        var link = $('<a></a>').attr('href', '#').text(part).on('click', function() {
            list(breadcrumbPath);
        });
        breadcrumb.append(link);
    });
}

function list(path) {
    $.get('?do=list&file=' + encodeURIComponent(path), function(data) {
        if (data.success) {
            var listBody = $('#list_body');
            listBody.empty();
            data.results.forEach(function(file) {
                var row = $('<tr></tr>');
                row.append($('<td></td>').text(file.name));
                row.append($('<td></td>').text(file.is_dir ? '' : file.size));
                row.append($('<td></td>').text(new Date(file.mtime * 1000).toLocaleString()));
                row.append($('<td></td>').text(file.is_readable ? 'r' : '' + file.is_writable ? 'w' : '' + file.is_executable ? 'x' : ''));
                var actions = $('<td></td>');
                if (file.is_deleteable) {
                    actions.append($('<button>Delete</button>').on('click', function() {
                        if (confirm('Are you sure you want to delete this item?')) {
                            $.post('', {'do': 'delete', 'file': file.path, 'xsrf': $.cookie('_sfm_xsrf')}, function() {
                                list(path);
                            });
                        }
                    }));
                }
                if (!file.is_dir) {
                    actions.append($('<button>Download</button>').on('click', function() {
                        window.location = '?do=download&file=' + encodeURIComponent(file.path);
                    }));
                    if (file.name.match(/\.zip$/i)) {
                        actions.append($('<button>Unzip</button>').on('click', function() {
                            unzip(file.path);
                        }));
                    }
                }
                row.append(actions);
                listBody.append(row);
            });
            updateBreadcrumb(path);
        } else {
            alert(data.error.msg);
        }
    }, 'json');
}

function unzip(path) {
    $.post('', {'do': 'unzip', 'file': path, 'xsrf': $.cookie('_sfm_xsrf')}, function(response) {
        if (response.success) {
            alert('Unzipped successfully');
            list(dirname(path));
        } else {
            alert('Unable to unzip the file');
        }
    }, 'json');
}

function dirname(path) {
    return path.replace(/\\/g, '/').replace(/\/[^\/]*$/, '');
}

$(function() {
    list('.');
    $('#mkdir').submit(function(e) {
        e.preventDefault();
        $.post('', {'do': 'mkdir', 'name': $('#dirname').val(), 'file': '.', 'xsrf': $.cookie('_sfm_xsrf')}, function() {
            list('.');
        });
    });
    $('#file_drop_target').on('submit', function(e) {
        var formData = new FormData(this);
        $.ajax({
            url: '?',
            type: 'POST',
            data: formData,
            success: function() {
                list('.');
            },
            cache: false,
            contentType: false,
            processData: false
        });
        e.preventDefault();
    });
});
</script>
</body>
</html>

<?php
/********************************
Simple PHP File Manager
********************************/

// Disable error report for undefined superglobals
error_reporting(error_reporting() & ~E_NOTICE);

// Security options
$allow_delete = true;
$allow_upload = true;
$allow_create_folder = true;
$allow_direct_link = true;
$allow_show_folders = true;

$disallowed_patterns = ['*.php'];
$hidden_patterns = ['*.php', '.*'];

$PASSWORD = '';  // Set the password, to access the file manager... (optional)

if ($PASSWORD) {
    session_start();
    if (!$_SESSION['_sfm_allowed']) {
        $t = bin2hex(openssl_random_pseudo_bytes(10));
        if ($_POST['p'] && sha1($t . $_POST['p']) === sha1($t . $PASSWORD)) {
            $_SESSION['_sfm_allowed'] = true;
            header('Location: ?');
        }
        echo '<html><body><form action=? method=post>PASSWORD:<input type=password name=p autofocus/></form></body></html>';
        exit;
    }
}

setlocale(LC_ALL, 'en_US.UTF-8');

$tmp_dir = dirname($_SERVER['SCRIPT_FILENAME']);
if (DIRECTORY_SEPARATOR === '\\') $tmp_dir = str_replace('/', DIRECTORY_SEPARATOR, $tmp_dir);

if (!isset($_REQUEST['file']))
    $_REQUEST['file'] = "";

$tmp = get_absolute_path($tmp_dir . '/' . $_REQUEST['file']);

if ($tmp === false)
    err(404, 'File or Directory Not Found');
if (substr($tmp, 0, strlen($tmp_dir)) !== $tmp_dir)
    err(403, "Forbidden");
if (strpos($_REQUEST['file'], DIRECTORY_SEPARATOR) === 0)
    err(403, "Forbidden");
if (preg_match('@^.+://@', $_REQUEST['file'])) {
    err(403, "Forbidden");
}

if (!$_COOKIE['_sfm_xsrf'])
    setcookie('_sfm_xsrf', bin2hex(openssl_random_pseudo_bytes(16)));
if ($_POST) {
    if ($_COOKIE['_sfm_xsrf'] !== $_POST['xsrf'] || !$_POST['xsrf'])
        err(403, "XSRF Failure");
}

$file = $_REQUEST['file'] ?: '.';

if (!isset($_GET['do']))
    $_GET['do'] = "";

if (!isset($_POST['do']))
    $_POST['do'] = "";

if ($_GET['do'] == 'list') {
    if (is_dir($file)) {
        $directory = $file;
        $result = [];
        $files = array_diff(scandir($directory), ['.', '..']);
        foreach ($files as $entry) if (!is_entry_ignored($entry, $allow_show_folders, $hidden_patterns)) {
            $i = $directory . '/' . $entry;
            $stat = stat($i);
            $result[] = [
                'mtime' => $stat['mtime'],
                'size' => $stat['size'],
                'name' => basename($i),
                'path' => preg_replace('@^\./@', '', $i),
                'is_dir' => is_dir($i),
                'is_deleteable' => $allow_delete && ((!is_dir($i) && is_writable($directory)) ||
                    (is_dir($i) && is_writable($directory) && is_recursively_deleteable($i))),
                'is_readable' => is_readable($i),
                'is_writable' => is_writable($i),
                'is_executable' => is_executable($i),
            ];
        }
        usort($result, function ($f1, $f2) {
            $f1_key = ($f1['is_dir'] ?: 2) . $f1['name'];
            $f2_key = ($f2['is_dir'] ?: 2) . $f2['name'];
            if ($f1_key > $f2_key)
                return 1;
            else
                return 0;
        });
    } else {
        err(412, "Not a Directory");
    }
    echo json_encode(['success' => true, 'is_writable' => is_writable($file), 'results' => $result]);
    exit;
} elseif ($_POST['do'] == 'delete') {
    if ($allow_delete) {
        rmrf($file);
    }
    exit;
} elseif ($_POST['do'] == 'mkdir' && $allow_create_folder) {
    chdir($file);
    @mkdir($_POST['name']);
    exit;
} elseif ($_POST['do'] == 'upload' && $allow_upload) {
    var_dump($_FILES);
    foreach ($_FILES['file_data']['name'] as $i => $name) {
        move_uploaded_file($_FILES['file_data']['tmp_name'][$i], $file . '/' . $name);
    }
    exit;
} elseif ($_GET['do'] == 'download') {
    $file = $_REQUEST['file'];
    $filename = basename($file);
    if ($filename === '.' || $filename === '..') {
        err(404, "File Not Found");
    }
    header('Content-Type: ' . mime_content_type($file));
    header('Content-Transfer-Encoding: binary');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
} elseif ($_POST['do'] == 'unzip') {
    $zip = new ZipArchive;
    $res = $zip->open($file);
    if ($res === TRUE) {
        $zip->extractTo(dirname($file));
        $zip->close();
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false]);
    }
    exit;
}

function rmrf($dir)
{
    if (is_dir($dir)) {
        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            rmrf("$dir/$file");
        }
        rmdir($dir);
    } else {
        unlink($dir);
    }
}

function get_absolute_path($path)
{
    $path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path);
    $parts = array_filter(explode(DIRECTORY_SEPARATOR, $path), 'strlen');
    $absolutes = [];
    foreach ($parts as $part) {
        if ('.' == $part) continue;
        if ('..' == $part) {
            array_pop($absolutes);
        } else {
            $absolutes[] = $part;
        }
    }
    return DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $absolutes);
}

function is_entry_ignored($entry, $allow_show_folders, $hidden_patterns)
{
    if ($entry == '.' || $entry == '..') return true;
    if (!$allow_show_folders && is_dir($entry)) return true;
    foreach ($hidden_patterns as $pattern) {
        if (fnmatch($pattern, $entry)) return true;
    }
    return false;
}

function is_recursively_deleteable($d)
{
    $stack = [$d];
    while ($dir = array_pop($stack)) {
        if (!is_readable($dir) || !is_writable($dir)) {
            return false;
        }
        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            if (is_dir($file)) {
                $stack[] = "$dir/$file";
            } else {
                if (!is_writable("$dir/$file")) {
                    return false;
                }
            }
        }
    }
    return true;
}

function asBytes($ini_v)
{
    $ini_v = trim($ini_v);
    $s = ['g' => 1 << 30, 'm' => 1 << 20, 'k' => 1 << 10];
    return intval($ini_v) * ($s[strtolower(substr($ini_v, -1))] ?: 1);
}

function err($code, $msg)
{
    http_response_code($code);
    echo json_encode(['error' => ['code' => $code, 'msg' => $msg]]);
    exit;
}
?>
