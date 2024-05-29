<?php
/********************************
Simple PHP File Manager
Copyright John Campbell (jcampbell1)

Liscense: MIT
********************************/

//Disable error report for undefined superglobals
error_reporting( error_reporting() & ~E_NOTICE );

//Security options
$allow_delete = true; // Set to false to disable delete button and delete POST request.
$allow_upload = true; // Set to true to allow upload files
$allow_create_folder = true; // Set to false to disable folder creation
$allow_direct_link = true; // Set to false to only allow downloads and not direct link
$allow_show_folders = true; // Set to false to hide all subdirectories

$disallowed_patterns = ['*.php'];  // must be an array.  Matching files not allowed to be uploaded
$hidden_patterns = ['*.php','.*']; // Matching files hidden in directory index

$PASSWORD = 'RWS101Files';  // Set the password, to access the file manager... (optional)

if($PASSWORD) {

	session_start();
	if(!$_SESSION['_sfm_allowed']) {
		// sha1, and random bytes to thwart timing attacks.  Not meant as secure hashing.
		$t = bin2hex(openssl_random_pseudo_bytes(10));
		if($_POST['p'] && sha1($t.$_POST['p']) === sha1($t.$PASSWORD)) {
			$_SESSION['_sfm_allowed'] = true;
			header('Location: ?');
		}
		echo '<html>
		<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
		<body><div class="h-screen flex w-full justify-center items-center dark:bg-gray-800">

		<div class="flex relative rounded-md w-full px-4 max-w-xl">
			<form action=? method=post>
				<input type=password name=p autofocus class="w-full p-3 rounded-md border-2 border-r-white rounded-r-none border-gray-300 placeholder-gray-500 dark:placeholder-gray-300 dark:bg-gray-500dark:text-gray-300 dark:border-none " /></form>
	   
			<button
				class="inline-flex items-center gap-2 bg-violet-700 text-white text-lg font-semibold py-3 px-6 rounded-r-md">
				<span>OK</span>
			   
				</span>
			</button>
		</div>
	
	</div></body></html>';
		exit;
	}
}

// must be in UTF-8 or `basename` doesn't work
setlocale(LC_ALL,'en_US.UTF-8');

$tmp_dir = dirname($_SERVER['SCRIPT_FILENAME']);
if(DIRECTORY_SEPARATOR==='\\') $tmp_dir = str_replace('/',DIRECTORY_SEPARATOR,$tmp_dir);
$tmp = get_absolute_path($tmp_dir . '/' .$_REQUEST['file']);

if($tmp === false)
	err(404,'File or Directory Not Found');
if(substr($tmp, 0,strlen($tmp_dir)) !== $tmp_dir)
	err(403,"Forbidden");
if(strpos($_REQUEST['file'], DIRECTORY_SEPARATOR) === 0)
	err(403,"Forbidden");
if(preg_match('@^.+://@',$_REQUEST['file'])) {
	err(403,"Forbidden");
}


if(!$_COOKIE['_sfm_xsrf'])
	setcookie('_sfm_xsrf',bin2hex(openssl_random_pseudo_bytes(16)));
if($_POST) {
	if($_COOKIE['_sfm_xsrf'] !== $_POST['xsrf'] || !$_POST['xsrf'])
		err(403,"XSRF Failure");
}

$file = $_REQUEST['file'] ?: '.';

if($_GET['do'] == 'list') {
	if (is_dir($file)) {
		$directory = $file;
		$result = [];
		$files = array_diff(scandir($directory), ['.','..']);
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
		usort($result,function($f1,$f2){
			$f1_key = ($f1['is_dir']?:2) . $f1['name'];
			$f2_key = ($f2['is_dir']?:2) . $f2['name'];
			return $f1_key > $f2_key;
		});
	} else {
		err(412,"Not a Directory");
	}
	echo json_encode(['success' => true, 'is_writable' => is_writable($file), 'results' =>$result]);
	exit;
} elseif ($_POST['do'] == 'delete') {
	if($allow_delete) {
		rmrf($file);
	}
	exit;
} elseif ($_POST['do'] == 'mkdir' && $allow_create_folder) {
	// don't allow actions outside root. we also filter out slashes to catch args like './../outside'
	$dir = $_POST['name'];
	$dir = str_replace('/', '', $dir);
	if(substr($dir, 0, 2) === '..')
	    exit;
	chdir($file);
	@mkdir($_POST['name']);
	exit;
} elseif ($_POST['do'] == 'upload' && $allow_upload) {
	foreach($disallowed_patterns as $pattern)
		if(fnmatch($pattern, $_FILES['file_data']['name']))
			err(403,"Files of this type are not allowed.");

	$res = move_uploaded_file($_FILES['file_data']['tmp_name'], $file.'/'.$_FILES['file_data']['name']);
	exit;
} elseif ($_GET['do'] == 'download') {
	foreach($disallowed_patterns as $pattern)
		if(fnmatch($pattern, $file))
			err(403,"Files of this type are not allowed.");

	$filename = basename($file);
	$finfo = finfo_open(FILEINFO_MIME_TYPE);
	header('Content-Type: ' . finfo_file($finfo, $file));
	header('Content-Length: '. filesize($file));
	header(sprintf('Content-Disposition: attachment; filename=%s',
		strpos('MSIE',$_SERVER['HTTP_REFERER']) ? rawurlencode($filename) : "\"$filename\"" ));
	ob_flush();
	readfile($file);
	exit;
}elseif ($_POST['do'] == 'unzip') {
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

function is_entry_ignored($entry, $allow_show_folders, $hidden_patterns) {
	if ($entry === basename(__FILE__)) {
		return true;
	}

	if (is_dir($entry) && !$allow_show_folders) {
		return true;
	}
	foreach($hidden_patterns as $pattern) {
		if(fnmatch($pattern,$entry)) {
			return true;
		}
	}
	return false;
}

function rmrf($dir) {
	if(is_dir($dir)) {
		$files = array_diff(scandir($dir), ['.','..']);
		foreach ($files as $file)
			rmrf("$dir/$file");
		rmdir($dir);
	} else {
		unlink($dir);
	}
}
function is_recursively_deleteable($d) {
	$stack = [$d];
	while($dir = array_pop($stack)) {
		if(!is_readable($dir) || !is_writable($dir))
			return false;
		$files = array_diff(scandir($dir), ['.','..']);
		foreach($files as $file) if(is_dir($file)) {
			$stack[] = "$dir/$file";
		}
	}
	return true;
}

// from: http://php.net/manual/en/function.realpath.php#84012
function get_absolute_path($path) {
        $path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path);
        $parts = explode(DIRECTORY_SEPARATOR, $path);
        $absolutes = [];
        foreach ($parts as $part) {
            if ('.' == $part) continue;
            if ('..' == $part) {
                array_pop($absolutes);
            } else {
                $absolutes[] = $part;
            }
        }
        return implode(DIRECTORY_SEPARATOR, $absolutes);
    }

function err($code,$msg) {
	http_response_code($code);
	header("Content-Type: application/json");
	echo json_encode(['error' => ['code'=>intval($code), 'msg' => $msg]]);
	exit;
}

function asBytes($ini_v) {
	$ini_v = trim($ini_v);
	$s = ['g'=> 1<<30, 'm' => 1<<20, 'k' => 1<<10];
	return intval($ini_v) * ($s[strtolower(substr($ini_v,-1))] ?: 1);
}
$MAX_UPLOAD_SIZE = min(asBytes(ini_get('post_max_size')), asBytes(ini_get('upload_max_filesize')));
?>
<!DOCTYPE html>
<html><head>
<meta http-equiv="content-type" content="text/html; charset=utf-8">

<style>
body {font-family: "lucida grande","Segoe UI",Arial, sans-serif; font-size: 14px;width:1024;padding:1em;margin:0;}
th {font-weight: normal; color: #1F75CC; background-color: #F0F9FF; padding:.5em 1em .5em .2em;
	text-align: left;cursor:pointer;user-select: none;}
th .indicator {margin-left: 6px }
thead {border-top: 1px solid #82CFFA; border-bottom: 1px solid #96C4EA;border-left: 1px solid #E7F2FB;
	border-right: 1px solid #E7F2FB; }
#top {height:52px;}
#mkdir {display:inline-block;float:right;padding-top:16px;}
label { display:block; font-size:11px; color:#555;}
#file_drop_target {width:500px; padding:12px 0; border: 4px dashed #ccc;font-size:12px;color:#ccc;
	text-align: center;float:right;margin-right:20px;}
#file_drop_target.drag_over {border: 4px dashed #96C4EA; color: #96C4EA;}
#upload_progress {padding: 4px 0;}
#upload_progress .error {color:#a00;}
#upload_progress > div { padding:3px 0;}
.no_write #mkdir, .no_write #file_drop_target {display: none}
.progress_track {display:inline-block;width:200px;height:10px;border:1px solid #333;margin: 0 4px 0 10px;}
.progress {background-color: #82CFFA;height:10px; }
footer {font-size:11px; color:#bbbbc5; padding:4em 0 0;text-align: left;}
footer a, footer a:visited {color:#bbbbc5;}
#breadcrumb { padding-top:34px; font-size:15px; color:#aaa;display:inline-block;float:left;}
#folder_actions {width: 50%;float:right;}
a, a:visited { color:#00c; text-decoration: none}
a:hover {text-decoration: underline}
.sort_hide{ display:none;}
table {border-collapse: collapse;width:100%;}
thead {max-width: 1024px}
td { padding:.2em 1em .2em .2em; border-bottom:1px solid #def;height:30px; font-size:12px;white-space: nowrap;}
td.first {font-size:14px;white-space: normal;}
td.empty { color:#777; font-style: italic; text-align: center;padding:3em 0;}
.is_dir .size {color:transparent;font-size:0;}
.is_dir .size:before {content: "--"; font-size:14px;color:#333;}
.is_dir .download{visibility: hidden}
a.unzip {display:inline-block;
	background: url(data:image/png;base64,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) no-repeat scroll 0 2px;
	color:blue;	margin-left: 15px;font-size:11px;padding:0 0 0 13px;
}
a.delete {display:inline-block;
	background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAABGdBTUEAAK/INwWK6QAAABl0RVh0U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAADtSURBVHjajFC7DkFREJy9iXg0t+EHRKJDJSqRuIVaJT7AF+jR+xuNRiJyS8WlRaHWeOU+kBy7eyKhs8lkJrOzZ3OWzMAD15gxYhB+yzAm0ndez+eYMYLngdkIf2vpSYbCfsNkOx07n8kgWa1UpptNII5VR/M56Nyt6Qq33bbhQsHy6aR0WSyEyEmiCG6vR2ffB65X4HCwYC2e9CTjJGGok4/7Hcjl+ImLBWv1uCRDu3peV5eGQ2C5/P1zq4X9dGpXP+LYhmYz4HbDMQgUosWTnmQoKKf0htVKBZvtFsx6S9bm48ktaV3EXwd/CzAAVjt+gHT5me0AAAAASUVORK5CYII=) no-repeat scroll 0 2px;
	color:#d00;	margin-left: 15px;font-size:11px;padding:0 0 0 13px;
}
.name {
	background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAABAklEQVRIie2UMW6DMBSG/4cYkJClIhauwMgx8CnSC9EjJKcwd2HGYmAwEoMREtClEJxYakmcoWq/yX623veebZmWZcFKWZbXyTHeOeeXfWDN69/uzPP8x1mVUmiaBlLKsxACAC6cc2OPd7zYK1EUYRgGZFkG3/fPAE5fIjcCAJimCXEcGxKnAiICERkSIcQmeVoQhiHatoWUEkopJEkCAB/r+t0lHyVN023c9z201qiq6s2ZYA9jDIwx1HW9xZ4+Ihta69cK9vwLvsX6ivYf4FGIyJj/rg5uqwccd2Ar7OUdOL/kPyKY5/mhZJ53/2asgiAIHhLYMARd16EoCozj6EzwCYrrX5dC9FQIAAAAAElFTkSuQmCC) no-repeat scroll 0px 12px;
	padding:15px 0 10px 40px;
}
.is_dir .name {
	background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAADdgAAA3YBfdWCzAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAI0SURBVFiF7Vctb1RRED1nZu5977VQVBEQBKZ1GCDBEwy+ISgCBsMPwOH4CUXgsKQOAxq5CaKChEBqShNK222327f79n0MgpRQ2qC2twKOGjE352TO3Jl76e44S8iZsgOww+Dhi/V3nePOsQRFv679/qsnV96ehgAeWvBged3vXi+OJewMW/Q+T8YCLr18fPnNqQq4fS0/MWlQdviwVqNpp9Mvs7l8Wn50aRH4zQIAqOruxANZAG4thKmQA8D7j5OFw/iIgLXvo6mR/B36K+LNp71vVd1cTMR8BFmwTesc88/uLQ5FKO4+k4aarbuPnq98mbdo2q70hmU0VREkEeCOtqrbMprmFqM1psoYAsg0U9EBtB0YozUWzWpVZQgBxMm3YPoCiLpxRrPaYrBKRSUL5qn2AgFU0koMVlkMOo6G2SIymQCAGE/AGHRsWbCRKc8VmaBN4wBIwkZkFmxkWZDSFCwyommZSABgCmZBSsuiHahA8kA2iZYzSapAsmgHlgfdVyGLTFg3iZqQhAqZB923GGUgQhYRVElmAUXIGGVgedQ9AJJnAkqyClCEkkfdM1Pt13VHdxDpnof0jgxB+mYqO5PaCSDRIAbgDgdpKjtmwm13irsnq4ATdKeYcNvUZAt0dg5NVwEQFKrJlpn45lwh/LpbWdela4K5QsXEN61tytWr81l5YSY/n4wdQH84qjd2J6vEz+W0BOAGgLlE/AMAPQCv6e4gmWYC/QF3d/7zf8P/An4AWL/T1+B2nyIAAAAASUVORK5CYII=) no-repeat scroll 0px 10px;
	padding:15px 0 10px 40px;
}
.download {
	background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAB2klEQVR4nJ2ST2sTQRiHn5mdmj92t9XmUJIWJGq9NHrRgxQiCtqbl97FqxgaL34CP0FD8Qv07EHEU0Ew6EXEk6ci8Q9JtcXEkHR3k+zujIdUqMkmiANzmJdnHn7vzCuIWbe291tSkvhz1pr+q1L2bBwrRgvFrcZKKinfP9zI2EoKmm7Azstf3V7fXK2Wc3ujvIqzAhglwRJoS2ImQZMEBjgyoDS4hv8QGHA1WICvp9yelsA7ITBTIkwWhGBZ0Iv+MUF+c/cB8PTHt08snb+AGAACZDj8qIN6bSe/uWsBb2qV24/GBLn8yl0plY9AJ9NKeL5ICyEIQkkiZenF5XwBDAZzWItLIIR6LGfk26VVxzltJ2gFw2a0FmQLZ+bcbo/DPbcd+PrDyRb+GqRipbGlZtX92UvzjmUpEGC0JgpC3M9dL+qGz16XsvcmCgCK2/vPtTNzJ1x2kkZIRBSivh8Z2Q4+VkvZy6O8HHvWyGyITvA1qndNpxfguQNkc2CIzM0xNk5QLedCEZm1VKsf2XrAXMNrA2vVcq4ZJ4DhvCSAeSALXASuLBTW129U6oPrT969AK4Bq0AeWARs4BRgieMUEkgDmeO9ANipzDnH//nFB0KgAxwATaAFeID5DQNatLGdaXOWAAAAAElFTkSuQmCC) no-repeat scroll 0px 5px;
	padding:4px 0 4px 20px;
}
</style>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.8.2/jquery.min.js"></script>
<script>
(function($){
	$.fn.tablesorter = function() {
		var $table = this;
		this.find('th').click(function() {
			var idx = $(this).index();
			var direction = $(this).hasClass('sort_asc');
			$table.tablesortby(idx,direction);
		});
		return this;
	};
	$.fn.tablesortby = function(idx,direction) {
		var $rows = this.find('tbody tr');
		function elementToVal(a) {
			var $a_elem = $(a).find('td:nth-child('+(idx+1)+')');
			var a_val = $a_elem.attr('data-sort') || $a_elem.text();
			return (a_val == parseInt(a_val) ? parseInt(a_val) : a_val);
		}
		$rows.sort(function(a,b){
			var a_val = elementToVal(a), b_val = elementToVal(b);
			return (a_val > b_val ? 1 : (a_val == b_val ? 0 : -1)) * (direction ? 1 : -1);
		})
		this.find('th').removeClass('sort_asc sort_desc');
		$(this).find('thead th:nth-child('+(idx+1)+')').addClass(direction ? 'sort_desc' : 'sort_asc');
		for(var i =0;i<$rows.length;i++)
			this.append($rows[i]);
		this.settablesortmarkers();
		return this;
	}
	$.fn.retablesort = function() {
		var $e = this.find('thead th.sort_asc, thead th.sort_desc');
		if($e.length)
			this.tablesortby($e.index(), $e.hasClass('sort_desc') );

		return this;
	}
	$.fn.settablesortmarkers = function() {
		this.find('thead th span.indicator').remove();
		this.find('thead th.sort_asc').append('<span class="indicator">&darr;<span>');
		this.find('thead th.sort_desc').append('<span class="indicator">&uarr;<span>');
		return this;
	}
})(jQuery);
$(function(){
	var XSRF = (document.cookie.match('(^|; )_sfm_xsrf=([^;]*)')||0)[2];
	var MAX_UPLOAD_SIZE = <?php echo $MAX_UPLOAD_SIZE ?>;
	var $tbody = $('#list');
	$(window).on('hashchange',list).trigger('hashchange');
	$('#table').tablesorter();

	$('#table').on('click', '.delete', function() {
    var fileName = $(this).attr('data-file');
    var userConfirmation = prompt("To confirm deletion, please type the file name: " + fileName);
    
    if (userConfirmation === fileName) {
        $.post("", {'do': 'delete', 'file': fileName, 'xsrf': XSRF}, function(response) {
            list();
        }, 'json');
    } else {
        alert("File name does not match. Deletion cancelled.");
    }
    return false;
});

	$('#table').on('click','.unzip',function(data) {
		$.post("",{'do':'unzip',file:$(this).attr('data-file'),xsrf:XSRF},function(response){
			list();
		},'json');
		return false;
	});
	$('#mkdir').submit(function(e) {
		var hashval = decodeURIComponent(window.location.hash.substr(1)),
			$dir = $(this).find('[name=name]');
		e.preventDefault();
		$dir.val().length && $.post('?',{'do':'mkdir',name:$dir.val(),xsrf:XSRF,file:hashval},function(data){
			list();
		},'json');
		$dir.val('');
		return false;
	});
<?php if($allow_upload): ?>
	// file upload stuff
	$('#file_drop_target').on('dragover',function(){
		$(this).addClass('drag_over');
		return false;
	}).on('dragend',function(){
		$(this).removeClass('drag_over');
		return false;
	}).on('drop',function(e){
		e.preventDefault();
		var files = e.originalEvent.dataTransfer.files;
		$.each(files,function(k,file) {
			uploadFile(file);
		});
		$(this).removeClass('drag_over');
	});
	$('input[type=file]').change(function(e) {
		e.preventDefault();
		$.each(this.files,function(k,file) {
			uploadFile(file);
		});
	});


	function uploadFile(file) {
		var folder = decodeURIComponent(window.location.hash.substr(1));

		if(file.size > MAX_UPLOAD_SIZE) {
			var $error_row = renderFileSizeErrorRow(file,folder);
			$('#upload_progress').append($error_row);
			window.setTimeout(function(){$error_row.fadeOut();},5000);
			return false;
		}

		var $row = renderFileUploadRow(file,folder);
		$('#upload_progress').append($row);
		var fd = new FormData();
		fd.append('file_data',file);
		fd.append('file',folder);
		fd.append('xsrf',XSRF);
		fd.append('do','upload');
		var xhr = new XMLHttpRequest();
		xhr.open('POST', '?');
		xhr.onload = function() {
			$row.remove();
    		list();
  		};
		xhr.upload.onprogress = function(e){
			if(e.lengthComputable) {
				$row.find('.progress').css('width',(e.loaded/e.total*100 | 0)+'%' );
			}
		};
	    xhr.send(fd);
	}
	function renderFileUploadRow(file,folder) {
		return $row = $('<div/>')
			.append( $('<span class="fileuploadname" />').text( (folder ? folder+'/':'')+file.name))
			.append( $('<div class="progress_track"><div class="progress"></div></div>')  )
			.append( $('<span class="size" />').text(formatFileSize(file.size)) )
	};
	function renderFileSizeErrorRow(file,folder) {
		return $row = $('<div class="error" />')
			.append( $('<span class="fileuploadname" />').text( 'Error: ' + (folder ? folder+'/':'')+file.name))
			.append( $('<span/>').html(' file size - <b>' + formatFileSize(file.size) + '</b>'
				+' exceeds max upload size of <b>' + formatFileSize(MAX_UPLOAD_SIZE) + '</b>')  );
	}
<?php endif; ?>
	function list() {
		var hashval = window.location.hash.substr(1);
		$.get('?do=list&file='+ hashval,function(data) {
			$tbody.empty();
			$('#breadcrumb').empty().html(renderBreadcrumbs(hashval));
			if(data.success) {
				$.each(data.results,function(k,v){
					$tbody.append(renderFileRow(v));
				});
				!data.results.length && $tbody.append('<tr><td class="empty" colspan=5>This folder is empty</td></tr>')
				data.is_writable ? $('body').removeClass('no_write') : $('body').addClass('no_write');
			} else {
				console.warn(data.error.msg);
			}
			$('#table').retablesort();
		},'json');
	}
	function renderFileRow(data) {
		var $link = $('<a class="name" />')
			.attr('href', data.is_dir ? '#' + encodeURIComponent(data.path) : './' + data.path)
			.text(data.name);
		var allow_direct_link = <?php echo $allow_direct_link?'true':'false'; ?>;
        	if (!data.is_dir && !allow_direct_link)  $link.css('pointer-events','none');
		var $dl_link = $('<a/>').attr('href','?do=download&file='+ encodeURIComponent(data.path))
			.addClass('download').text('download');
		var $delete_link = $('<a href="#" />').attr('data-file',data.path).addClass('delete').text('delete');
		var $unzip_link = $('<a href="#" />').attr('data-file',data.path).addClass('unzip').text('unzip');
		var perms = [];
		if(data.is_readable) perms.push('read');
		if(data.is_writable) perms.push('write');
		if(data.is_executable) perms.push('exec');
		var $html = $('<tr />')
			.addClass(data.is_dir ? 'is_dir' : '')
			.append( $('<td class="first" />').append($link) )
			.append( $('<td/>').attr('data-sort',data.is_dir ? -1 : data.size)
				.html($('<span class="size" />').text(formatFileSize(data.size))) )
			.append( $('<td/>').attr('data-sort',data.mtime).text(formatTimestamp(data.mtime)) )
			.append( $('<td/>').text(perms.join('+')) )
			.append( $('<td/>').append($dl_link).append($unzip_link).append( data.is_deleteable ? $delete_link : '') )
		return $html;
	}
	function renderBreadcrumbs(path) {
		var base = "",
			$html = $('<div/>').append( $('<a href=#>Home</a></div>') );
		$.each(path.split('%2F'),function(k,v){
			if(v) {
				var v_as_text = decodeURIComponent(v);
				$html.append( $('<span/>').text(' ▸ ') )
					.append( $('<a/>').attr('href','#'+base+v).text(v_as_text) );
				base += v + '%2F';
			}
		});
		return $html;
	}
	function formatTimestamp(unix_timestamp) {
		var m = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
		var d = new Date(unix_timestamp*1000);
		return [m[d.getMonth()],' ',d.getDate(),', ',d.getFullYear()," ",
			(d.getHours() % 12 || 12),":",(d.getMinutes() < 10 ? '0' : '')+d.getMinutes(),
			" ",d.getHours() >= 12 ? 'PM' : 'AM'].join('');
	}
	function formatFileSize(bytes) {
		var s = ['bytes', 'KB','MB','GB','TB','PB','EB'];
		for(var pos = 0;bytes >= 1000; pos++,bytes /= 1024);
		var d = Math.round(bytes*10);
		return pos ? [parseInt(d/10),".",d%10," ",s[pos]].join('') : bytes + ' bytes';
	}
})

</script>
</head><body>
<img src="/logo.png" alt="Logo" width="200px" />

<div id="top">
   <?php if($allow_create_folder): ?>
	<form action="?" method="post" id="mkdir" />
		<label for=dirname>Create New Folder</label><input id=dirname type=text name=name value="" />
		<input type="submit" value="create" />
	</form>

   <?php endif; ?>

   <?php if($allow_upload): ?>

	<div id="file_drop_target">
		Drag Files Here To Upload
		<b>or</b>
		<input type="file" multiple />
	</div>
   <?php endif; ?>
	<div id="breadcrumb">&nbsp;</div>
</div>

<div id="upload_progress"></div>
<table id="table"><thead><tr>
	<th>Name</th>
	<th>Size</th>
	<th>Modified</th>
	<th>Permissions</th>
	<th>Actions</th>
</tr></thead><tbody id="list">

</tbody></table>
</body></html>
