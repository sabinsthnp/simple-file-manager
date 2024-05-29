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

$PASSWORD = '';  // Set the password, to access the file manager... (optional)

if($PASSWORD) {

	session_start();
	if(!$_SESSION['_sfm_allowed']) {
		// sha1, and random bytes to thwart timing attacks.  Not meant as secure hashing.
		$t = bin2hex(openssl_random_pseudo_bytes(10));
		if($_POST['p'] && sha1($t.$_POST['p']) === sha1($t.$PASSWORD)) {
			$_SESSION['_sfm_allowed'] = true;
			header('Location: ?');
		}
		echo '<html><body><form action=? method=post>PASSWORD:<input type=password name=p autofocus/></form></body></html>';
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
