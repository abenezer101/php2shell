<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$log = new Logger('app');
$log->pushHandler(new StreamHandler(__DIR__ . '/../var/app.log', Logger::WARNING));

// Upload endpoint: this is the code path that touches session upload progress.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['attachment'])) {
    $tmp = $_FILES['attachment']['tmp_name'];
    if (is_uploaded_file($tmp)) {
        move_uploaded_file($tmp, __DIR__ . '/../var/' . basename($_FILES['attachment']['name']));
        $log->warning('upload accepted', ['name' => $_FILES['attachment']['name']]);
    }
}

echo "<!DOCTYPE html><html><body>";
echo "<h1>Sample app</h1>";
echo "<form method='post' enctype='multipart/form-data'>";
echo "<input type='file' name='attachment'><button>Upload</button>";
echo "</form></body></html>";
