<?php
ob_start();

$mac = '';

// Генерируем X-Hwid (эмуляция Happ) который зависит от MAC-адреса сетевухи роутера
if (file_exists('/sys/class/net/br-lan/address')) {
    $mac = trim(file_get_contents('/sys/class/net/br-lan/address'));
} elseif (file_exists('/sys/class/net/eth0/address')) {
    $mac = trim(file_get_contents('/sys/class/net/eth0/address'));
}

if (!$mac) {
    $mac = php_uname('n');
}

$hwid = substr(md5(strtolower($mac)), 0, 17);

// Заголовки запроса к подписке
$headers = [
    'User-Agent: Happ/4.9.0',
    'X-Device-Os: Android',
    'X-Device-Locale: ru',
    'X-Device-Model: ELP-NX1',
    'X-Ver-Os: 15',
    'Connection: close',
    'X-Hwid: ' . $hwid,
];

$base64 = filter_var($_GET['base64'] ?? 'true', FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
if ($base64 === null) $base64 = true;

$url = $_GET['url'] ?? '';
if (!$url) {
    die('Чтобы раскурить подписку Happ построчно в список серверов, введите:<br>http://[IP морды роутера]/happ_to_vless.php?base64=true|false&url=[Ваша ссылка на подписку как есть]<br>Задайте параметр парсера (упаковка выдачи списка в base64) base64=true - для sing-box и его аналогов, base64=false - для V2RayA');
}

// Запрос к подписке
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $url, // Когда-то было htmlspecialchars
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 5,

    CURLOPT_CONNECTTIMEOUT => 60,
    CURLOPT_TIMEOUT => 30,

    CURLOPT_ENCODING => '',

    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,

    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,

    // Захват заголовков (инфа о подписке)
    CURLOPT_HEADER => true,
]);

$response = curl_exec($ch);
$error = curl_error($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

curl_close($ch);

if ($error || $httpCode !== 200 || !$response) {
    http_response_code(502);
    die("Ошибка запроса: " . ($error ?: "HTTP $httpCode"));
}

$rawHeaders = substr($response, 0, $headerSize);
$body = substr($response, $headerSize);

$response = $body;

// Декодим
$decoded = base64_decode($response, true);
$data = $decoded ?: $response;

// Жысон
$json = json_decode($data, true);
if (!$json) {
    die('Проблема с JSON');
}

$result = [];

// Перекуриваем JSON в список прямых подключений к серверам
foreach ($json as $item) {

    if (!isset($item['outbounds'])) continue;

    $remark = $item['remarks'] ?? 'node';

    foreach ($item['outbounds'] as $out) {

        $protocol = $out['protocol'] ?? '';

        // VLESS ВСЁ!!!
        if ($protocol === 'vless') {

            $v = $out['settings']['vnext'][0] ?? null;
            if (!$v) continue;

            $user = $v['users'][0] ?? null;
            if (!$user) continue;

            $addr = $v['address'];
            $port = $v['port'];
            $id   = $user['id'];
            $flow = $user['flow'] ?? '';

            $stream = $out['streamSettings'] ?? [];

            $type = $stream['network'] ?? 'tcp';
            $security = $stream['security'] ?? 'none';

            $params = [];

            $params['type'] = $type;

            // Network
            if ($type === 'ws') {
                $params['path'] = $stream['wsSettings']['path'] ?? '';
                $params['host'] = $stream['wsSettings']['headers']['Host'] ?? '';
            }

            if ($type === 'xhttp') {
                $params['path'] = $stream['xhttpSettings']['path'] ?? '/';
                $params['mode'] = $stream['xhttpSettings']['mode'] ?? 'auto';
            }

            if ($type === 'grpc') {
                $grpc = $stream['grpcSettings'] ?? [];
                $params['serviceName'] = $grpc['serviceName'] ?? '';
                if (!empty($grpc['authority'])) {
                    $params['authority'] = $grpc['authority'];
                }
                if (!empty($grpc['mode'])) {
                    $params['mode'] = $grpc['mode'] === true ? 'multi' : $grpc['mode'];
                }
            }

            // Security
            $params['security'] = $security;

            if ($security === 'tls') {
                $tls = $stream['tlsSettings'] ?? [];
                $params['sni'] = $tls['serverName'] ?? $addr;
                $params['fp']  = $tls['fingerprint'] ?? '';
                if (!empty($tls['alpn'])) {
                    $params['alpn'] = implode(',', $tls['alpn']);
                }
            }

            if ($security === 'reality') {
                $r = $stream['realitySettings'] ?? [];
                $params['sni'] = $r['serverName'] ?? '';
                $params['fp']  = $r['fingerprint'] ?? '';
                $params['pbk'] = $r['publicKey'] ?? '';
                $params['sid'] = $r['shortId'] ?? '';
            }

            if (!empty($flow)) {
                $params['flow'] = $flow;
            }

            // Сборка query
            $query = http_build_query($params);

            $link = "vless://{$id}@{$addr}:{$port}?{$query}#" . rawurlencode($remark);
            $result[] = $link;
        }

        // TROJAN
        if ($protocol === 'trojan') {

            $srv = $out['settings']['servers'][0] ?? null;
            if (!$srv) continue;

            $addr = $srv['address'];
            $port = $srv['port'];
            $pass = $srv['password'];

            $stream = $out['streamSettings'] ?? [];

            $type = $stream['network'] ?? 'tcp';
            $security = $stream['security'] ?? 'tls';

            $params = [
                'type' => $type,
                'security' => $security
            ];

            if ($security === 'tls') {
                $tls = $stream['tlsSettings'] ?? [];
                $params['sni'] = $tls['serverName'] ?? $addr;
                $params['fp']  = $tls['fingerprint'] ?? '';
                if (!empty($tls['alpn'])) {
                    $params['alpn'] = implode(',', $tls['alpn']);
                }
            }

            $query = http_build_query($params);

            $link = "trojan://{$pass}@{$addr}:{$port}?{$query}#" . rawurlencode($remark);
            $result[] = $link;
        }
		
        // HYSTERIA2
        if ($protocol === 'hysteria2' || ($protocol === 'hysteria' && (($out['settings']['version'] ?? 0) == 2 || ($out['streamSettings']['hysteriaSettings']['version'] ?? 0) == 2))) {

            $srv = $out['settings'] ?? [];
            $stream = $out['streamSettings'] ?? [];
            $hy = $stream['hysteriaSettings'] ?? [];
            $tls = $stream['tlsSettings'] ?? [];

            $addr = $srv['address'] ?? '';
            $port = $srv['port'] ?? '';
            $auth = $hy['auth'] ?? ($srv['password'] ?? ($srv['auth'] ?? ''));
            if (!$addr || !$port || !$auth) continue;

            $params = [];
            $params['sni'] = $tls['serverName'] ?? $addr;
            if (!empty($tls['fingerprint'])) {
                $params['fp'] = $tls['fingerprint'];
            }
            if (!empty($tls['alpn'])) {
                $params['alpn'] = implode(',', $tls['alpn']);
            }
            if (!empty($stream['finalmask'])) {
                $params['fm'] = json_encode($stream['finalmask'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            }

            $query = http_build_query($params);
            $link = "hysteria2://{$auth}@{$addr}:{$port}/?{$query}#" . rawurlencode($remark);
            $result[] = $link;
        }

		// SHADOWSOCKS
		if ($protocol === 'shadowsocks') {

			$srv = $out['settings']['servers'][0] ?? null;
			if (!$srv) continue;

			$addr = $srv['address'];
			$port = $srv['port'];
			$pass = $srv['password'];
			$method = $srv['method'];

			// base64(method:password)
			$userInfo = base64_encode($method . ':' . $pass);

			// Базовая ссылка
			$link = "ss://{$userInfo}@{$addr}:{$port}";

			// streamSettings (опционально)
			$stream = $out['streamSettings'] ?? [];
			$type = $stream['network'] ?? 'tcp';

			$params = [];

			// Если вдруг появится ws
			if ($type === 'ws') {
				$params['type'] = 'ws';
				$params['path'] = $stream['wsSettings']['path'] ?? '';
				$params['host'] = $stream['wsSettings']['headers']['Host'] ?? '';
			}

			// Если есть параметры - добавляем
			if (!empty($params)) {
				$link .= '?' . http_build_query($params);
			}

			$link .= '#' . rawurlencode($remark);
			$result[] = $link;
		}
    }
}

// Проксируем заголовки

// Удаляем encoding (мы уже распаковали)
header_remove('Content-Encoding');

// Заголовки, которые не надо передавать
$blockedHeaders = [
    'transfer-encoding',
    'content-length',
    'content-encoding',
    'connection',
];

// Берём последний блок (если были редиректы)
$headerBlocks = explode("\r\n\r\n", trim($rawHeaders));
$lastHeaders = end($headerBlocks);

foreach (explode("\r\n", $lastHeaders) as $line) {

    if (strpos($line, ':') === false) continue;

    [$key, $value] = explode(':', $line, 2);

    $key = trim($key);
    $value = trim($value);

    if (in_array(strtolower($key), $blockedHeaders)) continue;

    header($key . ': ' . $value, false);
}

// Очистка результата
$result = array_filter($result, function($v) {
    return is_string($v) && strpos($v, '://') !== false;
});

// Убираем дубликаты
$result = array_values(array_unique($result));

// Формируем список
$output = trim(implode("\n", $result));
$encoded = $base64 ? base64_encode($output) : $output;

// Чистый вывод
if (ob_get_length()) {
    ob_clean(); // Убираем BOM/мусор
}

header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-cache, max-age=0');
echo $encoded;
exit;
